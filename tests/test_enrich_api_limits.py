"""Optional GeoIP web API: off by default, rate limited, strict timeout, never fatal."""
import io
import json
import socket
import threading
import time
import urllib.request

import pytest

from honeylens.config import Settings
from honeylens.enrich.geo import Enricher, IPInfoProvider, RateLimiter, build_enricher


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def ok_opener(calls):
    def opener(req, timeout):
        calls.append((req.full_url, timeout))
        return FakeResp(json.dumps({"country": "DE", "city": "Berlin", "org": "AS3320 Deutsche Telekom",
                                    "loc": "52.5,13.4"}).encode())
    return opener


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HL_ENRICH_API_TOKEN", raising=False)
    e = build_enricher(Settings())
    assert not any(isinstance(p, IPInfoProvider) for p in e.providers)


def test_settings_reach_provider(monkeypatch):
    monkeypatch.setenv("HL_ENRICH_API_TOKEN", "tok")
    monkeypatch.setenv("HL_ENRICH_API_MAX_PER_MINUTE", "7")
    monkeypatch.setenv("HL_ENRICH_API_TIMEOUT_S", "60")
    api = [p for p in build_enricher(Settings()).providers if isinstance(p, IPInfoProvider)][0]
    assert api.limiter.max_calls == 7
    assert api.timeout == 5.0  # clamped: never wait more than 5 s


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.1.1", "127.0.0.1", "172.16.0.9", "169.254.1.1",
                                "192.0.2.10", "198.51.100.7", "203.0.113.9", "2001:db8::1", "::1", "fc00::1",
                                "0.0.0.0", "224.0.0.1", "not-an-ip"])
def test_never_sends_private_documentation_or_invalid_ips(ip):
    calls = []
    api = IPInfoProvider("tok", opener=ok_opener(calls))
    assert api.lookup(ip) is None
    assert calls == []


def test_rate_limiter_window():
    clock = Clock()
    rl = RateLimiter(3, 60, clock)
    assert [rl.allow() for _ in range(5)] == [True, True, True, False, False]
    clock.t += 59.9
    assert rl.allow() is False
    clock.t += 0.2
    assert rl.allow() is True
    assert RateLimiter(0, 60, clock).allow() is False


def test_provider_respects_limit_and_recovers():
    clock, calls = Clock(), []
    api = IPInfoProvider("tok", max_per_minute=5, clock=clock, opener=ok_opener(calls))
    results = [api.lookup(f"8.8.{i}.8") for i in range(12)]
    assert sum(r is not None for r in results) == 5
    assert len(calls) == 5 and api.stats["rate_limited"] == 7
    assert results[0].country_code == "DE" and results[0].asn == 3320
    clock.t += 61
    assert api.lookup("1.1.1.1") is not None and len(calls) == 6


def test_failures_return_none_then_cooldown():
    clock, n = Clock(), [0]

    def failing(req, timeout):
        n[0] += 1
        raise TimeoutError("slow")

    api = IPInfoProvider("tok", clock=clock, opener=failing)
    assert [api.lookup("8.8.8.8") for _ in range(5)] == [None] * 5
    assert n[0] == 3  # after 3 failures in a row the API is paused
    assert api.stats["skipped_cooldown"] == 2
    clock.t += 301
    api.lookup("8.8.8.8")
    assert n[0] == 4


@pytest.mark.parametrize("payload", [b"not json", b"[1,2]", b"\xff\xfe"])
def test_bad_responses_are_not_fatal(payload):
    api = IPInfoProvider("tok", opener=lambda req, timeout: FakeResp(payload))
    assert api.lookup("8.8.8.8") is None and api.stats["failed"] == 1


def test_real_socket_timeout_is_strict():
    """A server that accepts but never answers: we must give up after ~timeout seconds."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    held = []
    threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()

    def local(req, timeout):
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # ignore any http_proxy
        return direct.open(f"http://127.0.0.1:{port}/", timeout=timeout)

    api = IPInfoProvider("tok", timeout=0.5, opener=local)
    t0 = time.monotonic()
    assert api.lookup("8.8.8.8") is None
    elapsed = time.monotonic() - t0
    srv.close()
    assert 0.4 <= elapsed < 2.0, elapsed
    assert api.stats["failed"] == 1


def test_enricher_continues_when_api_fails():
    def boom(req, timeout):
        raise OSError("network unreachable")

    e = Enricher([IPInfoProvider("tok", opener=boom)])
    info = e.lookup("8.8.8.8")
    assert info.source == "none" and info.ip == "8.8.8.8"
    assert e.stats["miss"] == 1
