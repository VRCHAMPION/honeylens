import hashlib
import json
from datetime import UTC, datetime

import pytest

from honeylens.pipeline.events import parse_line
from honeylens.simulator.cli import main as sim_main
from honeylens.simulator.guard import TargetNotAllowed, check_target
from honeylens.simulator.live import run_live
from honeylens.simulator.personas import PERSONAS
from honeylens.simulator.synthetic import generate, write

REQUIRED = {"scanner", "brute-forcer", "recon-bot", "mirai-loader", "cryptominer-dropper",
            "ssh-key-implant", "honeypot-prober", "log-wiper"}


def test_eight_personas():
    assert {p.name for p in PERSONAS} >= REQUIRED


def test_personas_use_only_safe_indicators():
    import re
    for p in PERSONAS:
        for text in p.commands + p.downloads:
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
                assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip
            for host in re.findall(r"https?://([^/:\s]+)", text):
                assert host.endswith((".invalid", ".test")) or host[0].isdigit(), host
            assert "EICAR" not in text.upper()


def resolver(mapping):
    return lambda name: mapping[name]


def test_guard_allows_loopback_and_project_service():
    assert check_target("127.0.0.1", allowed_hosts="", compose_services="cowrie") == "127.0.0.1"
    assert check_target("localhost", resolver({"localhost": ["127.0.0.1"]}), "", "cowrie") == "127.0.0.1"
    assert check_target("cowrie", resolver({"cowrie": ["172.20.0.3"]}), "", "cowrie") == "172.20.0.3"


@pytest.mark.parametrize("host,ips", [
    ("8.8.8.8", None), ("example.com", ["93.184.215.14"]), ("cowrie", ["93.184.215.14"]),
    ("192.168.1.10", None), ("mixed", ["127.0.0.1", "8.8.8.8"]), ("0.0.0.0", None), ("224.0.0.1", None),
])
def test_guard_refuses_everything_else(host, ips):
    res = resolver({host: ips}) if ips else None
    with pytest.raises(TargetNotAllowed):
        check_target(host, res, "", "cowrie")


def test_guard_allowlist_exact_match():
    assert check_target("my-honeypot.test", resolver({"my-honeypot.test": ["198.51.100.50"]}),
                        "my-honeypot.test", "cowrie") == "198.51.100.50"
    with pytest.raises(TargetNotAllowed):
        check_target("other.test", resolver({"other.test": ["198.51.100.50"]}), "my-honeypot.test", "cowrie")


def test_unapproved_hostname_is_rejected_before_dns():
    def must_not_resolve(_name):
        raise AssertionError("unapproved names must be rejected before DNS")

    with pytest.raises(TargetNotAllowed):
        check_target("unapproved.example", must_not_resolve, "", "cowrie")


def test_live_refuses_before_connecting(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not connect")
    monkeypatch.setattr("socket.create_connection", boom)
    monkeypatch.setenv("HL_SIM_ALLOWED_HOSTS", "")
    with pytest.raises(TargetNotAllowed):
        run_live("8.8.8.8", 22, 1, 1)
    assert sim_main(["live", "--target", "1.1.1.1"]) == 2


END = datetime(2026, 10, 5, tzinfo=UTC)


def test_synthetic_deterministic(tmp_path):
    a, b, c = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"
    write(str(a), 42, 3, END, 20)
    write(str(b), 42, 3, END, 20)
    write(str(c), 43, 3, END, 20)
    ha, hb, hc = (hashlib.sha256(p.read_bytes()).hexdigest() for p in (a, b, c))
    assert ha == hb != hc


def test_synthetic_is_valid_cowrie_format():
    events = list(generate(1, 2, END, 30))
    kinds = {e["eventid"] for e in events}
    assert {"cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success",
            "cowrie.command.input", "cowrie.session.closed"} <= kinds
    for e in events:
        ev = parse_line(json.dumps(e).encode())
        assert ev.is_simulated
        assert END.timestamp() - 2 * 86400 <= ev.ts.timestamp() <= END.timestamp() + 3600
