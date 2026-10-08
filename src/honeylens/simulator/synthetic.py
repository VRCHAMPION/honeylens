"""Deterministic synthetic Cowrie events (no network at all).

Same ``--seed`` + same ``--end`` => byte-for-byte identical output. That makes
demos repeatable and lets tests compare against a known hash.

Every event carries ``"honeylens_simulated": true`` and uses an RFC 5737 source
IP, so the pipeline always marks it ``is_simulated = TRUE``.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from honeylens.simulator.personas import PERSONAS, Persona

DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
SENSOR = "honeylens-synthetic"


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ip_pool(rng: random.Random, size: int) -> list[str]:
    pool = sorted({f"{rng.choice(DOC_PREFIXES)}{rng.randint(1, 254)}" for _ in range(size * 2)})
    rng.shuffle(pool)
    return pool[:size]


def _success(persona: Persona, user: str, pw: str) -> bool:
    """Mirror cowrie/userdb.txt so synthetic data behaves like the real honeypot."""
    good = {("root", "admin123"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("root", "xc3511")}
    return (user, pw) in good


def session_events(rng: random.Random, persona: Persona, start: datetime, ip: str, sid: str) -> list[dict[str, Any]]:
    """All events for one fake session."""
    t = start
    evs: list[dict[str, Any]] = []

    def add(eventid: str, **fields: Any) -> None:
        base = {"eventid": eventid, "session": sid, "src_ip": ip, "timestamp": _ts(t),
                "sensor": SENSOR, "honeylens_simulated": True}
        base.update(fields)
        evs.append(base)

    def tick(bot_s: tuple[float, float], human_s: tuple[float, float]) -> timedelta:
        lo, hi = bot_s if persona.style == "bot" else human_s
        return timedelta(seconds=round(rng.uniform(lo, hi), 3))

    add("cowrie.session.connect", src_port=rng.randint(32768, 60999), dst_ip="10.0.0.5", dst_port=22,
        protocol="ssh", message="New connection")
    t += tick((0.05, 0.3), (0.2, 1.0))
    add("cowrie.client.version", version=persona.client_version)
    t += tick((0.01, 0.1), (0.1, 0.3))
    add("cowrie.client.kex", hassh=f"{rng.getrandbits(128):032x}")
    logged_in = False
    for user, pw in persona.logins:
        t += tick((0.2, 1.2), (2.0, 6.0))
        if _success(persona, user, pw):
            add("cowrie.login.success", username=user, password=pw)
            logged_in = True
            break
        add("cowrie.login.failed", username=user, password=pw)
    if logged_in:
        t += tick((0.3, 1.5), (3.0, 8.0))
        for cmd in persona.commands:
            add("cowrie.command.input", input=cmd)
            for url in persona.downloads:
                if url in cmd or url.rsplit("/", 1)[-1] in cmd.split():
                    add("cowrie.session.file_download.failed", url=url,
                        message="download blocked by HoneyLens (never fetched)")
            t += tick((0.1, 0.8), (2.5, 12.0))
    t += tick((0.1, 0.5), (1.0, 3.0))
    add("cowrie.session.closed", duration=round((t - start).total_seconds(), 3))
    return evs


def generate(seed: int, days: int, end: datetime, sessions_per_day: int = 60) -> Iterator[dict[str, Any]]:
    """Yield events for ``days`` days ending at ``end`` (UTC), sorted by time."""
    rng = random.Random(seed)  # nosec B311
    ips = _ip_pool(rng, 120)
    weights = [p.weight for p in PERSONAS]
    all_events: list[dict[str, Any]] = []
    start_day = end - timedelta(days=days)
    counter = 0
    for d in range(days):
        day_start = start_day + timedelta(days=d)
        # Slightly more traffic in the most recent week, so week-over-week is non-zero.
        n = int(sessions_per_day * (1.25 if d >= days - 7 else 1.0))
        for _ in range(n):
            persona = rng.choices(PERSONAS, weights=weights, k=1)[0]
            start = day_start + timedelta(seconds=rng.randint(0, 86399), microseconds=rng.randint(0, 999999))
            counter += 1
            sid = f"syn{seed:04d}{counter:07d}"
            ip = rng.choice(ips[:30] if persona.name == "scanner" else ips)
            all_events.extend(session_events(rng, persona, start, ip, sid))
    all_events.sort(key=lambda e: (e["timestamp"], e["session"]))
    yield from all_events


def write(path: str, seed: int, days: int, end: datetime, sessions_per_day: int = 60) -> int:
    """Write JSON lines to ``path`` atomically. Returns event count."""
    import os
    import tempfile

    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".synthetic-", suffix=".tmp")
    count = 0
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        for ev in generate(seed, days, end, sessions_per_day):
            fh.write(json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n")
            count += 1
    os.replace(tmp, path)
    return count
