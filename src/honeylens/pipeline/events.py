"""Parse one Cowrie JSON log line into a clean, typed event.

Cowrie writes one JSON object per line, for example::

    {"eventid": "cowrie.login.failed", "username": "root", "password": "123456",
     "src_ip": "203.0.113.7", "session": "a1b2c3d4", "timestamp": "2026-10-06T10:00:00.123456Z", ...}

We only TRUST the fields we validate here. Everything else stays in the raw
JSONB copy for later investigation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from honeylens.pipeline.sanitize import clean_ip, clean_port, clean_text

KNOWN_EVENTS = {
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.client.size",
    "cowrie.client.var",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.session.file_download.failed",
    "cowrie.session.file_upload",
    "cowrie.direct-tcpip.request",
    "cowrie.direct-tcpip.data",
    "cowrie.log.closed",
    "cowrie.session.params",
}
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EVENTID_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")
_SIM_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


class BadEvent(ValueError):
    """The line is not a usable Cowrie event (counted as 'malformed')."""


@dataclass
class Event:
    """A validated Cowrie event."""

    event_uid: str
    eventid: str
    session_id: str
    ts: datetime
    src_ip: str | None
    sensor: str
    is_simulated: bool
    raw: dict[str, Any]
    fields: dict[str, Any] = field(default_factory=dict)


def parse_timestamp(value: object) -> datetime:
    """Parse Cowrie's ISO-8601 timestamp and return an aware UTC datetime."""
    if not isinstance(value, str) or len(value) > 40:
        raise BadEvent("missing or bad timestamp")
    text = value.strip().replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise BadEvent("bad timestamp") from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    ts = ts.astimezone(UTC)
    if not 2000 <= ts.year <= 2100:
        raise BadEvent("timestamp out of range")
    return ts


def is_simulated_ip(ip: str | None, treat_private_as_simulated: bool) -> bool:
    """True if traffic from this IP must be our own simulator, not a real attacker.

    Documentation IPs (RFC 5737) are never routed on the internet, so they can
    only come from the synthetic generator. Private/loopback IPs come from the
    laptop or the Docker network (the live simulator) - on a public cloud
    honeypot real attackers always arrive from public IPs.
    """
    if ip is None:
        return False
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in _SIM_NETS):
        return True
    return treat_private_as_simulated and (addr.is_private or addr.is_loopback or addr.is_link_local)


def _scrub(obj: Any, depth: int = 0) -> Any:
    """Recursively sanitize a JSON value for the raw JSONB copy (limits depth and size)."""
    if depth > 4:
        return "[too deep]"
    if isinstance(obj, dict):
        return {clean_text(k)[:64]: _scrub(v, depth + 1) for k, v in list(obj.items())[:64]}
    if isinstance(obj, list):
        return [_scrub(v, depth + 1) for v in obj[:64]]
    if isinstance(obj, str):
        return clean_text(obj, "message")
    if isinstance(obj, bool | int | float) or obj is None:
        return obj
    return clean_text(obj)


def _reject_nonfinite(value: str) -> None:
    """Reject JavaScript-style NaN/Infinity constants, which PostgreSQL JSONB rejects."""
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    """Parse a JSON number without allowing overflow to Python's infinity value."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def parse_line(line: bytes, treat_private_as_simulated: bool = True) -> Event:
    """Validate and normalise one raw log line. Raises :class:`BadEvent`."""
    text = line.strip()
    if not text:
        raise BadEvent("empty line")
    uid = hashlib.sha256(text).hexdigest()
    try:
        data = json.loads(
            text.decode("utf-8", errors="replace"),
            parse_constant=_reject_nonfinite,
            parse_float=_finite_float,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BadEvent("not json") from exc
    if not isinstance(data, dict):
        raise BadEvent("not an object")
    eventid = data.get("eventid")
    if not isinstance(eventid, str) or not _EVENTID_RE.match(eventid):
        raise BadEvent("bad eventid")
    session = data.get("session")
    if not isinstance(session, str) or not _SESSION_RE.match(session):
        raise BadEvent("bad session")
    ts = parse_timestamp(data.get("timestamp"))
    src_ip = clean_ip(data.get("src_ip"))
    simulated = bool(data.get("honeylens_simulated") is True) or is_simulated_ip(
        src_ip, treat_private_as_simulated
    )
    ev = Event(
        event_uid=uid,
        eventid=eventid,
        session_id=session,
        ts=ts,
        src_ip=src_ip,
        sensor=clean_text(data.get("sensor"))[:64],
        is_simulated=simulated,
        raw=_scrub(data),
    )
    f = ev.fields
    if eventid == "cowrie.session.connect":
        f["src_port"] = clean_port(data.get("src_port"))
        f["dst_port"] = clean_port(data.get("dst_port"))
        f["protocol"] = clean_text(data.get("protocol"))[:16] or "ssh"
    elif eventid == "cowrie.client.version":
        f["client_version"] = clean_text(data.get("version"), "client_version")
    elif eventid == "cowrie.client.kex":
        f["hassh"] = clean_text(data.get("hassh"))[:64]
    elif eventid in {"cowrie.login.success", "cowrie.login.failed"}:
        f["username"] = clean_text(data.get("username"), "username")
        f["password"] = clean_text(data.get("password"), "password")
        f["success"] = eventid == "cowrie.login.success"
    elif eventid in {"cowrie.command.input", "cowrie.command.failed"}:
        f["command"] = clean_text(data.get("input"), "command")
        f["known"] = eventid == "cowrie.command.input"
    elif eventid.startswith("cowrie.session.file_download") or eventid == "cowrie.session.file_upload":
        url = clean_text(data.get("url"), "url")
        f["url"] = url
        host = ""
        if url:
            try:
                host = (urlsplit(url).hostname or "")[:255]
            except ValueError:
                host = ""
        f["url_host"] = host
        sha = data.get("shasum")
        f["shasum"] = sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) else ""
        f["outfile"] = clean_text(data.get("outfile") or data.get("filename"))
    elif eventid == "cowrie.session.closed":
        dur = data.get("duration")
        f["duration"] = float(dur) if isinstance(dur, int | float) and 0 <= dur < 10**7 else None
    return ev
