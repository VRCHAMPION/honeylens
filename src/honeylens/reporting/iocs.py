"""Pull IOCs (Indicators of Compromise) out of attacker COMMAND TEXT.

Cowrie only records a download when its fake wget/curl runs. Many droppers
pipe the download straight into a shell or use scp, so the payload host never
reaches the downloads table. This module finds those hosts in the command
text itself:

* URLs with http, https, ftp or tftp schemes,
* scp/rsync sources written as ``user@host:path``,
* bare IPv4 addresses (including the ones inside URLs and scp sources).

What is left out: private, loopback, link-local, multicast and other
non-public addresses, the honeypot's own IP (``HL_SENSOR_IP``) and the
operator's ignored IPs (``HL_IGNORE_IPS``). RFC 5737 documentation ranges are
kept on purpose: they only ever appear in simulated data, which is labelled
``simulated`` everywhere, and the tests use them instead of real IPs.

HoneyLens never connects to anything extracted here.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from honeylens.config import Network, ip_in

CONTEXT_URL = "seen in command (never fetched)"
CONTEXT_IP = "seen in command (never fetched)"
CONTEXT_SCP = "scp source seen in command (never fetched)"

_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
# Bounded character classes only (ReDoS-safe on hostile 4 KB commands).
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|tftp)://[^\s'\"<>`;|(){}\\]{1,2000}")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_SCP_CONTEXT_RE = re.compile(r"\b(?:scp|rsync|sftp)\b")
_SCP_TARGET_RE = re.compile(r"(?<![\w.@-])([A-Za-z0-9._-]{1,64})@([A-Za-z0-9.-]{1,253}):([^\s;|&'\"`]{0,256})")
# Cheap SQL pre-filter: only commands that could hold an IOC are fetched.
SQL_CANDIDATE_REGEX = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|://|@[A-Za-z0-9.-]+:"


def exportable_ip(ip: str, exclude: tuple[Network, ...] = ()) -> bool:
    """True if ``ip`` is a public (or RFC 5737 documentation) address that is not excluded."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if ip_in(ip, exclude):
        return False
    if any(addr in n for n in _DOC_NETS):
        return True
    return addr.is_global and not addr.is_multicast


def extract(command: str, exclude: tuple[Network, ...] = ()) -> list[tuple[str, str]]:
    """Return ``(type, value)`` pairs found in one command, in first-seen order, without duplicates.

    Types: ``url``, ``ipv4-addr``, ``scp-target``.
    """
    found: dict[tuple[str, str], None] = {}
    text = command.replace(" \u23ce ", "\n")
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,:")
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            continue
        if not host:
            continue
        if re.fullmatch(r"[0-9.]+", host) and not exportable_ip(host, exclude):
            continue
        found[("url", url)] = None
    if _SCP_CONTEXT_RE.search(text):
        for m in _SCP_TARGET_RE.finditer(text):
            host = m.group(2).strip(".")
            if "." not in host:
                continue
            if re.fullmatch(r"[0-9.]+", host) and not exportable_ip(host, exclude):
                continue
            found[("scp-target", f"{m.group(1)}@{host}:{m.group(3)}")] = None
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if exportable_ip(ip, exclude):
            found[("ipv4-addr", str(ipaddress.ip_address(ip)))] = None
    return list(found)


def aggregate(rows: Iterable[dict[str, Any]], exclude: tuple[Network, ...] = ()) -> list[dict[str, Any]]:
    """Turn command rows (command, times, first_seen, last_seen, simulated) into one row per IOC."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        for kind, value in extract(r["command"], exclude):
            item = out.setdefault((kind, value), {
                "type": kind, "value": value, "count": 0, "first_seen": r["first_seen"],
                "last_seen": r["last_seen"], "simulated": True,
                "context": {"url": CONTEXT_URL, "ipv4-addr": CONTEXT_IP, "scp-target": CONTEXT_SCP}[kind],
            })
            item["count"] += int(r["times"])
            item["first_seen"] = _min(item["first_seen"], r["first_seen"])
            item["last_seen"] = _max(item["last_seen"], r["last_seen"])
            item["simulated"] = item["simulated"] and bool(r["simulated"])
    order = {"url": 0, "scp-target": 1, "ipv4-addr": 2}
    return sorted(out.values(), key=lambda i: (order[i["type"]], -i["count"], i["value"]))


def _min(a: datetime | None, b: datetime | None) -> datetime | None:
    return b if a is None else a if b is None else min(a, b)


def _max(a: datetime | None, b: datetime | None) -> datetime | None:
    return b if a is None else a if b is None else max(a, b)
