"""Make hostile attacker text safe to store and display.

Everything an attacker types is HOSTILE input. They may send:

* ANSI (American National Standards Institute) escape codes that repaint a
  terminal or hide text when an analyst runs ``cat`` on a log,
* NUL bytes and control characters that break databases or parsers,
* gigantic strings meant to fill the disk or slow down regexes,
* HTML/JavaScript meant to run in a dashboard (XSS, Cross-Site Scripting).

This module removes the first three. HTML escaping happens at DISPLAY time
(Jinja2 autoescape in the report, and Grafana's own escaping), because
escaping twice corrupts data and the database should keep the real text.
"""

from __future__ import annotations

import ipaddress
import re

# Max lengths per field. Real commands are short; long ones are almost always
# junk or an attack on us. Values are generous but bounded.
FIELD_LIMITS: dict[str, int] = {
    "command": 4096,
    "username": 256,
    "password": 256,  # nosec B105
    "url": 2048,
    "client_version": 256,
    "message": 1024,
    "default": 512,
}

# ESC [ ... final-byte   (CSI sequences)  |  ESC ] ... BEL/ST (OSC)  |  ESC x
# The repetition counts are bounded, so this regex cannot backtrack badly.
_ANSI_RE = re.compile(r"\x1b\[[0-?]{0,32}[ -/]{0,8}[@-~]|\x1b\][^\x07\x1b]{0,512}(\x07|\x1b\\)?|\x1b.")
# C0 controls except TAB, plus DEL and C1 controls (0x80-0x9f)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(value: object, field: str = "default") -> str:
    """Return a printable, length-limited string.

    Steps: convert to ``str`` -> remove ANSI escapes -> replace newlines with a
    visible marker -> drop other control characters -> cut to the field limit.
    The marker ``" ⏎ "`` keeps multi-line attacker input readable on one line.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    limit = FIELD_LIMITS.get(field, FIELD_LIMITS["default"])
    # Pre-cut so the regexes below never run on megabytes of text.
    text = text[: limit * 2]
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ⏎ ")
    text = _CTRL_RE.sub("", text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def clean_ip(value: object) -> str | None:
    """Return a normalised IP address string, or None if it is not an IP."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def clean_port(value: object) -> int | None:
    """Return a TCP port number 0-65535 or None."""
    if isinstance(value, bool):
        return None
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def defang(text: str) -> str:
    """Make URLs and IPs non-clickable for reports: ``http://1.2.3.4`` -> ``hxxp://1[.]2[.]3[.]4``.

    Defanging is a SOC (Security Operations Centre) habit: nobody can click a
    live malware link by accident, and mail filters will not flag the report.
    """
    out = re.sub(r"(?i)\bhttp", "hxxp", text)
    out = re.sub(r"(?i)\bftp", "fxp", out)
    out = out.replace("://", "[://]")
    out = re.sub(r"(?<=[0-9a-zA-Z])\.(?=[0-9a-zA-Z])", "[.]", out)
    return out


def mask_ip(ip: str) -> str:
    """Hide the host part of an IP for sharing: 203.0.113.45 -> 203.0.113.x."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "x.x.x.x"
    if addr.version == 4:
        parts = str(addr).split(".")
        return ".".join(parts[:3] + ["x"])
    net = ipaddress.ip_network(f"{addr}/48", strict=False)
    return f"{net.network_address}/48(masked)"
