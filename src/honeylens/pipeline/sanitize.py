"""Make hostile attacker text safe to store and display.

Everything an attacker types is HOSTILE input. They may send:

* ANSI (American National Standards Institute) escape codes that repaint a
  terminal or hide text when an analyst runs ``cat`` on a log,
* NUL bytes and control characters that break databases or parsers,
* invisible Unicode "format" characters (bidi overrides such as U+202E,
  zero-width spaces, isolates) that make text display differently from
  what it really contains,
* lone UTF-16 surrogates (``\\ud800`` written as a JSON escape), which
  PostgreSQL refuses to store and which would otherwise stall ingestion,
* gigantic strings meant to fill the disk or slow down regexes,
* HTML/JavaScript meant to run in a dashboard (XSS, Cross-Site Scripting).

This module removes the first four. HTML escaping happens at DISPLAY time
(Jinja2 autoescape in the report, and Grafana's own escaping), because
escaping twice corrupts data and the database should keep the real text.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

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


# Cf = format characters (bidi overrides, zero-width chars, BOM, ...).
# Cs = lone surrogates: valid in a Python str and in JSON ("\ud800") but not
# encodable as UTF-8, so PostgreSQL rejects the whole row.
_DROP_CATEGORIES = frozenset({"Cf", "Cs"})
# Unicode LINE SEPARATOR / PARAGRAPH SEPARATOR act as line breaks in many viewers.
_UNICODE_NEWLINES = str.maketrans({"\u2028": "\n", "\u2029": "\n"})


def _strip_format_chars(text: str) -> str:
    """Drop Unicode categories Cf (invisible format chars) and Cs (lone surrogates)."""
    if text.isascii():
        return text
    return "".join(ch for ch in text if unicodedata.category(ch) not in _DROP_CATEGORIES)


def clean_text(value: object, field: str = "default") -> str:
    """Return a printable, length-limited string.

    Steps: convert to ``str`` -> remove ANSI escapes -> replace newlines
    (including U+2028/U+2029) with a visible marker -> drop other control
    characters, Unicode format (Cf) characters and lone surrogates (Cs) ->
    cut to the field limit.
    The marker ``" ⏎ "`` keeps multi-line attacker input readable on one line.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    limit = FIELD_LIMITS.get(field, FIELD_LIMITS["default"])
    # Pre-cut so the regexes below never run on megabytes of text.
    text = text[: limit * 2]
    text = _ANSI_RE.sub("", text)
    text = text.translate(_UNICODE_NEWLINES)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ⏎ ")
    text = _CTRL_RE.sub("", text)
    text = _strip_format_chars(text)
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
    """Hide the host part of an IP for sharing: 203.0.113.45 -> 203.0.113.x.

    IPv6 keeps only its /48 prefix. An IPv4-mapped IPv6 address
    (``::ffff:203.0.113.45``) is masked like the IPv4 it carries.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "x.x.x.x"
    if addr.version == 4:
        parts = str(addr).split(".")
        return ".".join(parts[:3] + ["x"])
    if addr.ipv4_mapped is not None:
        return "::ffff:" + mask_ip(str(addr.ipv4_mapped))
    net = ipaddress.ip_network(f"{addr}/48", strict=False)
    return f"{net.network_address}/48(masked)"


# IPv4 written plainly or defanged ("1[.]2[.]3[.]4", "1(.)2(.)3(.)4", "1[dot]2...").
# Octets may carry leading zeros ("198.051.100.023"): many tools still accept them.
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|0[0-9]{1,2}|[1-9]?[0-9])"
_DOT = r"(?:\.|\[\.\]|\(\.\)|\[dot\])"
_IPV4_IN_TEXT_RE = re.compile(rf"(?<![0-9.]){_OCTET}(?:{_DOT}{_OCTET}){{3}}(?![0-9])")
# IPv6 candidates (validated with the ipaddress module before masking),
# including an embedded IPv4 tail such as 2001:db8::1.2.3.4 or ::ffff:1.2.3.4.
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:.\[])"
)
# URL hosts written as one number or in hex/octal parts: http://3325256727/,
# http://0xC6336417/, http://0xc6.0x33.100.23/ all mean an IPv4 address.
_NUM = r"(?:0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10})"
_NUMERIC_URL_HOST_RE = re.compile(
    rf"(?<=://)(?P<auth>[^/@\s]{{0,256}}@)?(?P<host>{_NUM}(?:\.{_NUM}){{0,3}})(?=[/:?#\s'\"]|$)"
)
_MAX_MASK_INPUT = 65536


def _mask_ipv4_match(m: re.Match[str]) -> str:
    text = m.group(0)
    seps = list(re.finditer(_DOT, text))
    return text[: seps[-1].end()] + "x"


def _mask_ipv6_match(m: re.Match[str]) -> str:
    text = m.group(0)
    if not re.search(r"[0-9A-Fa-f]", text):
        return text
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return text
    return mask_ip(text)


def _mask_numeric_host(m: re.Match[str]) -> str:
    return (m.group("auth") or "") + "x.x.x.x"


def mask_ips_in_text(text: str) -> str:
    """Mask every IPv4/IPv6 address found inside free text (URLs, commands, summaries).

    ``wget http://198.51.100.23/x.sh`` -> ``wget http://198.51.100.x/x.sh``;
    defanged forms such as ``198[.]51[.]100[.]23`` keep their style
    (``198[.]51[.]100[.]x``). IPv6 addresses become ``<prefix>::/48(masked)``
    (IPv6 with an embedded IPv4 tail is masked as a whole). Numeric URL hosts
    (``http://3325256727/``, ``http://0xC6336417/``) become ``x.x.x.x``.
    Over-long input is cut first so the regexes stay cheap.
    """
    if not text:
        return text
    text = text[:_MAX_MASK_INPUT]
    # IPv6 first, so an embedded IPv4 tail is masked together with its prefix.
    text = _IPV6_CANDIDATE_RE.sub(_mask_ipv6_match, text)
    text = _IPV4_IN_TEXT_RE.sub(_mask_ipv4_match, text)
    return _NUMERIC_URL_HOST_RE.sub(_mask_numeric_host, text)
