"""Settings for every HoneyLens program, read from environment variables.

Why environment variables: Docker Compose passes settings this way, and it keeps
passwords out of source code (they live in the git-ignored ``.env`` file).

Every setting has a safe default so tests can run without a ``.env`` file.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

DISPLAY_TZ = ZoneInfo("Asia/Kolkata")
"""All data is STORED in UTC (Coordinated Universal Time) and only DISPLAYED in
India Standard Time (IST, Asia/Kolkata, UTC+05:30). Storing UTC avoids
daylight-saving and server-timezone bugs."""


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def build_dsn(user: str, password: str, host: str, port: int, db: str) -> str:
    """Build a libpq key/value connection string without exposing it in logs."""

    def q(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    return (
        f"host={q(host)} port={port} dbname={q(db)} user={q(user)} "
        f"password={q(password)} connect_timeout=5 application_name=honeylens"
    )


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(text: str) -> tuple[Network, ...]:
    """Parse a comma/space separated list of IPs and CIDRs (``HL_IGNORE_IPS``).

    A single IP becomes a /32 (or /128) network. A bad entry raises
    ``ValueError`` so a typo is reported at startup instead of silently
    not ignoring anything.
    """
    nets: list[Network] = []
    for part in text.replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid IP or CIDR in list: {part!r}") from exc
    return tuple(nets)


def ip_in(ip: str | None, nets: tuple[Network, ...]) -> bool:
    """True if ``ip`` is inside any of ``nets`` (False for None / bad IPs)."""
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


@dataclass(frozen=True)
class Settings:
    """All tunable values in one place. See ``.env.example`` for meanings."""

    db_host: str = field(default_factory=lambda: _env("HL_DB_HOST", "localhost"))
    db_port: int = field(default_factory=lambda: _env_int("HL_DB_PORT", 5432))
    db_name: str = field(default_factory=lambda: _env("POSTGRES_DB", "honeylens"))
    db_user: str = field(default_factory=lambda: _env("HL_DB_USER", "hl_pipeline"))
    db_password: str = field(default_factory=lambda: _env("HL_DB_PASSWORD", ""))

    input_glob: str = field(
        default_factory=lambda: _env("HL_INPUT_GLOB", "/cowrie-logs/cowrie.json*")
    )
    extra_input_glob: str = field(
        default_factory=lambda: _env("HL_EXTRA_INPUT_GLOB", "/synthetic/*.json")
    )
    batch_size: int = field(default_factory=lambda: _env_int("HL_BATCH_SIZE", 500))
    poll_seconds: float = field(
        default_factory=lambda: float(_env_int("HL_POLL_MS", 1000)) / 1000.0
    )
    max_line_bytes: int = field(
        default_factory=lambda: _env_int("HL_MAX_LINE_BYTES", 65536)
    )
    retention_days: int = field(default_factory=lambda: _env_int("HL_RETENTION_DAYS", 90))
    treat_private_as_simulated: bool = field(
        default_factory=lambda: _env_bool("HL_TREAT_PRIVATE_AS_SIMULATED", True)
    )

    ignore_loopback: bool = field(default_factory=lambda: _env_bool("HL_IGNORE_LOOPBACK", True))
    # Your own test/admin IPs: sessions from these are kept in the database but
    # marked is_ignored and left out of reports, IOC exports and dashboards.
    ignore_ips: str = field(default_factory=lambda: _env("HL_IGNORE_IPS", ""))
    # The honeypot's own public IP(s): never exported as an IOC when attackers
    # mention it in a command.
    sensor_ips: str = field(default_factory=lambda: _env("HL_SENSOR_IP", ""))
    # Per-IP brute-force window: an IP with >= brute_min_failures failed logins
    # (across ALL its sessions) within +/- brute_window_min minutes of a session
    # makes that login-only session a 'brute-forcer' instead of a 'scanner'.
    brute_window_min: int = field(default_factory=lambda: _env_int("HL_BRUTE_WINDOW_MIN", 60))
    brute_min_failures: int = field(default_factory=lambda: _env_int("HL_BRUTE_MIN_FAILURES", 20))

    mmdb_city_path: str = field(
        default_factory=lambda: _env("HL_MMDB_CITY", "/geoip/dbip-city-lite.mmdb")
    )
    mmdb_asn_path: str = field(
        default_factory=lambda: _env("HL_MMDB_ASN", "/geoip/dbip-asn-lite.mmdb")
    )
    enrich_api_token: str = field(default_factory=lambda: _env("HL_ENRICH_API_TOKEN", ""))
    enrich_api_max_per_minute: int = field(default_factory=lambda: _env_int("HL_ENRICH_API_MAX_PER_MINUTE", 30))
    enrich_api_timeout_s: float = field(default_factory=lambda: float(_env_int("HL_ENRICH_API_TIMEOUT_S", 3)))
    enrich_cache_days: int = field(
        default_factory=lambda: _env_int("HL_ENRICH_CACHE_DAYS", 30)
    )

    @property
    def ignore_networks(self) -> tuple[Network, ...]:
        """``HL_IGNORE_IPS`` parsed into networks (raises ValueError on a typo)."""
        return parse_networks(self.ignore_ips)

    @property
    def sensor_networks(self) -> tuple[Network, ...]:
        """``HL_SENSOR_IP`` parsed into networks."""
        return parse_networks(self.sensor_ips)

    def dsn(self) -> str:
        """Connection string for this program's own database role."""
        return build_dsn(self.db_user, self.db_password, self.db_host, self.db_port, self.db_name)
