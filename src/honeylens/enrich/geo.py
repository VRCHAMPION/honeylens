"""Add location and network owner (ASN) information to attacker IPs.

ASN = Autonomous System Number: the ID of the network (ISP, cloud provider,
university...) that announces an IP range on the internet.

Provider chain (first answer wins):

1. **Special ranges** - private, loopback and reserved IPs never leave the box.
   RFC 5737 documentation IPs (used by our simulator) get deterministic DEMO
   data so dashboards look alive offline.
2. **Database cache** - ``enrichment_cache`` table, so each IP is looked up once.
3. **Local MMDB** (MaxMind DB format) files, for example DB-IP Lite. Fast,
   offline and private: the attacker never learns we looked them up.
4. **Optional HTTP API** (ipinfo.io), only if ``HL_ENRICH_API_TOKEN`` is set.
   We send the attacker's IP to a third party, so it is OFF by default. When on,
   it is protected by a strict timeout (``HL_ENRICH_API_TIMEOUT_S``, clamped to
   0.5-5 s), a rate limiter (``HL_ENRICH_API_MAX_PER_MINUTE``, default 30) and
   a cool-down after 3 failures in a row. Any API problem just means "no
   enrichment" - the pipeline never stops for it.

Important honesty rule: GeoIP shows where an IP is *registered*, not who the
attacker is. Traffic is often relayed through hacked machines or VPNs, so we
never make attribution claims ("country X attacked us").
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

log = logging.getLogger("honeylens.enrich")

DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
"""RFC 5737 / RFC 3849 documentation ranges: guaranteed never to be real hosts."""

# Deterministic demo data: fake but plausible. ASNs come from the private-use
# range 64512-65534 (RFC 6996), so they can never be confused with a real network.
_DEMO_PLACES: list[tuple[str, str, str, float, float]] = [
    ("CN", "China", "Shanghai", 31.23, 121.47),
    ("US", "United States", "Ashburn", 39.04, -77.49),
    ("RU", "Russia", "Moscow", 55.75, 37.62),
    ("BR", "Brazil", "Sao Paulo", -23.55, -46.63),
    ("IN", "India", "Mumbai", 19.08, 72.88),
    ("DE", "Germany", "Frankfurt", 50.11, 8.68),
    ("NL", "Netherlands", "Amsterdam", 52.37, 4.90),
    ("VN", "Vietnam", "Hanoi", 21.03, 105.85),
    ("KR", "South Korea", "Seoul", 37.57, 126.98),
    ("SG", "Singapore", "Singapore", 1.35, 103.82),
    ("ID", "Indonesia", "Jakarta", -6.21, 106.85),
    ("FR", "France", "Paris", 48.86, 2.35),
]


@dataclass
class GeoInfo:
    """Enrichment result for one IP."""

    ip: str
    country_code: str = ""
    country: str = ""
    city: str = ""
    asn: int | None = None
    as_org: str = ""
    lat: float | None = None
    lon: float | None = None
    source: str = "none"
    is_private: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Plain dict for SQL parameters and JSON."""
        return asdict(self)


def classify_ip(ip: str) -> str:
    """Return 'documentation', 'private', 'reserved', 'invalid' or 'public'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if any(addr in net for net in DOC_NETS):
        return "documentation"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "private"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


def demo_geo(ip: str) -> GeoInfo:
    """Deterministic fake enrichment for documentation IPs (same IP -> same answer)."""
    digest = hashlib.sha256(ip.encode()).digest()
    cc, country, city, lat, lon = _DEMO_PLACES[digest[0] % len(_DEMO_PLACES)]
    asn = 64512 + int.from_bytes(digest[1:3], "big") % 1000
    return GeoInfo(
        ip=ip,
        country_code=cc,
        country=country,
        city=city,
        asn=asn,
        as_org=f"DEMO-NET-{asn} (simulated)",
        lat=lat,
        lon=lon,
        source="demo",
    )


class Provider(Protocol):
    """Anything that can look up an IP."""

    name: str

    def lookup(self, ip: str) -> GeoInfo | None:
        """Return info or None when this provider has no answer."""


class MMDBProvider:
    """Reads local City and ASN databases in MaxMind DB format (DB-IP or MaxMind GeoLite2)."""

    name = "mmdb"

    def __init__(self, city_path: str, asn_path: str) -> None:
        self._city = self._open(city_path)
        self._asn = self._open(asn_path)

    @staticmethod
    def _open(path: str) -> Any:
        if not path or not os.path.isfile(path):
            return None
        try:
            import maxminddb  # imported lazily: optional at runtime

            return maxminddb.open_database(path)
        except Exception as exc:  # noqa: BLE001 - a broken DB must not crash the pipeline
            log.warning("cannot open mmdb", extra={"path": path, "error": str(exc)})
            return None

    @property
    def available(self) -> bool:
        """True when at least one database opened."""
        return self._city is not None or self._asn is not None

    def lookup(self, ip: str) -> GeoInfo | None:
        """Look up in both databases and merge the answers."""
        if not self.available:
            return None
        info = GeoInfo(ip=ip, source="mmdb")
        found = False
        if self._city is not None:
            rec = self._city.get(ip) or {}
            if rec:
                found = True
                country = rec.get("country") or {}
                info.country_code = str(country.get("iso_code") or "")[:2]
                info.country = str((country.get("names") or {}).get("en") or "")[:64]
                info.city = str(((rec.get("city") or {}).get("names") or {}).get("en") or "")[:64]
                loc = rec.get("location") or {}
                info.lat = loc.get("latitude")
                info.lon = loc.get("longitude")
        if self._asn is not None:
            rec = self._asn.get(ip) or {}
            if rec:
                found = True
                num = rec.get("autonomous_system_number")
                info.asn = int(num) if isinstance(num, int) else None
                info.as_org = str(rec.get("autonomous_system_organization") or "")[:128]
        return info if found else None


class RateLimiter:
    """At most ``max_calls`` per ``period`` seconds (sliding window). Clock is injectable for tests."""

    def __init__(self, max_calls: int, period: float = 60.0, clock: Any = None) -> None:
        self.max_calls = max(0, int(max_calls))
        self.period = period
        self.clock = clock or time.monotonic
        self.calls: deque[float] = deque()

    def allow(self) -> bool:
        """Record and allow one call, or refuse it when the window is full."""
        now = self.clock()
        while self.calls and now - self.calls[0] >= self.period:
            self.calls.popleft()
        if len(self.calls) >= self.max_calls:
            return False
        self.calls.append(now)
        return True


class IPInfoProvider:
    """Optional online lookup via ipinfo.io. Disabled unless a token is configured."""

    name = "api"
    MIN_TIMEOUT, MAX_TIMEOUT = 0.5, 5.0
    FAILURES_BEFORE_COOLDOWN, COOLDOWN_S = 3, 300.0

    def __init__(self, token: str, timeout: float = 3.0, max_per_minute: int = 30,
                 clock: Any = None, opener: Any = None) -> None:
        self.token = token
        self.timeout = min(self.MAX_TIMEOUT, max(self.MIN_TIMEOUT, float(timeout)))
        self.clock = clock or time.monotonic
        self.limiter = RateLimiter(max_per_minute, 60.0, self.clock)
        self.opener = opener or urllib.request.urlopen
        self.failures = 0
        self.paused_until = 0.0
        self.stats: dict[str, int] = {}

    def _count(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1

    def lookup(self, ip: str) -> GeoInfo | None:
        """Query the API. Only ever called for validated PUBLIC IP addresses."""
        if not self.token or classify_ip(ip) != "public":
            self._count("skipped_not_public")
            return None
        if self.clock() < self.paused_until:
            self._count("skipped_cooldown")
            return None
        if not self.limiter.allow():
            self._count("rate_limited")
            return None
        data = self._fetch(ip)
        if data is None:
            return None
        return self._parse(ip, data)

    def _fetch(self, ip: str) -> dict[str, Any] | None:
        # The URL host is fixed; only a validated IP is placed in the path.
        url = f"https://ipinfo.io/{ipaddress.ip_address(ip)}/json"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with self.opener(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310
                data = json.loads(resp.read(65536))
            if not isinstance(data, dict):
                raise ValueError("unexpected JSON")
        except Exception as exc:  # noqa: BLE001 - timeouts, HTTP 429/5xx, bad JSON: never fatal
            self.failures += 1
            self._count("failed")
            if self.failures >= self.FAILURES_BEFORE_COOLDOWN:
                self.paused_until = self.clock() + self.COOLDOWN_S
                self.failures = 0
                log.warning("enrichment api paused", extra={"seconds": self.COOLDOWN_S})
            log.warning("enrichment api failed", extra={"error": type(exc).__name__})
            return None
        self.failures = 0
        self._count("ok")
        return data

    @staticmethod
    def _parse(ip: str, data: dict[str, Any]) -> GeoInfo:
        org = str(data.get("org") or "")
        asn: int | None = None
        if org.startswith("AS") and " " in org:
            num, _, org = org.partition(" ")
            asn = int(num[2:]) if num[2:].isdigit() else None
        lat = lon = None
        if isinstance(data.get("loc"), str) and "," in data["loc"]:
            try:
                lat, lon = (float(x) for x in data["loc"].split(",", 1))
            except ValueError:
                lat = lon = None
        return GeoInfo(
            ip=ip,
            country_code=str(data.get("country") or "")[:2],
            country=str(data.get("country") or "")[:64],
            city=str(data.get("city") or "")[:64],
            asn=asn,
            as_org=org[:128],
            lat=lat,
            lon=lon,
            source="api",
        )


class Enricher:
    """Runs the provider chain with a database cache in front."""

    def __init__(self, providers: list[Any], cache_days: int = 30) -> None:
        self.providers = providers
        self.cache_days = cache_days
        self.stats: dict[str, int] = {}

    def _count(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1

    def lookup(self, ip: str, conn: Any | None = None) -> GeoInfo:
        """Return enrichment for ``ip``, using and filling the DB cache when ``conn`` is given."""
        kind = classify_ip(ip)
        if kind == "documentation":
            self._count("demo")
            return demo_geo(ip)
        if kind in {"private", "reserved", "invalid"}:
            self._count("private")
            return GeoInfo(ip=ip, country="Private / reserved", source="local", is_private=True)
        if conn is not None:
            cached = self._cache_get(conn, ip)
            if cached:
                self._count("cache_hit")
                return cached
        for provider in self.providers:
            info = provider.lookup(ip)
            if info:
                self._count(provider.name)
                if conn is not None:
                    self._cache_put(conn, info)
                return info
        self._count("miss")
        return GeoInfo(ip=ip, source="none")

    def _cache_get(self, conn: Any, ip: str) -> GeoInfo | None:
        row = conn.execute(
            "SELECT country_code, country, city, asn, as_org, lat, lon, source, is_private "
            "FROM honeylens.enrichment_cache WHERE ip = %s AND expires_at > now()",
            (ip,),
        ).fetchone()
        if not row:
            return None
        return GeoInfo(ip, row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])

    def _cache_put(self, conn: Any, info: GeoInfo) -> None:
        expires = datetime.now(UTC) + timedelta(days=self.cache_days)
        conn.execute(
            "INSERT INTO honeylens.enrichment_cache "
            "(ip, country_code, country, city, asn, as_org, lat, lon, source, is_private, expires_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (ip) DO UPDATE SET country_code=EXCLUDED.country_code, "
            "country=EXCLUDED.country, city=EXCLUDED.city, asn=EXCLUDED.asn, as_org=EXCLUDED.as_org, "
            "lat=EXCLUDED.lat, lon=EXCLUDED.lon, source=EXCLUDED.source, "
            "is_private=EXCLUDED.is_private, fetched_at=now(), expires_at=EXCLUDED.expires_at",
            (
                info.ip, info.country_code, info.country, info.city, info.asn, info.as_org,
                info.lat, info.lon, info.source, info.is_private, expires,
            ),
        )


def build_enricher(settings: Any) -> Enricher:
    """Create the standard chain from settings."""
    providers: list[Any] = []
    mmdb = MMDBProvider(settings.mmdb_city_path, settings.mmdb_asn_path)
    if mmdb.available:
        providers.append(mmdb)
    if settings.enrich_api_token:
        providers.append(IPInfoProvider(settings.enrich_api_token,
                                        timeout=getattr(settings, "enrich_api_timeout_s", 3.0),
                                        max_per_minute=getattr(settings, "enrich_api_max_per_minute", 30)))
    return Enricher(providers, settings.enrich_cache_days)
