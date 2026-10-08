"""IOC (Indicator of Compromise) exports: CSV, STIX 2.1 and ATT&CK Navigator.

* **CSV** - opens in Excel / Google Sheets; easy to share with anyone.
* **STIX 2.1** (Structured Threat Information eXpression) - the standard JSON
  format threat-intel platforms (MISP, OpenCTI) import. Machine-readable, so
  values are NOT defanged here (tools need the real value) but every object is
  labelled ``simulated`` or ``honeypot-observed`` and has low confidence.
* **Navigator layer** - colours the ATT&CK matrix by how often each technique
  was seen; load it at https://mitre-attack.github.io/attack-navigator/.

With ``mask_ips=True`` IP addresses are masked in CSV (including IPs inside
URLs), IP indicators are left out of STIX entirely (a masked IP is not a valid
STIX pattern) and IPs inside URL indicators are masked.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from honeylens.mitre.attack import navigator_layer
from honeylens.pipeline.sanitize import mask_ip, mask_ips_in_text
from honeylens.reporting.data import ReportData

NAMESPACE = uuid.UUID("6b7f2f0e-6c1e-4c0a-9a43-2d8f1f1c0a11")  # fixed => deterministic STIX IDs


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + key)}"


def _stix_time(dt: datetime | None) -> str:
    dt = (dt or datetime.now(UTC)).astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _esc(value: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def to_csv(d: ReportData, mask_ips: bool = False) -> str:
    """One row per IOC: type, value, counts, first/last seen (UTC), simulated flag."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "count", "first_seen_utc", "last_seen_utc", "simulated", "context"])

    def safe(value: str) -> str:
        # Spreadsheet apps may ignore leading whitespace/BOM before formulas.
        # Prefix any such cell so exported attacker-controlled text stays inert.
        first = value.lstrip(" \t\r\n\ufeff")[:1]
        return "'" + value if first in ("=", "+", "-", "@") or value[:1] in ("\t", "\r", "\n") else value

    for r in d.ioc_ips:
        w.writerow(["ipv4-addr" if ":" not in r["ip"] else "ipv6-addr",
                    mask_ip(r["ip"]) if mask_ips else r["ip"], r["sessions"],
                    _stix_time(r["first_seen"]), _stix_time(r["last_seen"]), r["simulated"],
                    safe(f"max severity {r['max_severity']}; classes {','.join(c for c in r['classes'] if c)}")])
    for r in d.ioc_urls:
        url = mask_ips_in_text(r["url"]) if mask_ips else r["url"]
        w.writerow(["url", safe(url), r["attempts"], _stix_time(r["first_seen"]), _stix_time(r["last_seen"]),
                    r["simulated"], "download attempted (never fetched)"])
    for r in d.ioc_hashes:
        w.writerow(["file:sha256", r["shasum"], r["seen"], _stix_time(r["first_seen"]), "", r["simulated"], ""])
    return buf.getvalue()


def to_stix(d: ReportData, mask_ips: bool = False) -> dict[str, Any]:
    """Build a STIX 2.1 bundle (identity, indicators, attack-patterns, report)."""
    created = _stix_time(d.window.end)
    identity = {
        "type": "identity", "spec_version": "2.1", "id": _sid("identity", "honeylens"),
        "created": created, "modified": created, "name": "HoneyLens honeypot", "identity_class": "system",
    }
    objects: list[dict[str, Any]] = [identity]

    def indicator(key: str, name: str, pattern: str, first: datetime | None, simulated: bool, extra: str) -> None:
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _sid("indicator", key),
            "created": created, "modified": created, "created_by_ref": identity["id"],
            "name": name, "description": extra, "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": _stix_time(first),
            "confidence": 15 if simulated else 40,
            "labels": ["simulated" if simulated else "honeypot-observed"],
        })

    if not mask_ips:
        for r in d.ioc_ips:
            kind = "ipv6-addr" if ":" in r["ip"] else "ipv4-addr"
            indicator(f"ip:{r['ip']}", f"Honeypot attacker IP {r['ip']}", f"[{kind}:value = '{_esc(r['ip'])}']",
                      r["first_seen"], r["simulated"], f"{r['sessions']} sessions, max severity {r['max_severity']}")
    seen_urls: set[str] = set()
    for r in d.ioc_urls:
        url = mask_ips_in_text(r["url"]) if mask_ips else r["url"]
        if url in seen_urls:
            continue  # two URLs can become identical once their IPs are masked
        seen_urls.add(url)
        indicator(f"url:{url}", "URL an attacker tried to download (never fetched)",
                  f"[url:value = '{_esc(url)}']", r["first_seen"], r["simulated"], f"{r['attempts']} attempts")
    for r in d.ioc_hashes:
        indicator(f"sha256:{r['shasum']}", "File hash seen on honeypot",
                  f"[file:hashes.'SHA-256' = '{r['shasum']}']", r["first_seen"], r["simulated"], "")
    for t in d.techniques:
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": _sid("attack-pattern", t["technique_id"]),
            "created": created, "modified": created, "name": t["technique_name"],
            "external_references": [{"source_name": "mitre-attack", "external_id": t["technique_id"],
                                      "url": "https://attack.mitre.org/techniques/" + t["technique_id"].replace(".", "/") + "/"}],
        })
    refs = [o["id"] for o in objects if o["type"] != "identity"] or [identity["id"]]
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _sid("report", created + d.data_filter),
        "created": created, "modified": created, "created_by_ref": identity["id"],
        "name": f"HoneyLens weekly report ({d.data_filter} data)", "report_types": ["threat-report"],
        "published": created, "object_refs": refs,
        "description": "Observed on an SSH honeypot. Source IPs are often compromised or rented machines: no attribution.",
    })
    return {"type": "bundle", "id": _sid("bundle", created + d.data_filter + str(mask_ips)), "objects": objects}


def to_navigator(d: ReportData) -> dict[str, Any]:
    """ATT&CK Navigator layer scored by sessions per technique this week."""
    counts = {t["technique_id"]: int(t["sessions"]) for t in d.techniques}
    return navigator_layer(counts, name=f"HoneyLens observed ({d.data_filter})",
                           description="Techniques seen on the honeypot this week; score = sessions.")


def dumps(obj: Any) -> str:
    """Stable JSON text."""
    return json.dumps(obj, indent=2, sort_keys=False, default=str) + "\n"
