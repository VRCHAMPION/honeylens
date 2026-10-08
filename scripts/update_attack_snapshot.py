#!/usr/bin/env python3
"""Build the small ATT&CK snapshot that HoneyLens bundles.

What: MITRE publishes the full Enterprise ATT&CK (Adversarial Tactics,
Techniques, and Common Knowledge) matrix as one big STIX (Structured Threat
Information eXpression) JSON file of about 50 MB. We only need, for every
technique: its ID, name, tactics, and whether it is revoked or deprecated.

Why: a 50 MB file would bloat the repository and slow every test.
The trimmed file keeps the official IDs and records the SHA-256 hash of the
exact upstream file, so anyone can re-create it and check we did not change
anything.

How to run (needs internet, run by a human, never by the pipeline):

    python scripts/update_attack_snapshot.py 19.2

or, if you already downloaded the file:

    python scripts/update_attack_snapshot.py 19.2 --input enterprise-attack-19.2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
OUT_DIR = Path(__file__).resolve().parents[1] / "src" / "honeylens" / "mitre" / "data"


def main() -> int:
    """Download (or read) the official file and write the trimmed snapshot."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="ATT&CK version, for example 19.2")
    parser.add_argument("--input", type=Path, help="already-downloaded STIX JSON")
    args = parser.parse_args()

    if args.input:
        raw = args.input.read_bytes()
        source = str(args.input.name)
    else:
        url = URL.format(version=args.version)
        # Fixed, trusted MITRE URL (not attacker controlled).
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310  # nosec B310
            raw = resp.read()
        source = url

    bundle = json.loads(raw)
    techniques: dict[str, dict[str, object]] = {}
    tactics: dict[str, dict[str, str]] = {}
    for obj in bundle["objects"]:
        refs = obj.get("external_references") or []
        ext_id = next(
            (r.get("external_id") for r in refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if obj.get("type") == "x-mitre-tactic" and ext_id:
            tactics[obj["x_mitre_shortname"]] = {"id": ext_id, "name": obj["name"]}
        if obj.get("type") != "attack-pattern" or not ext_id:
            continue
        techniques[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": sorted(
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    out = {
        "attack_version": args.version,
        "domain": "enterprise-attack",
        "source": source,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"enterprise-attack-{args.version}.min.json"
    path.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {path} with {len(techniques)} techniques, {len(tactics)} tactics")
    return 0


if __name__ == "__main__":
    sys.exit(main())
