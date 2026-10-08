#!/usr/bin/env python3
"""Validate STIX 2.1 bundles with the OASIS ``stix2`` library (not just JSON parsing).

Usage: python scripts/validate_stix.py docs/samples/iocs.stix.json [more.json ...]

Checks, per file:
  * ``stix2.parse(..., version="2.1", allow_custom=False)`` builds real stix2
    objects: required properties, types, timestamps, UUIDv4/v5 ids and
    property constraints are all enforced by the library,
  * every indicator ``pattern`` passes the official STIX pattern grammar
    (``stix2patterns`` validator),
  * every ``object_refs`` / relationship ref points at an object in the bundle.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import stix2
from stix2patterns.validator import run_validator


def validate(text: str) -> dict[str, int]:
    """Raise on any problem; return counts of object types."""
    bundle = stix2.parse(text, allow_custom=False, version="2.1")
    if not isinstance(bundle, stix2.v21.Bundle):
        raise ValueError("top-level object is not a STIX 2.1 bundle")
    ids = {o.id for o in bundle.objects}
    if len(ids) != len(bundle.objects):
        raise ValueError("duplicate STIX ids")
    counts: dict[str, int] = {}
    for o in bundle.objects:
        counts[o.type] = counts.get(o.type, 0) + 1
        if o.spec_version != "2.1":
            raise ValueError(f"{o.id}: spec_version {o.spec_version}")
        if o.type == "indicator":
            errors = run_validator(o.pattern, stix_version="2.1")
            if errors:
                raise ValueError(f"{o.id}: bad pattern {o.pattern!r}: {errors}")
        for ref in list(getattr(o, "object_refs", [])) + [getattr(o, "source_ref", None), getattr(o, "target_ref", None)]:
            if ref and ref not in ids:
                raise ValueError(f"{o.id}: dangling reference {ref}")
    return counts


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__)
        return 2
    bad = 0
    for p in paths:
        try:
            counts = validate(Path(p).read_text(encoding="utf-8"))
            print(f"VALID   {p}: {json.dumps(counts, sort_keys=True)}")
        except Exception as exc:  # noqa: BLE001
            bad += 1
            print(f"INVALID {p}: {type(exc).__name__}: {exc}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
