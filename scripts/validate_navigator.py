#!/usr/bin/env python3
"""Validate ATT&CK Navigator layer files against the official layer format 4.5.

Spec: https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
(latest layer format; Navigator 5.3.2 is the latest release, 21 April 2026).

Usage: python scripts/validate_navigator.py docs/samples/attack-navigator-layer.json [...]

Checks required fields and types from the spec, ``versions.layer == "4.5"``,
``versions.navigator >= 4.9.0``, a valid domain, gradient rules (>= 2 colours,
maxValue > minValue), and that every techniqueID / tactic exists, is not
revoked or deprecated, and matches its tactic in the bundled ATT&CK snapshot.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from honeylens.mitre.attack import load_snapshot

DOMAINS = {"enterprise-attack", "mobile-attack", "ics-attack"}
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
TID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def validate(layer: dict[str, Any]) -> int:
    """Raise ValueError on the first problem; return the number of technique entries."""
    snap = load_snapshot()
    for key, typ in (("name", str), ("domain", str), ("versions", dict)):
        if not isinstance(layer.get(key), typ):
            raise ValueError(f"'{key}' missing or not {typ.__name__}")
    if layer["domain"] not in DOMAINS:
        raise ValueError(f"bad domain {layer['domain']!r}")
    v = layer["versions"]
    if v.get("layer") != "4.5":
        raise ValueError("versions.layer must be '4.5'")
    if not isinstance(v.get("navigator"), str) or _ver(v["navigator"]) < (4, 9, 0):
        raise ValueError("versions.navigator must be at least 4.9.0")
    if "attack" in v and str(v["attack"]).split(".")[0] != snap["attack_version"].split(".")[0]:
        raise ValueError(f"versions.attack {v['attack']} != snapshot {snap['attack_version']}")
    g = layer.get("gradient")
    if g is not None:
        if not (isinstance(g.get("colors"), list) and len(g["colors"]) >= 2 and all(HEX.match(c) for c in g["colors"])):
            raise ValueError("gradient.colors needs >= 2 #RRGGBB values")
        if not g["maxValue"] > g["minValue"]:
            raise ValueError("gradient.maxValue must be > minValue")
    for item in layer.get("legendItems", []):
        if not (isinstance(item.get("label"), str) and isinstance(item.get("color"), str)):
            raise ValueError("legend item needs label and color")
    techs = layer.get("techniques", [])
    if not isinstance(techs, list):
        raise ValueError("techniques must be a list")
    for t in techs:
        tid = t.get("techniqueID")
        if not isinstance(tid, str) or not TID.match(tid):
            raise ValueError(f"bad techniqueID {tid!r}")
        info = snap["techniques"].get(tid)
        if not info:
            raise ValueError(f"{tid} not in ATT&CK {snap['attack_version']}")
        if info.get("revoked") or info.get("deprecated"):
            raise ValueError(f"{tid} is revoked/deprecated")
        if "tactic" in t and t["tactic"] not in info["tactics"]:
            raise ValueError(f"{tid} is not in tactic {t['tactic']}")
        if "score" in t and not isinstance(t["score"], (int, float)):
            raise ValueError(f"{tid} score must be a number")
        if "enabled" in t and not isinstance(t["enabled"], bool):
            raise ValueError(f"{tid} enabled must be boolean")
    return len(techs)


def main(paths: list[str]) -> int:
    bad = 0
    for p in paths:
        try:
            n = validate(json.loads(Path(p).read_text(encoding="utf-8")))
            print(f"VALID   {p}: layer 4.5, {n} technique entries")
        except (ValueError, KeyError, TypeError) as exc:
            bad += 1
            print(f"INVALID {p}: {exc}")
    return 1 if bad else 0 if paths else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
