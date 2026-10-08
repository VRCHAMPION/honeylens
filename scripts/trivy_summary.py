#!/usr/bin/env python3
"""Summarise Trivy JSON reports per package: severity counts and whether a fix exists.

Usage: python scripts/trivy_summary.py IMAGE_NAME report.json [IMAGE_NAME report.json ...] > table.md
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict


def summarise(name: str, path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    pkgs: dict[tuple[str, str, str], dict] = defaultdict(lambda: {"HIGH": 0, "CRITICAL": 0, "fixed": set(), "status": set(), "ids": []})
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            k = (res.get("Target", "").split(" (")[0][-40:], v["PkgName"], v.get("InstalledVersion", ""))
            p = pkgs[k]
            p[v["Severity"]] += 1
            p["status"].add(v.get("Status", "unknown"))
            if v.get("FixedVersion"):
                p["fixed"].add(v["FixedVersion"])
            if v["Severity"] == "CRITICAL":
                p["ids"].append(v["VulnerabilityID"])
    tot_h = sum(p["HIGH"] for p in pkgs.values())
    tot_c = sum(p["CRITICAL"] for p in pkgs.values())
    fixable = sum(p["HIGH"] + p["CRITICAL"] for p in pkgs.values() if p["fixed"])
    out = [f"### {name}: {tot_h} HIGH / {tot_c} CRITICAL ({fixable} with an upstream fix version)", "",
           "| Target | Package | Installed | HIGH | CRIT | Fix available | Status | CRITICAL IDs |", "|---|---|---|---|---|---|---|---|"]
    for (tgt, pkg, ver), p in sorted(pkgs.items(), key=lambda kv: (-kv[1]["CRITICAL"], -kv[1]["HIGH"], kv[0][1])):
        fix = ", ".join(sorted(p["fixed"]))[:60] or "no"
        status = ", ".join(sorted(p["status"]))
        out.append(f"| {tgt} | {pkg} | {ver[:30]} | {p['HIGH']} | {p['CRITICAL']} | {fix} | {status} | {', '.join(p['ids'])} |")
    return out + [""]


if __name__ == "__main__":
    args = sys.argv[1:]
    for i in range(0, len(args), 2):
        print("\n".join(summarise(args[i], args[i + 1])))
