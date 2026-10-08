#!/usr/bin/env python3
"""Check Grafana: is it up, is the datasource healthy, does every panel return data?

Usage (stack running):
    python scripts/check_grafana.py                 # reads GF_ADMIN_USER/PASSWORD from .env
    python scripts/check_grafana.py --data simulated

Checks:
1. /api/health is OK,
2. the provisioned datasource "honeylens-pg" passes Grafana's own health check,
3. all five HoneyLens dashboards are provisioned,
4. EVERY panel query runs without error and returns at least one row
   (template variables $data / $session are filled in like the UI would).
Exit code 0 = all good.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ["hl-soc-overview", "hl-creds-commands", "hl-attack-behaviour", "hl-session-explorer", "hl-pipeline-health"]


def env_file() -> dict[str, str]:
    out = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.startswith("#"):
                out[k.strip()] = v.strip()
    return out


class Grafana:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def call(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data else "GET",  # noqa: S310
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        # Ignore any HTTP(S)_PROXY settings: Grafana is on this machine.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=30) as r:  # noqa: S310  # nosec B310
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body or b"{}")
            except json.JSONDecodeError:
                return e.code, {"error": body[:200].decode(errors="replace")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:3000")
    ap.add_argument("--data", default="all", choices=["all", "real", "simulated"])
    ap.add_argument("--range", default="now-7d")
    args = ap.parse_args()
    env = env_file()
    g = Grafana(args.url, env.get("GF_ADMIN_USER", "admin"), env.get("GF_ADMIN_PASSWORD", ""))
    failures = 0
    code, health = g.call("/api/health")
    print(f"grafana health: {code} {health.get('database')} version={health.get('version')}")
    failures += code != 200
    code, ds = g.call("/api/datasources/uid/honeylens-pg/health")
    print(f"datasource health: {code} {ds.get('status')} - {ds.get('message')}")
    failures += ds.get("status") != "OK"
    _, found = g.call("/api/search?tag=honeylens&type=dash-db")
    uids = sorted(d["uid"] for d in found) if isinstance(found, list) else []
    print(f"dashboards found: {len(uids)} {uids}")
    failures += sorted(EXPECTED) != uids
    session = ""
    for uid in EXPECTED:
        _, dash = g.call(f"/api/dashboards/uid/{uid}")
        panels = dash.get("dashboard", {}).get("panels", [])
        for p in panels:
            for t in p.get("targets", []):
                sql = t["rawSql"].replace("${data}", args.data).replace("${session:sqlstring}", "'" + session.replace("'", "''") + "'")
                code, res = g.call("/api/ds/query", {"from": args.range, "to": "now", "queries": [
                    {"refId": t["refId"], "datasource": {"uid": "honeylens-pg"}, "rawSql": sql,
                     "format": t.get("format", "table"), "rawQuery": True}]})
                frames = res.get("results", {}).get(t["refId"], {}).get("frames", [])
                err = res.get("results", {}).get(t["refId"], {}).get("error")
                rows = sum(len((f.get("data", {}).get("values") or [[]])[0]) for f in frames)
                ok = code == 200 and not err and rows > 0
                failures += not ok
                print(f"  [{'OK ' if ok else 'FAIL'}] {uid:22} {p['title'][:55]:55} rows={rows}{' ERR ' + str(err)[:120] if err else ''}")
        if uid == "hl-attack-behaviour":
            # pick the top session for the Session Explorer variable, like the UI default
            sql = "SELECT session_id FROM honeylens.sessions ORDER BY severity DESC NULLS LAST, start_ts DESC LIMIT 1"
            _, res = g.call("/api/ds/query", {"from": args.range, "to": "now", "queries": [
                {"refId": "A", "datasource": {"uid": "honeylens-pg"}, "rawSql": sql, "format": "table", "rawQuery": True}]})
            frames = res.get("results", {}).get("A", {}).get("frames", [])
            session = frames[0]["data"]["values"][0][0] if frames and frames[0]["data"]["values"][0] else ""
    print(f"\n{'PASS' if not failures else 'FAIL'}: {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
