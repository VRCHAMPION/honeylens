#!/usr/bin/env python3
"""End-to-end integration test of the REAL Docker Compose stack.

    python scripts/integration_test.py            # full run, starts from "down -v" (DELETES local data!)
    python scripts/integration_test.py --keep     # do not run "down -v" first

Steps (each prints PASS/FAIL and timings):
 1. docker compose down -v, then up -d --build, wait until healthy
 2. loopback port check on the running containers
 3. live simulator -> Cowrie (real SSH inside the Compose network) + synthetic data
 4. pipeline ingests everything; DB count == independently computed expected count
 5. PostgreSQL outage: stop postgres, generate traffic, start postgres -> pipeline catches up, no loss/dupes
 6. pipeline restart -> nothing re-ingested
 7. log rotation (rename + new file, like Cowrie at midnight) -> both files ingested
 8. malformed, oversized and hostile lines appended to the live log -> counted / stored safely
 9. role permissions (Grafana role cannot write), container users (non-root)
10. Grafana datasource + every panel returns data; weekly report + exports generated
    (exports validated with the stix2 library and the Navigator layer-4.5 checker)
11. scheduled report service: next run is Monday 06:00 IST, --run-now writes a report
12. Cowrie accepts ONLY the fixed fake credentials (real SSH, wrong passwords fail)
13. placeholder / missing secrets stop migrate, pipeline and Compose (fail closed)
Exit code 0 only if every step passed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS: list[tuple[str, bool, str]] = []
# Expected-count helper, run INSIDE the honeylens image with read-only volumes.
EXPECTED_PY = r"""
import glob, ipaddress
from honeylens.pipeline.events import parse_line, BadEvent
uids=set(); bad=0; big=0; loop=0
for path in sorted(glob.glob('/cowrie-var/log/cowrie/cowrie.json*') + glob.glob('/synthetic/*.json')):
    for raw in open(path,'rb'):
        raw=raw.rstrip(b'\n')
        if len(raw) > 65536: big+=1; continue
        try: ev=parse_line(raw)
        except BadEvent: bad+=1; continue
        if ev.src_ip and ipaddress.ip_address(ev.src_ip).is_loopback: loop+=1; continue
        uids.add(ev.event_uid)
print(len(uids), bad, big, loop)
"""


def sh(*args: str, check: bool = True, timeout: int = 900, stdin: str | None = None) -> str:
    r = subprocess.run(list(args), cwd=ROOT, capture_output=True, text=True, timeout=timeout, input=stdin)  # noqa: S603  # nosec B603
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed ({r.returncode}): {r.stdout[-800:]} {r.stderr[-800:]}")
    return r.stdout


def dc(*args: str, **kw: object) -> str:
    return sh("docker", "compose", *args, **kw)  # type: ignore[arg-type]


def psql(sql: str) -> str:
    return dc("exec", "-T", "postgres", "sh", "-c", 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq', stdin=sql).strip()


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)


def wait_healthy(services: list[str], timeout: int = 240) -> float:
    start = time.time()
    while time.time() - start < timeout:
        out = dc("ps", "--format", "json")
        rows = [json.loads(line) for line in out.splitlines() if line.strip()] if not out.strip().startswith("[") else json.loads(out)
        health = {r["Service"]: r.get("Health", "") for r in rows}
        if all(health.get(s) == "healthy" for s in services):
            return time.time() - start
        time.sleep(3)
    raise RuntimeError(f"not healthy after {timeout}s: {health}")


def expected() -> tuple[int, int, int, int]:
    out = sh("docker", "run", "--rm", "--network", "none", "-v", "honeylens_cowrie_var:/cowrie-var:ro",
             "-v", "honeylens_hl_synthetic:/synthetic:ro", "honeylens:1.0.0", "python", "-c", EXPECTED_PY)
    a, b, c, d = (int(x) for x in out.split())
    return a, b, c, d


def wait_caught_up(timeout: int = 180) -> tuple[int, int, float]:
    start = time.time()
    exp = expected()[0]
    while time.time() - start < timeout:
        got = int(psql("SELECT count(*) FROM honeylens.raw_events;") or 0)
        if got == exp:
            return got, exp, time.time() - start
        time.sleep(3)
    return got, exp, time.time() - start


def as_cowrie(py: str) -> None:
    """Run Python as Cowrie's uid 999 against the Cowrie log volume (to simulate log events)."""
    sh("docker", "run", "--rm", "--network", "none", "-u", "999:999", "-v", "honeylens_cowrie_var:/v",
       "honeylens:1.0.0", "python", "-c", py)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    t0 = time.time()
    if not args.keep:
        dc("down", "-v", "--remove-orphans")
    t = time.time()
    dc("up", "-d", "--build", timeout=1800)
    took = wait_healthy(["postgres", "cowrie", "pipeline", "grafana", "report-scheduler"])
    record("1 stack up from clean volumes", True, f"(up+healthy in {time.time() - t:.0f}s; health wait {took:.0f}s)")

    out = sh(sys.executable, "scripts/check_ports.py", "--live", check=False)
    record("2 loopback-only published ports (live)", "PASS" in out and "FAIL" not in out)

    t = time.time()
    live = dc("--profile", "sim", "run", "--rm", "simulator", "honeylens-simulator", "live", "--target", "cowrie",
              "--port", "2222", "--sessions", "16", "--seed", "7", "--speed", "4")
    record("3a live simulator: real SSH sessions to Cowrie", "16 connected" in live, f"({live.strip().splitlines()[-1]}; {time.time() - t:.0f}s)")
    syn = dc("--profile", "sim", "run", "--rm", "synthetic")
    record("3b synthetic events written", "wrote" in syn, syn.strip().splitlines()[-1][:90])
    got, exp, secs = wait_caught_up()
    record("4 pipeline ingested exactly the expected events", got == exp > 0, f"(db={got} expected={exp}; {secs:.0f}s)")
    real_ssh = psql("SELECT count(*) FROM honeylens.sessions WHERE sensor <> 'honeylens-synthetic' AND login_success;")
    record("4b live Cowrie sessions reached PostgreSQL", int(real_ssh or 0) > 0, f"({real_ssh} successful live logins)")

    # 5. PostgreSQL outage
    dc("stop", "postgres")
    dc("--profile", "sim", "run", "--rm", "simulator", "honeylens-simulator", "live", "--target", "cowrie", "--port", "2222",
       "--sessions", "6", "--seed", "11", "--speed", "4")
    time.sleep(8)
    logs = dc("logs", "--since", "60s", "pipeline")
    saw_retry = "database error, will retry" in logs
    t = time.time()
    dc("start", "postgres")
    wait_healthy(["postgres"])
    got, exp, secs = wait_caught_up()
    record("5 PostgreSQL outage -> retry -> full recovery", saw_retry and got == exp, f"(retry logged={saw_retry}; db={got} expected={exp}; caught up {time.time() - t:.0f}s after restart)")

    # 6. pipeline restart
    before = psql("SELECT count(*) FROM honeylens.raw_events;")
    dc("restart", "pipeline")
    wait_healthy(["pipeline"])
    time.sleep(6)
    after = psql("SELECT count(*) FROM honeylens.raw_events;")
    # New Cowrie healthcheck lines may be read (and ignored); what must NOT happen is re-reading
    # old events, which would show up as duplicates.
    reread = psql("SELECT coalesce(sum(duplicates),0) FROM honeylens.pipeline_stats WHERE ts > now() - interval '15 seconds';")
    record("6 pipeline restart resumes from saved offsets", before == after and reread == "0", f"(rows {before}->{after}, old events re-read={reread})")

    # 7. rotation
    dc("stop", "cowrie")
    as_cowrie("import os; os.rename('/v/log/cowrie/cowrie.json', '/v/log/cowrie/cowrie.json.2026-01-01')")
    dc("start", "cowrie")
    wait_healthy(["cowrie"])
    dc("--profile", "sim", "run", "--rm", "simulator", "honeylens-simulator", "live", "--target", "cowrie", "--port", "2222",
       "--sessions", "4", "--seed", "13", "--speed", "4")
    got, exp, secs = wait_caught_up()
    # Offsets are tracked per inode: the renamed file and the new file must both be known.
    files = psql("SELECT count(*) FROM honeylens.ingest_offsets WHERE path LIKE '/cowrie-var/log/cowrie/cowrie.json%';")
    rotated = psql("SELECT count(*) FROM honeylens.ingest_offsets WHERE path LIKE '%.2026-01-01';")
    record("7 log rotation (rename + new file)", got == exp and int(files) >= 2 and rotated == "1",
           f"(db={got} expected={exp}; tracked files={files}, rotated file tracked={rotated})")

    # 8. malformed / oversized / hostile lines in the LIVE log
    hostile = json.dumps({"eventid": "cowrie.command.input", "session": "hostile0001", "src_ip": "198.51.100.66",
                          "timestamp": "2026-10-01T00:00:00Z",
                          "input": "<script>alert(1)</script>\u001b[2J'; DROP TABLE honeylens.sessions; --\u0000"})
    # Stop Cowrie while we append: Cowrie keeps its own write position, so a concurrent
    # writer can be overwritten (seen in the first run of this test).
    dc("stop", "cowrie")
    as_cowrie("open('/v/log/cowrie/cowrie.json','a').write('not json at all\\n' + 'X'*200000 + '\\n' + "
              + repr(hostile) + " + '\\n')")
    dc("start", "cowrie")
    wait_healthy(["cowrie"])
    got, exp, secs = wait_caught_up()
    m = psql("SELECT sum(malformed), sum(oversized) FROM honeylens.pipeline_stats;")
    cmd = psql("SELECT command FROM honeylens.commands WHERE session_id='hostile0001';")
    ok = got == exp and "\x1b" not in cmd and "<script>" in cmd and psql("SELECT to_regclass('honeylens.sessions');") == "honeylens.sessions"
    record("8 malformed/oversized/hostile lines handled", ok and m.split("|")[0] != "0" and m.split("|")[1] != "0",
           f"(malformed|oversized={m}; hostile stored as text, tables intact)")

    # 9. permissions + container users
    env = {k: v for k, v in (line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                             if "=" in line and not line.startswith("#"))}
    r = subprocess.run(["docker", "compose", "exec", "-T", "-e", f"PGPASSWORD={env['HL_GRAFANA_DB_PASSWORD']}", "postgres",  # noqa: S603,S607
                        "psql", "-h", "127.0.0.1", "-U", "hl_grafana", "-d", env.get("POSTGRES_DB", "honeylens"),
                        "-c", "DELETE FROM honeylens.sessions"], cwd=ROOT, capture_output=True, text=True)  # nosec B603 B607
    msg = (r.stdout + r.stderr).strip().splitlines()
    record("9a Grafana DB role cannot delete data", r.returncode != 0 and "read-only" in (r.stdout + r.stderr),
           f"({msg[0] if msg else ''})")
    users = {}
    for svc in ("cowrie", "pipeline", "grafana", "postgres"):
        cid = dc("ps", "-q", svc).strip()
        users[svc] = sh("docker", "inspect", "-f", "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.HostConfig.CapDrop}}|{{.HostConfig.SecurityOpt}}", cid).strip()
    ok = all("|false|" in u for u in users.values()) and users["cowrie"].startswith("999:999|true") and users["grafana"].startswith("472:0|true")
    record("9b containers non-root / read-only / not privileged", ok, json.dumps(users))
    pipe_user = dc("exec", "-T", "pipeline", "id").strip()
    record("9c pipeline runs as uid 10001", "uid=10001" in pipe_user, pipe_user)

    # 10. Grafana + report
    check_uid = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "0:0"
    grafana_cmd = [
        "docker", "run", "--rm", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--network", "honeylens_backend", "--user", check_uid, "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--pids-limit=32",
        "--mount", f"type=bind,source={ROOT / 'scripts'},target=/app/scripts,readonly",
        "--mount", f"type=bind,source={ROOT / '.env'},target=/app/.env,readonly",
        "honeylens:1.0.0", "python", "/app/scripts/check_grafana.py", "--url", "http://grafana:3000",
    ]
    grafana = subprocess.run(grafana_cmd, cwd=ROOT, capture_output=True, text=True,
                             timeout=900)  # noqa: S603,S607  # nosec B603 B607
    grafana_output = (grafana.stdout + grafana.stderr).splitlines()
    grafana_output = [line for line in grafana_output if line.strip()]
    grafana_summary = grafana_output[-1] if grafana_output else f"no output (exit {grafana.returncode})"
    grafana_ok = grafana.returncode == 0 and grafana_summary.startswith("PASS:")
    record("10a Grafana datasource + all panels return data", grafana_ok,
           f"(exit {grafana.returncode}; {grafana_summary})")
    (ROOT / "out").mkdir(exist_ok=True)
    rep = sh("docker", "compose", "--profile", "tools", "run", "--rm", "-e", "HL_DB_USER=hl_report", "-u",
             f"{os.getuid() if hasattr(os, 'getuid') else 10001}:{os.getgid() if hasattr(os, 'getgid') else 10001}",
             "report", "honeylens-report", "--out", "/out")
    record("10b weekly report + CSV/STIX/Navigator", all((ROOT / "out" / f).stat().st_size > 0 for f in
           ("weekly-report.html", "iocs.csv", "iocs.stix.json", "attack-navigator-layer.json")), rep.strip().replace("\n", "; "))

    v = sh(sys.executable, "scripts/validate_stix.py", "out/iocs.stix.json", check=False)
    n = sh(sys.executable, "scripts/validate_navigator.py", "out/attack-navigator-layer.json", check=False)
    record("10c exports valid (stix2 library + Navigator layer 4.5)", v.startswith("VALID") and n.startswith("VALID"),
           f"({v.strip()[:110]}; {n.strip()[:80]})")

    # 11. scheduled weekly report service
    nxt = dc("exec", "-T", "report-scheduler", "honeylens-report-scheduler", "--print-next").strip()
    dc("exec", "-T", "report-scheduler", "honeylens-report-scheduler", "--run-now")
    listing = dc("exec", "-T", "report-scheduler", "python", "-c",
                 "import glob,os;print(sorted(os.path.basename(p) for p in glob.glob('/out/*/*')))").strip()
    ok = "T06:00:00+05:30" in nxt and "Asia/Kolkata" in nxt and all(f in listing for f in (
        "weekly-report.html", "iocs.csv", "iocs.stix.json", "attack-navigator-layer.json"))
    record("11 report-scheduler: Monday 06:00 IST + run-now output", ok, f"({nxt}; files={listing})")

    # 12. Cowrie credentials: only the fixed fake list works (real SSH inside the Compose network)
    probe = (
        "import paramiko\n"
        "res=[]\n"
        "for u,p in [('root','xc3511'),('pi','raspberry'),('root','toor'),('root','not-in-list-93'),('admin','admin123'),('oracle','oracle')]:\n"
        "    c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "    try:\n"
        "        c.connect('cowrie',2222,u,p,timeout=10,allow_agent=False,look_for_keys=False); res.append('OK')\n"
        "    except paramiko.AuthenticationException: res.append('DENIED')\n"
        "    finally: c.close()\n"
        "print(' '.join(res))\n")
    got = dc("--profile", "sim", "run", "--rm", "--entrypoint", "python", "simulator", "-c", probe).strip().splitlines()[-1]
    record("12 Cowrie accepts only the fixed fake credentials", got == "OK OK DENIED DENIED DENIED DENIED", f"({got})")

    # 13. fail closed on placeholder / missing secrets (non-destructive: runs fail before connecting)
    bad_env = ROOT / ".env.placeholder-test"
    bad_env.write_text((ROOT / ".env").read_text().replace(
        f"GF_ADMIN_PASSWORD={env['GF_ADMIN_PASSWORD']}", "GF_ADMIN_PASSWORD=change-me-grafana-admin"))
    try:
        r1 = subprocess.run(["docker", "compose", "--env-file", str(bad_env), "run", "--rm", "--no-deps", "migrate"],  # noqa: S603,S607
                            cwd=ROOT, capture_output=True, text=True, timeout=120)  # nosec B603 B607
        r2 = subprocess.run(["docker", "compose", "run", "--rm", "--no-deps", "-e", "HL_DB_PASSWORD=change-me-pipeline-password",  # noqa: S603,S607
                             "pipeline"], cwd=ROOT, capture_output=True, text=True, timeout=120)  # nosec B603 B607
        missing = bad_env.read_text().replace("GF_ADMIN_PASSWORD=change-me-grafana-admin", "GF_ADMIN_PASSWORD=")
        bad_env.write_text(missing)
        r3 = subprocess.run(["docker", "compose", "--env-file", str(bad_env), "config", "-q"],  # noqa: S603,S607
                            cwd=ROOT, capture_output=True, text=True, timeout=60)  # nosec B603 B607
    finally:
        bad_env.unlink(missing_ok=True)
    ok = (r1.returncode != 0 and "GF_ADMIN_PASSWORD is still the placeholder" in r1.stdout + r1.stderr
          and r2.returncode == 2 and "refusing to start" in r2.stdout + r2.stderr
          and r3.returncode != 0 and "GF_ADMIN_PASSWORD" in r3.stderr)
    record("13 placeholder/missing secrets fail closed", ok,
           f"(migrate exit={r1.returncode}, pipeline exit={r2.returncode}, compose with empty secret exit={r3.returncode})")

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed in {time.time() - t0:.0f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
