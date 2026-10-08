#!/usr/bin/env python3
"""Safety check: is the laptop stack private?

Static mode (default) reads ``docker compose config --format json`` (the fully
merged, final configuration) into memory and FAILS if the rules below are broken. That
output contains resolved secrets, so it is parsed in memory only and NEVER printed or
logged; only service names and ports are printed. Plain validation uses
``docker compose config -q``. The rules:

* any published port binds to something other than 127.0.0.1,
* anything other than Cowrie 2222 and Grafana 3000 is published,
* PostgreSQL publishes a port,
* a service uses host networking, privileged mode, or mounts the Docker socket,
* the obsolete top-level ``version:`` key is present,
* a service publishes a port but is attached ONLY to ``internal: true``
  networks (Docker then silently skips the port, so it never binds).

``--live`` additionally inspects RUNNING containers with ``docker ps`` so the
real bindings are checked too, and FAILS if Cowrie (2222) or Grafana (3000) has
no published port at all.

Usage:  python scripts/check_ports.py [--live] [-f docker-compose.yml]
Exit code 0 = safe, 1 = problem found.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
from pathlib import Path

ALLOWED = {("cowrie", 2222), ("grafana", 3000)}
# Services whose port must really be published when the stack runs (--live).
EXPECTED_LIVE = {"cowrie": 2222, "grafana": 3000}


def compose_config(files: list[str], env_file: str | None) -> dict:
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", f]
    if env_file:
        cmd += ["--env-file", env_file]
    cmd += ["config", "--format", "json"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True)  # noqa: S603  # nosec B603
    return json.loads(out.stdout)


def check_static(cfg: dict, raw_files: list[str], allowed: set[tuple[str, int]], require_loopback: bool) -> list[str]:
    problems: list[str] = []
    for f in raw_files:
        for line in Path(f).read_text(encoding="utf-8").splitlines():
            if line.startswith("version:"):
                problems.append(f"{f}: obsolete top-level 'version:' key")
    networks = cfg.get("networks", {}) or {}
    for name, svc in cfg.get("services", {}).items():
        attached = list(svc.get("networks") or [])
        if svc.get("ports") and attached and all((networks.get(n) or {}).get("internal") for n in attached):
            problems.append(f"{name}: publishes ports but is only on internal networks (Docker will not bind them)")
        if svc.get("network_mode") == "host":
            problems.append(f"{name}: network_mode host is forbidden")
        if svc.get("privileged"):
            problems.append(f"{name}: privileged is forbidden")
        for vol in svc.get("volumes", []) or []:
            src = str(vol.get("source", ""))
            if "docker.sock" in src or "docker.sock" in str(vol.get("target", "")):
                problems.append(f"{name}: Docker socket mount is forbidden")
        for port in svc.get("ports", []) or []:
            host_ip = port.get("host_ip", "")
            target = int(port.get("target"))
            if name == "postgres":
                problems.append("postgres: must not publish any port")
            if (name, target) not in allowed:
                problems.append(f"{name}: port {target} is not on the allow-list {sorted(allowed)}")
            if require_loopback and host_ip != "127.0.0.1":
                problems.append(f"{name}: port {target} bound to '{host_ip or '0.0.0.0'}' instead of 127.0.0.1")  # noqa: S104  # nosec B104
    return problems


def check_live(cloud: bool = False) -> list[str]:
    out = subprocess.run(  # noqa: S603  # nosec B603 B607
        ["docker", "ps", "--filter", "label=com.docker.compose.project=honeylens", "--format", "{{.Names}}\t{{.Ports}}"],  # noqa: S607
        check=True, capture_output=True, text=True,
    ).stdout
    problems = []
    published: set[str] = set()
    for line in out.splitlines():
        name, _, ports = line.partition("\t")
        for mapping in filter(None, (p.strip() for p in ports.split(","))):
            if "->" in mapping:
                published.add(f"{name}|{mapping.split('->', 1)[1]}")
            if "->" in mapping and not mapping.startswith("127.0.0.1:") and not (cloud and "-cowrie-" in name):
                problems.append(f"LIVE {name}: {mapping} is not bound to 127.0.0.1")
        print(f"live  {name:28} {ports or '(no published ports)'}")
    for svc, port in EXPECTED_LIVE.items():
        if not any(f"-{svc}-" in p.split("|")[0] and p.split("|")[1].startswith(f"{port}/") for p in published):
            problems.append(f"LIVE {svc}: port {port} is not published (is the container only on internal networks?)")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-f", "--file", action="append", help="compose file(s)")
    ap.add_argument("--env-file", default=None)
    ap.add_argument("--live", action="store_true", help="also check running containers")
    ap.add_argument("--cloud", action="store_true", help="cloud mode: Cowrie may publish publicly, nothing else")
    args = ap.parse_args()
    files = args.file or ["docker-compose.yml"]
    cfg = compose_config(files, args.env_file)
    if args.cloud:
        problems = check_static(cfg, files, {("cowrie", 2222), ("grafana", 3000)}, require_loopback=False)
        for name, svc in cfg.get("services", {}).items():
            for port in svc.get("ports", []) or []:
                if name != "cowrie" and port.get("host_ip") != "127.0.0.1":
                    problems.append(f"{name}: only Cowrie may be public in the cloud")
    else:
        problems = check_static(cfg, files, ALLOWED, require_loopback=True)
    for name, svc in cfg.get("services", {}).items():
        ports = [f"{p.get('host_ip') or '0.0.0.0'}:{p.get('published')}->{p.get('target')}"  # noqa: S104  # nosec B104
                 for p in svc.get("ports", []) or []]
        print(f"config {name:12} {', '.join(ports) or '(no published ports)'}")
    if args.live:
        problems += check_live(args.cloud)
    if problems:
        print("\nFAIL:")
        for p in problems:
            print("  -", p)
        return 1
    print("\nPASS: only allowed ports are published" + ("" if args.cloud else ", all on 127.0.0.1"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
