#!/usr/bin/env python3
"""Measure pipeline throughput against a PostgreSQL server.

    HL_TEST_PG="host=127.0.0.1 port=5432 user=postgres password=..." python scripts/perf_test.py --days 7 --per-day 1000

Creates a throw-away database, generates deterministic synthetic events, ingests them with the
real Pipeline class, prints events/second, then drops the database. Numbers depend heavily on the
machine; always report them together with the hardware they were measured on.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from honeylens.config import Settings  # noqa: E402
from honeylens.migrate import apply_migrations, ensure_roles  # noqa: E402
from honeylens.pipeline.runner import Pipeline  # noqa: E402
from honeylens.simulator.synthetic import write  # noqa: E402

PW = {"hl_pipeline": "perf-pipeline-pw-1", "hl_grafana": "perf-grafana-pw-12", "hl_report": "perf-report-pw-123"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--per-day", type=int, default=1000)
    ap.add_argument("--batch", type=int, default=500)
    args = ap.parse_args()
    base = os.environ["HL_TEST_PG"]
    kv = dict(p.split("=", 1) for p in base.split())
    db = f"hl_perf_{uuid.uuid4().hex[:6]}"
    with psycopg.connect(base + " dbname=postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{db}"')
    try:
        with psycopg.connect(base + f" dbname={db}", autocommit=True) as c:
            ensure_roles(c, PW)
            apply_migrations(c, ROOT / "db" / "migrations")
        with tempfile.TemporaryDirectory() as tmp:
            n = write(f"{tmp}/synthetic-perf.json", 99, args.days, datetime(2026, 10, 1, tzinfo=UTC), args.per_day)
            size = Path(f"{tmp}/synthetic-perf.json").stat().st_size
            s = Settings(db_host=kv["host"], db_port=int(kv["port"]), db_name=db, db_user="hl_pipeline",
                         db_password=PW["hl_pipeline"], input_glob="", extra_input_glob=f"{tmp}/*.json",
                         batch_size=args.batch, mmdb_city_path="", mmdb_asn_path="")
            p = Pipeline(s)
            t = time.perf_counter()
            totals = p.drain()
            secs = time.perf_counter() - t
        with psycopg.connect(base + f" dbname={db}") as c:
            sessions = c.execute("SELECT count(*) FROM honeylens.sessions").fetchone()[0]
            t = time.perf_counter()
            c.execute("SELECT count(*), avg(severity) FROM honeylens.sessions WHERE start_ts > now() - interval '30 days'").fetchone()
            q_ms = (time.perf_counter() - t) * 1000
        print(f"machine: {platform.machine()} {os.cpu_count()} CPUs, Python {platform.python_version()}")
        print(f"events={n} file_bytes={size} sessions={sessions} batch={args.batch}")
        print(f"ingested={totals.inserted} in {secs:.1f}s -> {totals.inserted / secs:.0f} events/s, "
              f"{sessions / secs:.0f} sessions/s")
        print(f"sample dashboard-style query: {q_ms:.1f} ms")
    finally:
        with psycopg.connect(base + " dbname=postgres", autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
    return 0


if __name__ == "__main__":
    sys.exit(main())
