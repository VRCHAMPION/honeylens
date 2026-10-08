"""Shared test fixtures.

Database tests need a PostgreSQL server. Set HL_TEST_PG (libpq keywords for a
SUPERUSER connection, without dbname), for example:

    HL_TEST_PG="host=127.0.0.1 port=55432 user=hl_admin password=testadminpw"

Each test session creates a fresh throw-away database and drops it at the end.
Without HL_TEST_PG those tests are SKIPPED (and reported as skipped, not passed).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROLE_PASSWORDS = {
    "hl_pipeline": "tPl9-Xq2r-pipe-4kWz",
    "hl_grafana": "gF7m-Lw3e-graf-8nQs",
    "hl_report": "rP4v-Hd8k-rept-2jYc",
}


def _kv(dsn: str) -> dict[str, str]:
    return dict(p.split("=", 1) for p in dsn.split())


@pytest.fixture(scope="session")
def pg_admin_dsn():
    raw = os.environ.get("HL_TEST_PG")
    if not raw:
        pytest.skip("HL_TEST_PG not set: database tests skipped")
    import psycopg

    dbname = f"hl_test_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(raw + " dbname=postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{dbname}"')
    yield raw + f" dbname={dbname}", dbname
    with psycopg.connect(raw + " dbname=postgres", autocommit=True) as c:
        c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()", (dbname,))
        c.execute(f'DROP DATABASE IF EXISTS "{dbname}"')


@pytest.fixture(scope="session")
def migrated(pg_admin_dsn):
    """Database with roles and all migrations applied."""
    import psycopg

    from honeylens.migrate import apply_migrations, ensure_roles

    dsn, dbname = pg_admin_dsn
    with psycopg.connect(dsn, autocommit=True) as conn:
        ensure_roles(conn, ROLE_PASSWORDS)
        applied = apply_migrations(conn, ROOT / "db" / "migrations")
    return {"admin": dsn, "db": dbname, "applied": applied}


def role_dsn(migrated: dict, role: str) -> str:
    kv = _kv(migrated["admin"])
    return (f"host={kv['host']} port={kv['port']} dbname={migrated['db']} "
            f"user={role} password={ROLE_PASSWORDS[role]}")


@pytest.fixture()
def clean_db(migrated):
    """Empty all data tables before a test."""
    import psycopg

    with psycopg.connect(migrated["admin"], autocommit=True) as c:
        c.execute("TRUNCATE honeylens.raw_events, honeylens.sessions, honeylens.login_attempts, honeylens.commands, "
                  "honeylens.downloads, honeylens.enrichment_cache, honeylens.attack_matches, honeylens.session_summaries, "
                  "honeylens.pipeline_stats, honeylens.ingest_offsets RESTART IDENTITY CASCADE")
    return migrated
