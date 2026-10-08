"""Apply SQL migrations and create the three database roles.

Run: ``python -m honeylens.migrate`` (Compose runs it automatically in the
one-shot ``migrate`` service before the pipeline starts).

Idempotent by design:

* roles are created only if missing; passwords are (re)set from ``.env``,
* each ``db/migrations/NNN_*.sql`` file is recorded with its SHA-256 checksum
  and skipped next time; if someone edits an applied file we STOP with an
  error instead of guessing,
* the SQL itself uses ``IF NOT EXISTS`` / ``CREATE OR REPLACE`` as a second
  safety net.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path

import psycopg
from psycopg import sql

from honeylens.config import build_dsn
from honeylens.logutil import setup_logging
from honeylens.secretcheck import problem, require_all

log = logging.getLogger("honeylens.migrate")

ROLES = {
    "hl_pipeline": "HL_PIPELINE_DB_PASSWORD",
    "hl_grafana": "HL_GRAFANA_DB_PASSWORD",
    "hl_report": "HL_REPORT_DB_PASSWORD",
}


def find_migrations_dir() -> Path:
    """Locate db/migrations (env override, then the repo or image layout)."""
    env = os.environ.get("HL_MIGRATIONS_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in [*here.parents, Path("/app")]:
        cand = parent / "db" / "migrations"
        if cand.is_dir():
            return cand
    raise FileNotFoundError("db/migrations not found; set HL_MIGRATIONS_DIR")


def ensure_roles(conn: psycopg.Connection, passwords: dict[str, str]) -> None:
    """Create LOGIN roles if missing and set their passwords (never logged)."""
    for role, env_name in ROLES.items():
        password = passwords.get(role, "")
        why = problem(password)
        if why:
            raise SystemExit(f"{env_name} {why} (refusing to create role {role})")
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        if not exists:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
            log.info("created role", extra={"role": role})
        conn.execute(
            sql.SQL("ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        db = conn.info.dbname
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(db), sql.Identifier(role)))
    conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(conn.info.dbname)))


def apply_migrations(conn: psycopg.Connection, directory: Path) -> list[str]:
    """Apply new migration files in name order. Returns the versions applied now."""
    conn.execute("CREATE SCHEMA IF NOT EXISTS honeylens")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS honeylens.schema_migrations ("
        "version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    applied_now: list[str] = []
    for path in sorted(directory.glob("*.sql")):
        body = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(body.encode()).hexdigest()
        row = conn.execute(
            "SELECT checksum FROM honeylens.schema_migrations WHERE version = %s", (path.name,)
        ).fetchone()
        if row:
            if row[0] != checksum:
                raise SystemExit(
                    f"migration {path.name} was changed after it was applied. "
                    "Add a NEW migration file instead of editing old ones."
                )
            continue
        with conn.transaction():
            conn.execute(body.encode())  # file content is trusted repo SQL, not user input
            conn.execute(
                "INSERT INTO honeylens.schema_migrations (version, checksum) VALUES (%s, %s)",
                (path.name, checksum),
            )
        applied_now.append(path.name)
        log.info("applied migration", extra={"version": path.name})
    return applied_now


def main() -> int:
    """Entry point: connect as the database owner and migrate."""
    setup_logging()
    require_all()  # fail closed BEFORE anything connects; Grafana/pipeline wait for this job
    dsn = build_dsn(
        os.environ.get("POSTGRES_USER", "postgres"),
        os.environ.get("POSTGRES_PASSWORD", ""),
        os.environ.get("HL_DB_HOST", "localhost"),
        int(os.environ.get("HL_DB_PORT", "5432")),
        os.environ.get("POSTGRES_DB", "honeylens"),
    )
    passwords = {role: os.environ.get(env, "") for role, env in ROLES.items()}
    with psycopg.connect(dsn, autocommit=True) as conn:
        ensure_roles(conn, passwords)
        applied = apply_migrations(conn, find_migrations_dir())
    log.info("migrations complete", extra={"applied_now": applied})
    print(f"migrations complete; newly applied: {applied or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
