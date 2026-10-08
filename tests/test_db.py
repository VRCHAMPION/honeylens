"""Migrations are idempotent and roles have exactly the right permissions."""

import psycopg
import pytest

from tests.conftest import ROLE_PASSWORDS, ROOT, role_dsn

pytestmark = pytest.mark.db

TABLES = {"raw_events", "sessions", "login_attempts", "commands", "downloads", "enrichment_cache",
          "attack_matches", "session_summaries", "pipeline_stats", "ingest_offsets", "schema_migrations"}


def test_first_run_applied_everything(migrated):
    assert migrated["applied"] == ["001_schema.sql", "002_views_retention.sql", "003_grants.sql", "004_pipeline_ignored.sql"]
    with psycopg.connect(migrated["admin"]) as c:
        names = {r[0] for r in c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='honeylens'")}
    assert names >= TABLES
    assert {"v_unmapped_commands", "v_credentials", "v_session_overview", "v_attack_daily"} <= names


def test_second_and_third_run_are_noops(migrated):
    from honeylens.migrate import apply_migrations, ensure_roles
    for _ in range(2):
        with psycopg.connect(migrated["admin"], autocommit=True) as c:
            ensure_roles(c, ROLE_PASSWORDS)
            assert apply_migrations(c, ROOT / "db" / "migrations") == []


def test_raw_sql_files_are_idempotent_on_their_own(migrated):
    # Even re-executing the SQL directly (bypassing the tracker) must not fail.
    with psycopg.connect(migrated["admin"], autocommit=True) as c:
        for f in sorted((ROOT / "db" / "migrations").glob("*.sql")):
            c.execute(f.read_text().encode())


def test_changed_migration_is_detected(migrated, tmp_path):
    from honeylens.migrate import apply_migrations
    for f in (ROOT / "db" / "migrations").glob("*.sql"):
        (tmp_path / f.name).write_text(f.read_text())
    (tmp_path / "001_schema.sql").write_text((tmp_path / "001_schema.sql").read_text() + "\n-- edited\n")
    with psycopg.connect(migrated["admin"], autocommit=True) as c, pytest.raises(SystemExit, match="changed"):
        apply_migrations(c, tmp_path)


def test_is_simulated_everywhere(migrated):
    with psycopg.connect(migrated["admin"]) as c:
        tables = {r[0] for r in c.execute("SELECT table_name FROM information_schema.columns WHERE "
                                          "table_schema='honeylens' AND column_name='is_simulated'")}
    assert {"raw_events", "sessions", "login_attempts", "commands", "downloads", "attack_matches"} <= tables


def test_pipeline_role_can_write(clean_db):
    with psycopg.connect(role_dsn(clean_db, "hl_pipeline")) as c:
        c.execute("INSERT INTO honeylens.pipeline_stats (lines_read) VALUES (1)")
        c.execute("DELETE FROM honeylens.pipeline_stats")
        c.execute("SELECT * FROM honeylens.apply_retention(30)").fetchall()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("DROP TABLE honeylens.sessions")


@pytest.mark.parametrize("role", ["hl_grafana", "hl_report"])
def test_read_only_roles(clean_db, role):
    with psycopg.connect(role_dsn(clean_db, role)) as c:
        assert c.execute("SELECT count(*) FROM honeylens.sessions").fetchone()[0] == 0
        c.execute("SELECT count(*) FROM honeylens.v_session_overview").fetchone()
    for sql in ("INSERT INTO honeylens.pipeline_stats (lines_read) VALUES (1)",
                "DELETE FROM honeylens.sessions",
                "UPDATE honeylens.sessions SET severity = 0",
                "CREATE TABLE honeylens.evil (x int)",
                "CREATE TABLE public.evil (x int)",
                "SELECT * FROM honeylens.apply_retention(1)"):
        with psycopg.connect(role_dsn(clean_db, role)) as c, pytest.raises(psycopg.Error):
            c.execute(sql)


def test_roles_are_not_superusers(migrated):
    with psycopg.connect(migrated["admin"]) as c:
        rows = c.execute("SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname LIKE 'hl\\_%%'"
                         " AND rolname <> 'hl_admin'").fetchall()
    assert len(rows) == 3 and all(not any(r[1:]) for r in rows)


def test_weak_role_password_refused(pg_admin_dsn):
    from honeylens.migrate import ensure_roles
    with psycopg.connect(pg_admin_dsn[0], autocommit=True) as c, pytest.raises(SystemExit):
        ensure_roles(c, {"hl_pipeline": "short", "hl_grafana": "x" * 12, "hl_report": "x" * 12})


def test_retention_deletes_old_rows_only(clean_db):
    with psycopg.connect(clean_db["admin"], autocommit=True) as c:
        for age in (5, 200):
            c.execute("INSERT INTO honeylens.raw_events (event_uid, eventid, session_id, ts, payload) "
                      "VALUES (%s, 'x', 's', now() - make_interval(days => %s), '{}')", (f"u{age}", age))
        out = dict(c.execute("SELECT * FROM honeylens.apply_retention(90)").fetchall())
        assert out["raw_events"] == 1
        assert c.execute("SELECT event_uid FROM honeylens.raw_events").fetchall() == [("u5",)]
        assert c.execute("SELECT count(*) FROM honeylens.apply_retention(0)").fetchone()[0] == 0
