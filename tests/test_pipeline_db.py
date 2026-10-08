"""Against a real PostgreSQL: ingest, replay, restart, rotation, hostile input, outage."""

import json
import os
from datetime import UTC, datetime

import psycopg
import pytest

from honeylens.config import Settings
from honeylens.pipeline.runner import Pipeline
from honeylens.simulator.synthetic import write
from tests.conftest import ROLE_PASSWORDS, _kv

pytestmark = pytest.mark.db
END = datetime(2026, 10, 5, tzinfo=UTC)


def make_pipeline(db, folder, **kw):
    kv = _kv(db["admin"])
    s = Settings(db_host=kv["host"], db_port=int(kv["port"]), db_name=db["db"], db_user="hl_pipeline",
                 db_password=ROLE_PASSWORDS["hl_pipeline"], input_glob=str(folder / "cowrie.json*"),
                 extra_input_glob=str(folder / "synthetic*.json"), mmdb_city_path="", mmdb_asn_path="",
                 batch_size=kw.pop("batch_size", 200), max_line_bytes=kw.pop("max_line_bytes", 65536), **kw)
    return Pipeline(s)


def q(db, sql, *args):
    with psycopg.connect(db["admin"]) as c:
        return c.execute(sql, args).fetchall()


def ev(sid, eventid, ts, **kw):
    d = {"eventid": eventid, "session": sid, "src_ip": "203.0.113.50", "timestamp": ts, "sensor": "t"}
    d.update(kw)
    return json.dumps(d)


def test_synthetic_end_to_end(clean_db, tmp_path):
    n = write(str(tmp_path / "synthetic-1.json"), 42, 3, END, 40)
    p = make_pipeline(clean_db, tmp_path)
    totals = p.drain()
    assert totals.inserted == n and totals.malformed == 0
    sessions = q(clean_db, "SELECT count(*), count(*) FILTER (WHERE is_simulated) FROM honeylens.sessions")[0]
    assert sessions[0] > 100 and sessions[0] == sessions[1]
    classes = {r[0] for r in q(clean_db, "SELECT DISTINCT classification FROM honeylens.sessions")}
    assert {"scanner", "brute-forcer", "intruder", "malware-dropper", "cryptominer-like"} <= classes
    assert q(clean_db, "SELECT count(*) FROM honeylens.attack_matches")[0][0] > 0
    assert q(clean_db, "SELECT count(*) FROM honeylens.session_summaries")[0][0] == sessions[0]
    assert q(clean_db, "SELECT count(*) FROM honeylens.sessions WHERE geo_source='demo'")[0][0] == sessions[0]
    assert q(clean_db, "SELECT count(*) FROM honeylens.pipeline_stats")[0][0] >= 1
    assert q(clean_db, "SELECT count(*) FROM honeylens.v_unmapped_commands")[0][0] > 0
    # score reasons are stored and add up
    for sev, reasons in q(clean_db, "SELECT severity, score_reasons FROM honeylens.sessions WHERE severity > 0 LIMIT 20"):
        assert sev == min(100, sum(r["points"] for r in reasons))


def test_replay_creates_no_duplicates_and_restart_resumes(clean_db, tmp_path):
    write(str(tmp_path / "synthetic-1.json"), 7, 1, END, 30)
    make_pipeline(clean_db, tmp_path).drain()
    before = q(clean_db, "SELECT count(*) FROM honeylens.raw_events")[0][0]
    # restart: offsets loaded from DB, nothing re-read
    t = make_pipeline(clean_db, tmp_path).drain()
    assert t.lines == 0
    # replay: same content in a NEW file (new inode) is fully re-read but deduplicated
    os.replace(tmp_path / "synthetic-1.json", tmp_path / "synthetic-copy.json")
    (tmp_path / "synthetic-1.json").write_bytes((tmp_path / "synthetic-copy.json").read_bytes())
    t = make_pipeline(clean_db, tmp_path).drain()
    assert t.inserted == 0 and t.duplicates == before
    assert q(clean_db, "SELECT count(*) FROM honeylens.raw_events")[0][0] == before


def test_rotation_malformed_oversized_hostile(clean_db, tmp_path):
    log = tmp_path / "cowrie.json"
    s = "aaa111"
    lines = [
        ev(s, "cowrie.session.connect", "2026-10-04T10:00:00Z", src_port=5555, dst_port=22, protocol="ssh"),
        ev(s, "cowrie.login.success", "2026-10-04T10:00:01Z", username="root", password="x"),
        "this is not json",
        "{\"eventid\": \"cowrie.command.input\"}",
        ev(s, "cowrie.command.input", "2026-10-04T10:00:02Z", input="<script>alert('xss')</script>\x1b[31m; uname -a"),
        ev(s, "cowrie.command.input", "2026-10-04T10:00:03Z", input="'; DROP TABLE honeylens.sessions; --"),
        "Q" * 70000,
    ]
    log.write_text("\n".join(lines) + "\n")
    p = make_pipeline(clean_db, tmp_path)
    p.drain()
    # rotate: rename + new file with the rest of the session
    os.rename(log, tmp_path / "cowrie.json.2026-10-04")
    log.write_text(ev(s, "cowrie.session.closed", "2026-10-04T10:00:09Z", duration=9.0) + "\n")
    t = p.drain()
    assert t.malformed == 2 and t.oversized == 1
    cmds = [r[0] for r in q(clean_db, "SELECT command FROM honeylens.commands ORDER BY ts")]
    assert cmds[0] == "<script>alert('xss')</script>; uname -a"   # stored as text, ANSI stripped
    assert "DROP TABLE" in cmds[1]                               # stored, not executed
    row = q(clean_db, "SELECT login_success, commands_count, duration_s, end_ts FROM honeylens.sessions WHERE session_id=%s", s)[0]
    assert row[0] is True and row[1] == 2 and row[2] == 9.0
    assert q(clean_db, "SELECT count(*) FROM honeylens.sessions")[0][0] == 1  # table still exists


def test_outage_then_recovery(clean_db, tmp_path):
    write(str(tmp_path / "synthetic-1.json"), 3, 1, END, 10)
    p = make_pipeline(clean_db, tmp_path)
    p._connect()
    # Simulate PostgreSQL going away mid-run: kill our backend connection.
    with psycopg.connect(clean_db["admin"], autocommit=True) as c:
        c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='hl_pipeline'")
    with pytest.raises(psycopg.Error):
        p.run_once()
    assert q(clean_db, "SELECT count(*) FROM honeylens.raw_events")[0][0] == 0
    p._drop()
    totals = p.drain()  # reconnects and processes the SAME lines
    assert totals.inserted > 0
    assert q(clean_db, "SELECT count(*) FROM honeylens.raw_events")[0][0] == totals.inserted


def test_unique_session_counts_consistent(clean_db, tmp_path):
    write(str(tmp_path / "synthetic-1.json"), 11, 2, END, 25)
    make_pipeline(clean_db, tmp_path, batch_size=37).drain()  # odd batch size splits sessions across batches
    bad = q(clean_db, """SELECT s.session_id FROM honeylens.sessions s
        WHERE s.commands_count <> (SELECT count(*) FROM honeylens.commands c WHERE c.session_id = s.session_id)
           OR s.login_attempts <> (SELECT count(*) FROM honeylens.login_attempts l WHERE l.session_id = s.session_id)""")
    assert bad == []


def test_loopback_healthcheck_events_ignored(clean_db, tmp_path):
    (tmp_path / "cowrie.json").write_text("\n".join([
        ev("hc0001", "cowrie.session.connect", "2026-10-04T10:00:00Z", src_ip="127.0.0.1"),
        ev("hc0001", "cowrie.session.closed", "2026-10-04T10:00:00Z", src_ip="127.0.0.1"),
        ev("real01", "cowrie.session.connect", "2026-10-04T10:00:01Z"),
    ]) + "\n")
    t = make_pipeline(clean_db, tmp_path).drain()
    assert t.ignored == 2 and t.inserted == 1
    assert q(clean_db, "SELECT sum(ignored) FROM honeylens.pipeline_stats")[0][0] == 2


def test_session_duration_grows_per_batch(clean_db, tmp_path):
    log = tmp_path / "cowrie.json"
    s = "dur0001"
    log.write_text(ev(s, "cowrie.session.connect", "2026-10-04T10:00:00Z") + "\n"
                   + ev(s, "cowrie.command.input", "2026-10-04T10:00:05Z", input="id") + "\n")
    p = make_pipeline(clean_db, tmp_path)
    p.drain()
    sql = "SELECT duration_s FROM honeylens.sessions WHERE session_id=%s"
    assert q(clean_db, sql, s)[0][0] == 5.0
    with open(log, "a") as fh:
        fh.write(ev(s, "cowrie.command.input", "2026-10-04T10:00:40Z", input="uname -a") + "\n")
    p.drain()
    assert q(clean_db, sql, s)[0][0] == 40.0  # was frozen at the first batch's span before
    with open(log, "a") as fh:
        fh.write(ev(s, "cowrie.session.closed", "2026-10-04T10:00:41Z", duration=41.5) + "\n")
    p.drain()
    assert q(clean_db, sql, s)[0][0] == 41.5


TS = "2026-10-04T10:00:00Z"


def test_lone_surrogate_does_not_stall_ingestion(clean_db, tmp_path):
    """A JSON-escaped lone surrogate used to make PostgreSQL reject the whole batch forever."""
    log = tmp_path / "cowrie.json"
    bad = ('{"eventid":"cowrie.command.input","session":"sur001","src_ip":"203.0.113.9","timestamp":"' + TS + '",'
           '"sensor":"t","input":"echo \\ud800 \\udcff end"}')
    log.write_text("\n".join([bad, ev("good01", "cowrie.session.connect", TS)]) + "\n")
    t = make_pipeline(clean_db, tmp_path).drain()
    assert t.inserted == 2 and t.malformed == 0
    assert q(clean_db, "SELECT command FROM honeylens.commands")[0][0] == "echo   end"
    assert q(clean_db, "SELECT byte_offset FROM honeylens.ingest_offsets")[0][0] == log.stat().st_size


def test_poison_line_is_quarantined_and_batch_continues(clean_db, tmp_path, monkeypatch):
    """Even if a value still reaches PostgreSQL unsanitised, only that line is skipped."""
    import honeylens.pipeline.events as events_mod

    monkeypatch.setattr(events_mod, "_scrub", lambda obj, depth=0: obj)  # simulate a sanitiser gap
    log = tmp_path / "cowrie.json"
    bad = ('{"eventid":"cowrie.session.connect","session":"bad001","src_ip":"203.0.113.9","timestamp":"' + TS + '",'
           '"sensor":"t","junk":"\\ud800"}')
    log.write_text("\n".join([ev("good01", "cowrie.session.connect", TS), bad,
                              ev("good02", "cowrie.session.connect", TS)]) + "\n")
    p = make_pipeline(clean_db, tmp_path)
    t = p.drain()
    assert t.inserted == 2 and t.quarantined == 1 and t.malformed == 1
    assert {r[0] for r in q(clean_db, "SELECT session_id FROM honeylens.sessions")} == {"good01", "good02"}
    assert q(clean_db, "SELECT byte_offset FROM honeylens.ingest_offsets")[0][0] == log.stat().st_size
    assert q(clean_db, "SELECT sum(malformed) FROM honeylens.pipeline_stats")[0][0] == 1
    # restart: the poison line is not retried and nothing is duplicated
    t2 = make_pipeline(clean_db, tmp_path).drain()
    assert t2.lines == 0
    assert q(clean_db, "SELECT count(*) FROM honeylens.raw_events")[0][0] == 2


def test_python_error_for_one_event_is_quarantined(clean_db, tmp_path):
    (tmp_path / "cowrie.json").write_text("\n".join([
        ev("good01", "cowrie.session.connect", TS),
        ev("boom01", "cowrie.session.connect", TS, src_ip="198.51.100.66"),
    ]) + "\n")
    p = make_pipeline(clean_db, tmp_path)
    real = p.enricher.lookup

    def flaky(ip, conn=None):
        if ip == "198.51.100.66":
            raise KeyError("bug in enrichment for this IP")
        return real(ip, conn)

    p.enricher.lookup = flaky
    t = p.drain()
    assert t.inserted == 1 and t.quarantined == 1
    assert [r[0] for r in q(clean_db, "SELECT session_id FROM honeylens.sessions")] == ["good01"]


def test_parser_crash_counts_as_malformed(clean_db, tmp_path, monkeypatch):
    import honeylens.pipeline.runner as runner_mod

    def crash(data, _private):
        if b"crash" in data:
            raise RuntimeError("unexpected parser bug")
        return real_parse(data, _private)

    real_parse = runner_mod.parse_line
    monkeypatch.setattr(runner_mod, "parse_line", crash)
    (tmp_path / "cowrie.json").write_text(ev("crash1", "cowrie.session.connect", TS) + "\n"
                                          + ev("good01", "cowrie.session.connect", TS) + "\n")
    t = make_pipeline(clean_db, tmp_path).drain()
    assert t.malformed == 1 and t.inserted == 1


def test_database_errors_are_not_quarantined(clean_db, tmp_path):
    """A non-data error (here: missing privilege) must stop the batch for a retry, never skip lines."""
    (tmp_path / "cowrie.json").write_text(ev("good01", "cowrie.session.connect", TS) + "\n")
    with psycopg.connect(clean_db["admin"], autocommit=True) as c:
        c.execute("REVOKE INSERT ON honeylens.raw_events FROM hl_pipeline")
    try:
        p = make_pipeline(clean_db, tmp_path)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            p.run_once()
        assert p.totals.quarantined == 0
    finally:
        with psycopg.connect(clean_db["admin"], autocommit=True) as c:
            c.execute("GRANT INSERT ON honeylens.raw_events TO hl_pipeline")
    p._drop()
    assert make_pipeline(clean_db, tmp_path).drain().inserted == 1
