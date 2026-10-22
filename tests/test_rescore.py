"""honeylens-rescore: backfill classification/severity/matches for stored sessions."""

from datetime import UTC, datetime

import psycopg
import pytest

from honeylens.enrich.geo import Enricher
from honeylens.pipeline.rescore import main, parse_since, rescore
from honeylens.pipeline.store import ScoringConfig
from honeylens.simulator.synthetic import write
from tests.conftest import ROLE_PASSWORDS, _kv, role_dsn
from tests.real_fixtures import DROPPER, PROBE_FOLLOWUPS, PROBE_SCRIPT
from tests.test_bruteforce_db import one_guess_sessions
from tests.test_pipeline_db import END, ev, make_pipeline, q

pytestmark = pytest.mark.db
CFG = ScoringConfig(60, 20, ())
TS = "2026-10-04T09:00:00Z"
RAW_TABLES = ("raw_events", "login_attempts", "commands", "downloads")


def _real_sessions():
    ip, lines = "203.0.113.60", []
    lines += [ev("drop01", "cowrie.session.connect", TS, src_ip=ip),
              ev("drop01", "cowrie.login.success", TS, src_ip=ip, username="admin", password="admin"),
              ev("drop01", "cowrie.command.input", TS, src_ip=ip, input=DROPPER)]
    ip = "203.0.113.70"
    lines += [ev("prob01", "cowrie.session.connect", TS, src_ip=ip),
              ev("prob01", "cowrie.login.success", TS, src_ip=ip, username="root", password="root")]
    for cmd in [PROBE_SCRIPT, *PROBE_FOLLOWUPS, "uname -a", "nproc", "/bin/./uname -s -v -n -r -m"]:
        lines.append(ev("prob01", "cowrie.command.input", TS, src_ip=ip, input=cmd))
    lines += one_guess_sessions("198.51.100.77", 25)
    lines += [ev("mine01", "cowrie.session.connect", TS, src_ip="198.51.100.200"),
              ev("mine01", "cowrie.login.failed", TS, src_ip="198.51.100.200", username="root", password="x")]
    return lines


def _old_state(db):
    """Make the DB look like it was scored by the OLD code (before this fix)."""
    with psycopg.connect(db["admin"], autocommit=True) as c:
        c.execute("DELETE FROM honeylens.attack_matches WHERE rule_id IN ('HL-EXEC-008','HL-C2-007','HL-STEALTH-009',"
                  "'HL-DISC-017','HL-STEALTH-010')")
        c.execute("UPDATE honeylens.attack_matches SET confidence = 'low' WHERE rule_id = 'HL-DISC-001'")
        c.execute("UPDATE honeylens.commands SET mapped = FALSE WHERE command LIKE '%%xxxxxx%%'")
        c.execute("UPDATE honeylens.sessions SET classification = 'scanner', severity = 0, severity_label = 'low', "
                  "score_reasons = '[]' WHERE src_ip = '198.51.100.77'")
        c.execute("UPDATE honeylens.sessions SET classification = 'intruder', severity = 25 WHERE session_id = 'prob01'")
        c.execute("UPDATE honeylens.sessions SET severity = 40, severity_label = 'medium' WHERE session_id = 'drop01'")


@pytest.fixture()
def loaded(clean_db, tmp_path):
    write(str(tmp_path / "synthetic-1.json"), 11, 2, END, 20)
    (tmp_path / "cowrie.json").write_text("\n".join(_real_sessions()) + "\n")
    make_pipeline(clean_db, tmp_path).drain()
    _old_state(clean_db)
    return clean_db


def _snapshot(db):
    return {
        "sessions": q(db, "SELECT session_id, classification, severity, score_reasons::text FROM honeylens.sessions ORDER BY 1"),
        "matches": q(db, "SELECT id, event_uid, rule_id, confidence FROM honeylens.attack_matches ORDER BY id"),
        "mapped": q(db, "SELECT event_uid, mapped FROM honeylens.commands ORDER BY 1"),
        "ignored": q(db, "SELECT session_id FROM honeylens.ignored_sessions ORDER BY 1"),
        "raw": [q(db, f"SELECT count(*) FROM honeylens.{t}")[0][0] for t in RAW_TABLES],
    }


def _run(db, dry_run=False, since=None, cfg=CFG, batch_size=7):
    with psycopg.connect(role_dsn(db, "hl_pipeline"), autocommit=False) as conn:
        return rescore(conn, Enricher([]), cfg, since, batch_size, dry_run)


def _cls(db, sid):
    return q(db, "SELECT classification, severity FROM honeylens.sessions WHERE session_id = %s", sid)[0]


def test_dry_run_reports_but_writes_nothing(loaded):
    before = _snapshot(loaded)
    res = _run(loaded, dry_run=True)
    assert _snapshot(loaded) == before
    assert res.dry_run and res.changed >= 27
    assert res.transitions[("scanner", "brute-forcer")] == 25
    assert res.transitions[("intruder", "honeypot-prober")] == 1
    text = res.summary()
    assert "DRY RUN (nothing written)" in text and "scanner -> brute-forcer: 25" in text


def test_rescore_applies_then_is_idempotent(loaded):
    raw_before = _snapshot(loaded)["raw"]
    first = _run(loaded, cfg=ScoringConfig(60, 20, ()))
    assert first.changed >= 27 and first.matches_added > 0 and first.commands_remapped > 0
    cls, sev = _cls(loaded, "drop01")
    assert cls == "malware-dropper" and sev >= 60
    assert _cls(loaded, "prob01")[0] == "honeypot-prober"
    assert {r[0] for r in q(loaded, "SELECT classification FROM honeylens.sessions WHERE src_ip = '198.51.100.77'")} == {"brute-forcer"}
    assert q(loaded, "SELECT DISTINCT confidence FROM honeylens.attack_matches WHERE rule_id = 'HL-DISC-001'") == [("high",)]
    # reasons still add up after the backfill
    for sev, reasons in q(loaded, "SELECT severity, score_reasons FROM honeylens.sessions WHERE severity > 0"):
        assert sev == min(100, sum(r["points"] for r in reasons))
    after_first = _snapshot(loaded)
    assert after_first["raw"] == raw_before  # raw data untouched
    second = _run(loaded, batch_size=50)
    assert second.changed == 0 and second.matches_added == 0 and second.matches_removed == 0
    assert second.commands_remapped == 0 and second.sessions == first.sessions
    assert _snapshot(loaded) == after_first  # same rows, same ids


def test_rescore_refreshes_ignore_list_both_ways(loaded):
    mine = ScoringConfig(60, 20, __import__("honeylens.config", fromlist=["x"]).parse_networks("198.51.100.200"))
    res = _run(loaded, cfg=mine)
    assert res.ignored_added == 1
    assert q(loaded, "SELECT session_id FROM honeylens.ignored_sessions") == [("mine01",)]
    res = _run(loaded, cfg=CFG)  # IP removed from HL_IGNORE_IPS again
    assert res.ignored_removed == 1
    assert q(loaded, "SELECT count(*) FROM honeylens.ignored_sessions")[0][0] == 0
    assert q(loaded, "SELECT count(*) FROM honeylens.sessions WHERE session_id = 'mine01'")[0][0] == 1


def test_since_limits_scope(loaded):
    res = _run(loaded, since=datetime(2026, 10, 4, 9, 30, tzinfo=UTC))
    assert _cls(loaded, "drop01") == ("malware-dropper", 40)  # 09:00, before --since: untouched
    total = q(loaded, "SELECT count(*) FROM honeylens.sessions WHERE start_ts >= '2026-10-04T09:30:00Z'")[0][0]
    assert res.sessions == total


def test_parse_since():
    now = datetime(2026, 10, 23, tzinfo=UTC)
    assert parse_since("7d", now) == datetime(2026, 10, 16, tzinfo=UTC)
    assert parse_since("2026-10-01") == datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_since("2026-10-01T05:30:00+05:30") == datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_since(None) is None
    with pytest.raises(ValueError):
        parse_since("yesterday")


def test_cli_dry_run_then_apply(loaded, monkeypatch, capsys):
    kv = _kv(loaded["admin"])
    for k, v in {"HL_DB_HOST": kv["host"], "HL_DB_PORT": kv["port"], "POSTGRES_DB": loaded["db"],
                 "HL_DB_USER": "hl_pipeline", "HL_DB_PASSWORD": ROLE_PASSWORDS["hl_pipeline"],
                 "HL_MMDB_CITY": "", "HL_MMDB_ASN": "", "HL_IGNORE_IPS": "198.51.100.200"}.items():
        monkeypatch.setenv(k, v)
    before = _snapshot(loaded)
    assert main(["--dry-run", "--batch-size", "10"]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and "scanner -> brute-forcer: 25" in out and "+1 / -0" in out
    assert _snapshot(loaded) == before
    assert main([]) == 0
    assert "APPLIED" in capsys.readouterr().out
    assert q(loaded, "SELECT session_id FROM honeylens.ignored_sessions") == [("mine01",)]
    assert main(["--since", "30d"]) == 0  # relative --since; already applied, so nothing changes
    assert " 0 changed class or severity" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--batch-size", "0"])
    with pytest.raises(SystemExit):
        main(["--since", "yesterday"])


def test_summary_text_example(loaded, capsys):
    print(_run(loaded, dry_run=True).summary())
    out = capsys.readouterr().out
    assert "class                before      after" in out and "severity" in out
