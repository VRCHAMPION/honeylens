"""Per-IP time-window brute-force detection against a real PostgreSQL."""

from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from tests.test_pipeline_db import ev, make_pipeline, q

pytestmark = pytest.mark.db
BOT = "198.51.100.77"
SLOW = "198.51.100.88"


def one_guess_sessions(ip, n, start_minute=0, step_s=60, prefix="bf"):
    lines = []
    for i in range(n):
        when = datetime(2026, 10, 4, 10, tzinfo=UTC) + timedelta(seconds=start_minute * 60 + i * step_s)
        ts = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        sid = f"{prefix}{ip.split('.')[-1]}x{i:03d}"
        lines.append(ev(sid, "cowrie.session.connect", ts, src_ip=ip))
        lines.append(ev(sid, "cowrie.login.failed", ts, src_ip=ip, username="root", password=f"pw{i}"))
        lines.append(ev(sid, "cowrie.session.closed", ts, src_ip=ip))
    return lines


def classes(db, ip):
    return dict(q(db, "SELECT classification, count(*) FROM honeylens.sessions WHERE src_ip = %s GROUP BY 1", ip))


def test_one_guess_per_connection_bot_is_brute_forcer(clean_db, tmp_path):
    # 25 connections with ONE failed login each, 1 minute apart: the real-bot pattern
    lines = one_guess_sessions(BOT, 25) + one_guess_sessions(SLOW, 5, start_minute=0, step_s=600, prefix="sl")
    (tmp_path / "cowrie.json").write_text("\n".join(lines) + "\n")
    # small batches: early sessions are scored before the IP crosses the threshold,
    # so the neighbour upgrade has to fix them afterwards
    make_pipeline(clean_db, tmp_path, batch_size=9, brute_window_min=60, brute_min_failures=20).drain()
    assert classes(clean_db, BOT) == {"brute-forcer": 25}
    assert classes(clean_db, SLOW) == {"scanner": 5}
    for sev, reasons in q(clean_db, "SELECT severity, score_reasons FROM honeylens.sessions WHERE src_ip = %s", BOT):
        assert [r["rule"] for r in reasons] == ["ip_brute_force"] and sev == 5


def test_window_is_respected(clean_db, tmp_path):
    # 20 guesses spread over ~6.5 hours: never 20 inside +/-60 min
    lines = one_guess_sessions(BOT, 20, step_s=1200)
    (tmp_path / "cowrie.json").write_text("\n".join(lines) + "\n")
    make_pipeline(clean_db, tmp_path, brute_window_min=60, brute_min_failures=20).drain()
    assert classes(clean_db, BOT) == {"scanner": 20}


def test_disabled_with_zero_threshold(clean_db, tmp_path):
    (tmp_path / "cowrie.json").write_text("\n".join(one_guess_sessions(BOT, 25)) + "\n")
    make_pipeline(clean_db, tmp_path, brute_window_min=60, brute_min_failures=0).drain()
    assert classes(clean_db, BOT) == {"scanner": 25}


def test_window_query_can_use_index(migrated):
    with psycopg.connect(migrated["admin"]) as c:
        c.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in c.execute(
            "EXPLAIN SELECT count(*) FROM honeylens.login_attempts WHERE src_ip = '198.51.100.1' AND NOT success "
            "AND ts >= now() - interval '1 hour' AND ts <= now()").fetchall())
    assert "login_failed_ip_ts_idx" in plan
