import json
from datetime import UTC, datetime, timedelta

import pytest

from honeylens.pipeline.events import BadEvent, is_simulated_ip, parse_line, parse_timestamp
from honeylens.pipeline.scoring import SessionFacts, actor_type, classify, score_session, severity_label


def line(**kw):
    base = {"eventid": "cowrie.command.input", "session": "abc123", "src_ip": "203.0.113.9",
            "timestamp": "2026-10-01T10:00:00.000000Z", "input": "uname -a"}
    base.update(kw)
    return json.dumps(base).encode()


def test_parse_command_event():
    ev = parse_line(line())
    assert ev.eventid == "cowrie.command.input" and ev.fields["command"] == "uname -a"
    assert ev.ts == datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    assert ev.is_simulated  # RFC 5737 IP


@pytest.mark.parametrize("bad", [
    b"", b"not json", b"[1,2]", line(eventid=5), line(eventid="BAD EVENT!"), line(session="x" * 200),
    line(session="a;drop"), line(timestamp="yesterday"), line(timestamp="1800-01-01T00:00:00Z"),
])
def test_malformed_rejected(bad):
    with pytest.raises(BadEvent):
        parse_line(bad)


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity", b"1e999"])
def test_non_finite_json_numbers_are_rejected(number):
    prefix = b'{"eventid":"cowrie.command.input","session":"abc123","timestamp":"2026-10-01T10:00:00Z","input":"x","extra":'
    with pytest.raises(BadEvent):
        parse_line(prefix + number + b"}")


def test_hostile_fields_are_sanitized():
    ev = parse_line(line(input="\x1b[2Jrm -rf /\x00" + "A" * 9000, src_ip="not-an-ip"))
    assert "\x1b" not in ev.fields["command"] and "\x00" not in ev.fields["command"]
    assert len(ev.fields["command"]) <= 4096
    assert ev.src_ip is None


def test_login_and_download_fields():
    ev = parse_line(line(eventid="cowrie.login.failed", username="root", password="<b>x</b>"))
    assert ev.fields == {"username": "root", "password": "<b>x</b>", "success": False}
    ev = parse_line(line(eventid="cowrie.session.file_download", url="http://payload.invalid/a", shasum="z" * 64))
    assert ev.fields["url_host"] == "payload.invalid" and ev.fields["shasum"] == ""


def test_simulated_detection():
    assert is_simulated_ip("172.18.0.5", True)
    assert not is_simulated_ip("172.18.0.5", False)
    assert not is_simulated_ip("8.8.8.8", True)
    assert parse_line(line(src_ip="8.8.8.8", honeylens_simulated=True)).is_simulated


def test_timestamp_naive_is_utc():
    assert parse_timestamp("2026-10-01T10:00:00").tzinfo is not None


def _ts(seconds):
    base = datetime(2026, 10, 1, tzinfo=UTC)
    return [base + timedelta(seconds=s) for s in seconds]


def test_bot_vs_human():
    login = datetime(2026, 10, 1, tzinfo=UTC)
    bot = SessionFacts(login_success=True, login_success_ts=login, command_ts=_ts([0.5, 0.8, 1.1, 1.5]))
    assert actor_type(bot)[0] == "bot"
    human = SessionFacts(login_success=True, login_success_ts=login, command_ts=_ts([5, 9, 20, 23]))
    assert actor_type(human)[0] == "human"
    assert actor_type(SessionFacts(command_ts=_ts([1, 2])))[0] == "unknown"


def test_classes():
    assert classify(SessionFacts()) == "scanner"
    assert classify(SessionFacts(login_failures=12)) == "brute-forcer"
    assert classify(SessionFacts(login_success=True, command_ts=_ts([1]))) == "intruder"
    assert classify(SessionFacts(downloads=1)) == "malware-dropper"
    assert classify(SessionFacts(techniques={"T1496.001", "T1105"})) == "cryptominer-like"
    assert classify(SessionFacts(techniques={"T1497.001"}, command_ts=_ts([1, 2]))) == "honeypot-prober"


def test_score_is_explained_and_bounded():
    f = SessionFacts(login_success=True, login_failures=30, command_ts=_ts(range(20)), downloads=2,
                     techniques={"T1496.001", "T1105", "T1485"}, high_conf_techniques={"T1496.001", "T1105"},
                     tactics={"impact", "persistence", "defense-impairment", "command-and-control", "discovery"})
    r = score_session(f)
    assert r.severity == 100 and r.label == "critical"
    assert sum(x["points"] for x in r.reasons) >= 100
    empty = score_session(SessionFacts())
    assert empty.severity == 0 and empty.reasons == [] and empty.label == "low"
    assert severity_label(25) == "medium" and severity_label(50) == "high"
