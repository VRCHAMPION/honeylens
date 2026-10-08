"""Weekly report schedule: tested with a fake clock, so nobody waits for Monday."""
from datetime import UTC, datetime, timedelta

import pytest

from honeylens.reporting.scheduler import Scheduler, main, next_run, parse_schedule

IST_MON_0600_AS_UTC = datetime(2026, 10, 12, 0, 30, tzinfo=UTC)  # Mon 12 Oct 2026 06:00 IST


def test_default_is_monday_0600_ist():
    # Wed 7 Oct 2026 01:00 IST -> next Mon 12 Oct 06:00 IST
    now = datetime(2026, 10, 6, 19, 30, tzinfo=UTC)
    assert next_run(now) == IST_MON_0600_AS_UTC


@pytest.mark.parametrize(("now", "expected"), [
    (datetime(2026, 10, 12, 0, 29, 59, tzinfo=UTC), IST_MON_0600_AS_UTC),           # 1 s before
    (IST_MON_0600_AS_UTC, IST_MON_0600_AS_UTC + timedelta(days=7)),                  # exactly at -> next week
    (datetime(2026, 10, 11, 23, 0, tzinfo=UTC), IST_MON_0600_AS_UTC),                # Mon 04:30 IST
    (datetime(2026, 10, 11, 18, 29, tzinfo=UTC), IST_MON_0600_AS_UTC),               # Sun 23:59 IST
])
def test_boundaries(now, expected):
    assert next_run(now) == expected


def test_configurable_schedule_and_timezone():
    now = datetime(2026, 10, 7, 0, 0, tzinfo=UTC)  # Wed
    assert next_run(now, "FRI 18:15", "Asia/Kolkata") == datetime(2026, 10, 9, 12, 45, tzinfo=UTC)
    assert next_run(now, "DAILY 06:00", "UTC") == datetime(2026, 10, 7, 6, 0, tzinfo=UTC)
    assert next_run(now, "wed 00:00", "UTC") == datetime(2026, 10, 14, 0, 0, tzinfo=UTC)
    # A zone with daylight saving still lands on the local wall-clock time.
    got = next_run(datetime(2026, 3, 7, 12, 0, tzinfo=UTC), "MON 06:00", "America/New_York")
    assert got == datetime(2026, 3, 9, 10, 0, tzinfo=UTC)  # EDT (UTC-4) after the 8 Mar switch


@pytest.mark.parametrize("bad", ["", "MONDAY 06:00", "MON 6:00", "MON 24:00", "MON 06:60", "06:00", "MON"])
def test_bad_schedule_rejected(bad):
    with pytest.raises(ValueError):
        parse_schedule(bad)


def test_naive_now_rejected():
    with pytest.raises(ValueError):
        next_run(datetime(2026, 10, 7))  # noqa: DTZ001


class FakeClock:
    def __init__(self, start):
        self.now = start
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += timedelta(seconds=s)


def test_loop_runs_report_at_slot_with_ist_folder(tmp_path):
    clock = FakeClock(datetime(2026, 10, 12, 0, 25, tzinfo=UTC))  # Mon 05:55 IST
    calls = []
    s = Scheduler("MON 06:00", "Asia/Kolkata", tmp_path, lambda a: calls.append(a) or 0,
                  clock=clock, sleep=clock.sleep, heartbeat=tmp_path / "hb")
    s.loop(max_runs=2)
    assert len(calls) == 2
    assert calls[0][:2] == ["--out", str(tmp_path / "2026-10-12")]
    assert calls[0][2:4] == ["--end", "2026-10-12T00:30:00+00:00"]
    assert calls[1][1] == str(tmp_path / "2026-10-19")
    assert max(clock.slept) <= 60  # heartbeat refreshed at least once a minute
    assert (tmp_path / "hb").exists()
    assert [c for _, c in s.runs] == [0, 0]


def test_failure_does_not_kill_scheduler(tmp_path):
    clock = FakeClock(datetime(2026, 10, 12, 0, 29, tzinfo=UTC))

    def boom(_):
        raise RuntimeError("database down")

    s = Scheduler("MON 06:00", "Asia/Kolkata", tmp_path, boom, clock=clock, sleep=clock.sleep, heartbeat=tmp_path / "hb")
    s.loop(max_runs=2)
    assert [c for _, c in s.runs] == [1, 1]


def test_stop_flag_ends_loop(tmp_path):
    clock = FakeClock(datetime(2026, 10, 7, tzinfo=UTC))
    s = Scheduler("MON 06:00", "Asia/Kolkata", tmp_path, lambda a: 0, clock=clock, heartbeat=tmp_path / "hb")
    s.sleep = lambda _x: setattr(s, "stop", True)
    s.loop()
    assert s.runs == []


def test_cli_print_next_and_bad_schedule(capsys):
    assert main(["--print-next", "--schedule", "MON 06:00"]) == 0
    assert "Asia/Kolkata" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--print-next", "--schedule", "someday"])


def test_cli_refuses_placeholder_password(monkeypatch, tmp_path):
    monkeypatch.setenv("HL_DB_PASSWORD", "change-me-report-password")
    with pytest.raises(SystemExit) as e:
        main(["--out", str(tmp_path)])
    assert e.value.code == 2


@pytest.mark.parametrize(("raw", "expected"), [("true", True), ("1", True), ("YES", True), ("on", True),
                                               ("false", False), ("0", False), ("", False)])
def test_mask_ips_env_accepts_common_true_values(monkeypatch, tmp_path, raw, expected):
    import honeylens.reporting.scheduler as sched_mod

    seen = {}

    class FakeScheduler:
        def __init__(self, *args, extra_args=None, **kw):
            seen["extra"] = extra_args

        def run_once(self, now):
            return 0

    monkeypatch.setattr(sched_mod, "Scheduler", FakeScheduler)
    import secrets

    monkeypatch.setenv("HL_DB_PASSWORD", secrets.token_urlsafe(18))  # random, never a real secret
    monkeypatch.setenv("HL_REPORT_MASK_IPS", raw)
    assert sched_mod.main(["--out", str(tmp_path), "--run-now"]) == 0
    assert (seen["extra"] == ["--mask-ips"]) is expected
