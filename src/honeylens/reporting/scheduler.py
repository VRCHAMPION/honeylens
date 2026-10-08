"""``honeylens-report-scheduler``: run the weekly report on a fixed schedule.

Why not cron or a job queue: one small Python loop is enough for one report a
week, needs no extra packages or root, and runs in the same read-only image as
everything else. It simply calls the existing ``honeylens-report`` code.

Schedule format (``HL_REPORT_SCHEDULE``): ``"<DAY> HH:MM"``, for example
``"MON 06:00"`` (the default). Days: MON TUE WED THU FRI SAT SUN, or ``DAILY``.
The clock is ``HL_REPORT_TZ`` (default ``Asia/Kolkata``, IST).

Each run writes into ``<out>/<YYYY-MM-DD>/`` (the IST date of the run) so old
reports are kept, and touches ``/tmp/heartbeat`` every loop for the Docker
healthcheck. ``next_run()`` is a pure function, so tests check Monday 06:00
without waiting for Monday.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import re
import signal
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from honeylens.logutil import setup_logging

log = logging.getLogger("honeylens.report.scheduler")

DAYS = {"MON": 0, "TUE": 1, "WED": 2, "THU": 3, "FRI": 4, "SAT": 5, "SUN": 6}
DEFAULT_SCHEDULE = "MON 06:00"
DEFAULT_TZ = "Asia/Kolkata"
_SPEC = re.compile(r"^\s*(MON|TUE|WED|THU|FRI|SAT|SUN|DAILY)\s+([01]\d|2[0-3]):([0-5]\d)\s*$", re.IGNORECASE)


def parse_schedule(spec: str) -> tuple[int | None, int, int]:
    """``"MON 06:00"`` -> ``(0, 6, 0)``; ``"DAILY 23:30"`` -> ``(None, 23, 30)``."""
    m = _SPEC.match(spec or "")
    if not m:
        raise ValueError(f"bad HL_REPORT_SCHEDULE {spec!r}; use e.g. 'MON 06:00' or 'DAILY 06:00'")
    day = m.group(1).upper()
    return (None if day == "DAILY" else DAYS[day]), int(m.group(2)), int(m.group(3))


def next_run(now: datetime, spec: str = DEFAULT_SCHEDULE, tz: str = DEFAULT_TZ) -> datetime:
    """First scheduled moment STRICTLY after ``now`` (returned in UTC)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    weekday, hour, minute = parse_schedule(spec)
    local = now.astimezone(ZoneInfo(tz))
    cand = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    for _ in range(8):
        if cand > local and (weekday is None or cand.weekday() == weekday):
            return cand.astimezone(UTC)
        cand = (cand + timedelta(days=1)).replace(hour=hour, minute=minute)
    raise AssertionError("unreachable: a weekday always occurs within 8 days")  # pragma: no cover


class Scheduler:
    """Sleep until the next slot, run the report, repeat. Clock and sleep are injectable for tests."""

    def __init__(self, spec: str, tz: str, out: Path, run_report: Callable[[list[str]], int],
                 clock: Callable[[], datetime] | None = None, sleep: Callable[[float], None] = time.sleep,
                 heartbeat: Path = Path("/tmp/heartbeat"),  # noqa: S108  # nosec B108 - private 16 MB tmpfs per container
                 extra_args: list[str] | None = None) -> None:
        parse_schedule(spec)  # validate early
        ZoneInfo(tz)
        self.spec, self.tz, self.out = spec, tz, out
        self.run_report = run_report
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sleep = sleep
        self.heartbeat = heartbeat
        self.extra_args = extra_args or []
        self.stop = False
        self.runs: list[tuple[datetime, int]] = []

    def _beat(self) -> None:
        with contextlib.suppress(OSError):  # heartbeat is best effort
            self.heartbeat.touch()

    def run_once(self, when: datetime) -> int:
        """Generate one report into ``out/<IST date>``. A failure is logged, never fatal."""
        folder = self.out / when.astimezone(ZoneInfo(self.tz)).strftime("%Y-%m-%d")
        args = ["--out", str(folder), "--end", when.astimezone(UTC).isoformat(), *self.extra_args]
        try:
            code = self.run_report(args)
        except SystemExit as e:  # argparse or secret check
            code = int(e.code or 1) if not isinstance(e.code, str) else 1
        except Exception:  # noqa: BLE001 - DB down etc.; try again next slot
            log.exception("scheduled report failed")
            code = 1
        self.runs.append((when, code))
        log.info("scheduled report finished", extra={"folder": str(folder), "exit_code": code})
        return code

    def loop(self, max_runs: int | None = None) -> None:
        """Main loop. Sleeps in <= 60 s steps so the heartbeat stays fresh and SIGTERM is quick."""
        target = next_run(self.clock(), self.spec, self.tz)
        log.info("report scheduler started", extra={"schedule": self.spec, "tz": self.tz, "next_run_utc": target.isoformat()})
        while not self.stop:
            self._beat()
            now = self.clock()
            if now >= target:
                self.run_once(target)
                if max_runs is not None and len(self.runs) >= max_runs:
                    return
                target = next_run(now, self.spec, self.tz)
                log.info("next report", extra={"next_run_utc": target.isoformat()})
                continue
            self.sleep(min(60.0, (target - now).total_seconds()))


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``report-scheduler`` Compose service."""
    from honeylens.reporting.cli import main as report_main
    from honeylens.secretcheck import require_secret

    p = argparse.ArgumentParser(prog="honeylens-report-scheduler", description="Run honeylens-report on a schedule.")
    p.add_argument("--out", default=os.environ.get("HL_REPORT_OUT", "/out"))
    p.add_argument("--schedule", default=os.environ.get("HL_REPORT_SCHEDULE", DEFAULT_SCHEDULE))
    p.add_argument("--tz", default=os.environ.get("HL_REPORT_TZ", DEFAULT_TZ))
    p.add_argument("--print-next", action="store_true", help="print the next run time and exit")
    p.add_argument("--run-now", action="store_true", help="generate one report now (same code path) and exit")
    p.add_argument("--mask-ips", action="store_true", default=os.environ.get("HL_REPORT_MASK_IPS", "").lower() == "true")
    args = p.parse_args(argv)
    setup_logging()
    try:
        nxt = next_run(datetime.now(UTC), args.schedule, args.tz)
    except (ValueError, KeyError) as e:
        p.error(str(e))
    if args.print_next:
        print(f"next report: {nxt.astimezone(ZoneInfo(args.tz)).isoformat()} ({args.tz})")
        return 0
    require_secret("HL_DB_PASSWORD")
    sched = Scheduler(args.schedule, args.tz, Path(args.out), report_main,
                      extra_args=["--mask-ips"] if args.mask_ips else [])
    if args.run_now:
        return sched.run_once(datetime.now(UTC))

    def _stop(*_: object) -> None:
        sched.stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    sched.loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
