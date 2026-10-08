"""The pipeline main loop: tail -> parse -> store, forever, gracefully.

Behaviour:

* polls the log files every ``HL_POLL_MS`` milliseconds,
* processes up to ``HL_BATCH_SIZE`` lines per transaction (batching = fewer
  round trips to PostgreSQL = much faster),
* if PostgreSQL is down it waits with exponential back-off (1s, 2s, 4s ...
  max 30s) and retries the SAME lines - nothing is lost or duplicated,
* if ONE line makes the batch fail for a data reason (a value PostgreSQL
  rejects, or a bug in our own code for that event) the batch is replayed
  line by line inside savepoints; the bad line is skipped, counted as
  malformed ("quarantined" in the logs) and the offsets still move forward,
  so a single poison line can never stall ingestion,
* on SIGTERM/SIGINT (``docker compose stop`` / Ctrl+C) it finishes the current
  batch, commits, and exits cleanly,
* writes a metrics row to ``pipeline_stats`` after each batch (and a heartbeat
  every 30 s when idle) and logs the same numbers as JSON,
* runs the retention function once a day.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any

import psycopg

from honeylens.config import Settings
from honeylens.enrich.geo import build_enricher
from honeylens.logutil import setup_logging
from honeylens.mitre.attack import default_rules
from honeylens.pipeline.events import BadEvent, parse_line
from honeylens.pipeline.store import BatchStats, load_offsets, recompute_all, save_offsets, write_batch
from honeylens.pipeline.tailer import Tailer
from honeylens.secretcheck import require_secret

log = logging.getLogger("honeylens.pipeline")
HEARTBEAT_S = 30.0
RETENTION_EVERY_S = 24 * 3600


@dataclass
class Totals:
    """Lifetime counters since process start."""

    lines: int = 0
    inserted: int = 0
    duplicates: int = 0
    malformed: int = 0
    oversized: int = 0
    ignored: int = 0
    quarantined: int = 0
    db_errors: int = 0
    batches: int = 0


def _heartbeat(path: str = "/tmp/heartbeat") -> None:  # noqa: S108  # nosec B108
    """Touch a file so the Docker healthcheck can see the loop is alive."""
    try:
        with open(path, "a", encoding="utf-8"):
            pass
        os.utime(path)
    except OSError:
        pass


class Pipeline:
    """Owns the tailer, the DB connection and the loop."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.tailer = Tailer([settings.input_glob, settings.extra_input_glob], settings.max_line_bytes)
        self.enricher = build_enricher(settings)
        self.totals = Totals()
        self.stop = False
        self.conn: Any = None
        self._offsets_loaded = False
        self._last_stats = 0.0
        self._last_retention = 0.0

    # ------------------------------------------------------------ connection
    def _connect(self) -> None:
        if self.conn is not None and not self.conn.closed:
            return
        self.conn = psycopg.connect(self.settings.dsn(), autocommit=False)
        if not self._offsets_loaded:
            self.tailer.load_offsets(load_offsets(self.conn))
            self.conn.commit()
            self._offsets_loaded = True
        log.info("connected to database", extra={"files_known": len(self.tailer.states)})

    def _drop(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:  # noqa: BLE001,S110  # nosec B110
            pass
        self.conn = None

    # ------------------------------------------------------------ one batch
    def run_once(self) -> int:
        """Process one batch. Returns number of lines read (0 = idle)."""
        self._connect()
        started = time.monotonic()
        result = self.tailer.read(self.settings.batch_size)
        events, source, malformed, ignored = [], {}, 0, 0
        for line in result.lines:
            try:
                ev = parse_line(line.data, self.settings.treat_private_as_simulated)
            except BadEvent:
                malformed += 1
                continue
            except Exception as exc:  # noqa: BLE001 - a parser bug must not stall ingestion
                malformed += 1
                log.warning("quarantined line", extra={"file": os.path.basename(line.path), "error": type(exc).__name__})
                continue
            if self.settings.ignore_loopback and ev.src_ip and ipaddress.ip_address(ev.src_ip).is_loopback:
                ignored += 1  # Docker healthcheck probes, not attackers
                continue
            events.append(ev)
            source[ev.event_uid] = line.path
        pending = self.tailer.pending_offsets(result)
        stats = None
        quarantined = 0
        if result.lines or result.skipped_to or pending:
            stats, quarantined = self._store(events, pending, source)
            malformed += quarantined
        now = time.time()
        batch_ms = (time.monotonic() - started) * 1000
        if stats is not None or now - self._last_stats >= HEARTBEAT_S:
            self.conn.execute(
                "INSERT INTO honeylens.pipeline_stats (lines_read, events_ingested, duplicates, malformed, oversized, "
                "sessions_updated, batch_ms, lag_bytes, files_tracked, db_errors, ignored) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (len(result.lines), stats.inserted if stats else 0, stats.duplicates if stats else 0, malformed,
                 result.oversized, stats.sessions_updated if stats else 0, round(batch_ms, 2),
                 self.tailer.lag_bytes(), len(self.tailer.states), self.totals.db_errors, ignored),
            )
            self._last_stats = now
        self.conn.commit()
        self.tailer.commit(result)  # only after the commit succeeded
        if stats is not None:
            self.totals.batches += 1
            self.totals.lines += len(result.lines)
            self.totals.inserted += stats.inserted
            self.totals.duplicates += stats.duplicates
            self.totals.malformed += malformed
            self.totals.oversized += result.oversized
            self.totals.ignored += ignored
            self.totals.quarantined += quarantined
            log.info("batch", extra={"lines": len(result.lines), "inserted": stats.inserted,
                                     "duplicates": stats.duplicates, "malformed": malformed,
                                     "quarantined": quarantined,
                                     "oversized": result.oversized, "ignored": ignored, "sessions": stats.sessions_updated,
                                     "batch_ms": round(batch_ms, 1)})
        if now - self._last_retention >= RETENTION_EVERY_S:
            self._retention()
            self._last_retention = now
        return len(result.lines) + len(result.skipped_to)

    def _store(self, events: list[Any], pending: dict[str, Any], source: dict[str, str]) -> tuple[BatchStats, int]:
        """Write the batch; on a per-row failure replay it line by line and skip the bad lines.

        Everything happens inside the caller's transaction, so events and
        offsets are still committed together (effectively-once). Connection
        problems and server-side trouble (disk full, shutdown) are re-raised
        so the main loop backs off and retries the same lines.
        """
        conn = self.conn
        conn.execute("SAVEPOINT hl_batch")
        try:
            stats = write_batch(conn, events, self.enricher, pending, source)
        except Exception as exc:
            if not self._is_poison(exc):
                raise
            conn.execute("ROLLBACK TO SAVEPOINT hl_batch")
            log.warning("batch failed on a data error, retrying line by line", extra={"error": type(exc).__name__})
        else:
            conn.execute("RELEASE SAVEPOINT hl_batch")
            return stats, 0
        stats, bad = BatchStats(), 0
        for ev in events:
            conn.execute("SAVEPOINT hl_line")
            try:
                one = write_batch(conn, [ev], self.enricher, {}, source)
            except Exception as exc:
                if not self._is_poison(exc):
                    raise
                conn.execute("ROLLBACK TO SAVEPOINT hl_line")
                bad += 1
                # Only safe metadata: never the attacker-controlled content.
                log.warning("quarantined event", extra={"event_uid": ev.event_uid, "eventid": ev.eventid,
                                                        "file": os.path.basename(source.get(ev.event_uid, "")),
                                                        "error": type(exc).__name__})
                continue
            conn.execute("RELEASE SAVEPOINT hl_line")
            stats.inserted += one.inserted
            stats.duplicates += one.duplicates
            stats.sessions_updated += one.sessions_updated
        save_offsets(conn, pending)
        conn.execute("RELEASE SAVEPOINT hl_batch")
        return stats, bad

    def _is_poison(self, exc: Exception) -> bool:
        """True when ``exc`` is about the data of a row, not about the database or connection."""
        if self.conn is None or self.conn.closed or self.conn.broken:
            return False
        if isinstance(exc, psycopg.Error):
            return isinstance(exc, psycopg.DataError | psycopg.IntegrityError | psycopg.errors.ProgramLimitExceeded)
        return True  # a bug in our own Python code for this event (ValueError, KeyError, ...)

    def _retention(self) -> None:
        if self.settings.retention_days <= 0:
            return
        rows = self.conn.execute("SELECT * FROM honeylens.apply_retention(%s)", (self.settings.retention_days,)).fetchall()
        self.conn.commit()
        log.info("retention", extra={"deleted": {r[0]: r[1] for r in rows}, "keep_days": self.settings.retention_days})

    # ------------------------------------------------------------ loops
    def run_forever(self) -> None:
        """Main loop with back-off on database errors and graceful stop."""
        backoff = 1.0
        while not self.stop:
            _heartbeat()
            try:
                n = self.run_once()
                backoff = 1.0
                if n == 0:
                    self._sleep(self.settings.poll_seconds)
            except psycopg.Error as exc:
                self.totals.db_errors += 1
                log.warning("database error, will retry", extra={"error": type(exc).__name__, "retry_in_s": backoff})
                try:
                    if self.conn is not None and not self.conn.closed:
                        self.conn.rollback()
                except psycopg.Error:
                    pass
                self._drop()
                self._sleep(backoff)
                backoff = min(backoff * 2, 30.0)
        self._drop()
        log.info("pipeline stopped", extra=vars(self.totals))

    def drain(self) -> Totals:
        """Process everything currently in the files, then return (used by tests and --once)."""
        while self.run_once() > 0:
            pass
        self.conn.commit()
        return self.totals

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stop and time.monotonic() < end:
            time.sleep(min(0.2, seconds))

    def request_stop(self, signum: int, _frame: object) -> None:
        """Signal handler: finish the current batch then exit."""
        log.info("stop requested", extra={"signal": signum})
        self.stop = True


def main(argv: list[str] | None = None) -> int:
    """Console entry point ``honeylens-pipeline``."""
    parser = argparse.ArgumentParser(prog="honeylens-pipeline", description="Ingest Cowrie JSON logs into PostgreSQL.")
    parser.add_argument("--once", action="store_true", help="process what is there now, then exit")
    parser.add_argument("--recompute", action="store_true", help="re-score all sessions (after rule changes) and exit")
    parser.add_argument("--check-rules", action="store_true", help="validate ATT&CK rules and exit")
    args = parser.parse_args(argv)
    setup_logging()
    rules = default_rules()  # validates rules; fails fast on a bad rule
    if args.check_rules:
        print(f"{len(rules)} rules OK")
        return 0
    require_secret("HL_DB_PASSWORD")  # fail closed on missing/placeholder password
    pipe = Pipeline(Settings())
    signal.signal(signal.SIGTERM, pipe.request_stop)
    signal.signal(signal.SIGINT, pipe.request_stop)
    log.info("pipeline starting", extra={"rules": len(rules), "glob": pipe.tailer.patterns,
                                         "batch_size": pipe.settings.batch_size})
    if args.recompute:
        pipe._connect()
        n = recompute_all(pipe.conn, pipe.enricher)
        pipe.conn.commit()
        print(f"recomputed {n} sessions")
        return 0
    if args.once:
        totals = pipe.drain()
        print(f"done: {vars(totals)}")
        return 0
    pipe.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
