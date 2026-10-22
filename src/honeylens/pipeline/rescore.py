"""``honeylens-rescore`` / ``python -m honeylens.pipeline.rescore``: re-score stored sessions.

When detection rules or scoring change, sessions already in the database keep
their old class and severity. This tool brings them up to date, in batches:

1. re-match every stored command against the CURRENT rules
   (``attack_matches`` and ``commands.mapped``; stale matches are removed,
   new ones added, unchanged rows are left alone),
2. refresh the ``ignored_sessions`` list from the current ``HL_IGNORE_IPS``
   (adds and removes),
3. recount session totals and recompute classification, severity,
   ``score_reasons``, actor type and summary with the current scorer
   (including the per-IP brute-force window).

Safety:

* raw data is never deleted or changed: ``raw_events``, ``login_attempts``,
  ``commands`` (text) and ``downloads`` are read-only here; only derived
  columns and tables are rewritten,
* idempotent: a second run changes nothing,
* one transaction per batch (default 500 sessions), so it is resumable, light
  on a 1 GB VM and never holds long locks against the live pipeline. A batch
  that hits a deadlock with the pipeline is rolled back and retried,
* ``--dry-run`` does all the work inside each batch's transaction, prints the
  before/after summary and ROLLS BACK, so nothing is written.

Run it inside the pipeline container (it uses the pipeline's database role)::

    docker compose exec pipeline honeylens-rescore --dry-run
    docker compose exec pipeline honeylens-rescore
    docker compose exec pipeline honeylens-rescore --since 2026-10-01
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from honeylens.config import Settings, ip_in
from honeylens.enrich.geo import Enricher, build_enricher
from honeylens.logutil import setup_logging
from honeylens.mitre.attack import default_rules, match_command
from honeylens.pipeline.store import ScoringConfig, _recount, _score
from honeylens.secretcheck import require_secret

log = logging.getLogger("honeylens.rescore")
RETRIES = 3


@dataclass
class RescoreResult:
    """What a run changed (or would change, with ``dry_run``)."""

    sessions: int = 0
    batches: int = 0
    changed: int = 0
    dry_run: bool = False
    before_class: Counter[str] = field(default_factory=Counter)
    after_class: Counter[str] = field(default_factory=Counter)
    before_label: Counter[str] = field(default_factory=Counter)
    after_label: Counter[str] = field(default_factory=Counter)
    transitions: Counter[tuple[str, str]] = field(default_factory=Counter)
    matches_added: int = 0
    matches_removed: int = 0
    commands_remapped: int = 0
    ignored_added: int = 0
    ignored_removed: int = 0

    def summary(self) -> str:
        """Human-readable before/after report."""
        mode = "DRY RUN (nothing written)" if self.dry_run else "APPLIED"
        lines = [f"rescore {mode}: {self.sessions} sessions in {self.batches} batches, "
                 f"{self.changed} changed class or severity"]
        lines.append(f"  attack matches: +{self.matches_added} / -{self.matches_removed}; "
                     f"commands with a new mapped flag: {self.commands_remapped}")
        lines.append(f"  ignored sessions (HL_IGNORE_IPS): +{self.ignored_added} / -{self.ignored_removed}")
        classes = sorted(set(self.before_class) | set(self.after_class))
        lines.append("  class                before      after")
        for c in classes:
            lines.append(f"  {c:<18} {self.before_class[c]:>8} {self.after_class[c]:>10}")
        labels = [x for x in ("low", "medium", "high", "critical", "none")
                  if self.before_label[x] or self.after_label[x]]
        lines.append("  severity             before      after")
        for x in labels:
            lines.append(f"  {x:<18} {self.before_label[x]:>8} {self.after_label[x]:>10}")
        moved = [(k, n) for k, n in self.transitions.most_common() if k[0] != k[1]]
        if moved:
            lines.append("  class changes:")
            for (a, b), n in moved:
                lines.append(f"    {a} -> {b}: {n}")
        return "\n".join(lines)


def _state(conn: Any, sids: list[str]) -> dict[str, tuple[str, int | None, str]]:
    rows = conn.execute(
        "SELECT session_id, coalesce(classification, 'unknown'), severity, coalesce(severity_label, 'none') "
        "FROM honeylens.sessions WHERE session_id = ANY(%s)", (sids,)).fetchall()
    return {r[0]: (r[1], r[2], r[3]) for r in rows}


def _rematch(conn: Any, sids: list[str], res: RescoreResult) -> None:
    """Bring attack_matches and commands.mapped in line with the current rules."""
    rules = default_rules()
    cmds = conn.execute(
        "SELECT event_uid, session_id, ts, command, mapped, is_simulated FROM honeylens.commands "
        "WHERE session_id = ANY(%s)", (sids,)).fetchall()
    want: list[tuple[Any, ...]] = []
    keys: list[str] = []
    remap: list[tuple[bool, str]] = []
    for uid, sid, ts, command, mapped, sim in cmds:
        found = match_command(command, rules) if command else []
        for m in found:
            want.append((uid, sid, ts, m.rule_id, m.technique, m.technique_name, m.tactic, m.confidence, sim))
            keys.append(f"{uid}|{m.rule_id}")
        if bool(found) != mapped:
            remap.append((bool(found), uid))
    removed = conn.execute(
        "DELETE FROM honeylens.attack_matches WHERE session_id = ANY(%s) AND NOT (event_uid || '|' || rule_id = ANY(%s))",
        (sids, keys))
    res.matches_removed += removed.rowcount or 0
    with conn.cursor() as cur:
        for row in want:
            cur.execute(
                "INSERT INTO honeylens.attack_matches "
                "(event_uid, session_id, ts, rule_id, technique_id, technique_name, tactic, confidence, is_simulated) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid, rule_id) DO UPDATE SET "
                "technique_id = EXCLUDED.technique_id, technique_name = EXCLUDED.technique_name, "
                "tactic = EXCLUDED.tactic, confidence = EXCLUDED.confidence "
                "WHERE (attack_matches.technique_id, attack_matches.technique_name, attack_matches.tactic, attack_matches.confidence) "
                "IS DISTINCT FROM (EXCLUDED.technique_id, EXCLUDED.technique_name, EXCLUDED.tactic, EXCLUDED.confidence) "
                "RETURNING (xmax = 0)", row)
            got = cur.fetchone()
            if got and got[0]:
                res.matches_added += 1
        if remap:
            cur.executemany("UPDATE honeylens.commands SET mapped = %s WHERE event_uid = %s", remap)
    res.commands_remapped += len(remap)


def _refresh_ignored(conn: Any, sids: list[str], cfg: ScoringConfig, res: RescoreResult) -> None:
    """Make ignored_sessions match the current HL_IGNORE_IPS for these sessions (adds AND removes)."""
    rows = conn.execute("SELECT session_id, host(src_ip) FROM honeylens.sessions WHERE session_id = ANY(%s)",
                        (sids,)).fetchall()
    ignored = [(sid, ip) for sid, ip in rows if ip_in(ip, cfg.ignore_networks)]
    keep = [sid for sid, _ in ignored]
    removed = conn.execute(
        "DELETE FROM honeylens.ignored_sessions WHERE session_id = ANY(%s) AND NOT (session_id = ANY(%s))", (sids, keep))
    res.ignored_removed += removed.rowcount or 0
    with conn.cursor() as cur:
        for sid, ip in ignored:
            cur.execute("INSERT INTO honeylens.ignored_sessions (session_id, src_ip) VALUES (%s, %s) "
                        "ON CONFLICT DO NOTHING RETURNING 1", (sid, ip))
            if cur.fetchone():
                res.ignored_added += 1


def _batch(conn: Any, sids: list[str], enricher: Enricher, cfg: ScoringConfig, res: RescoreResult) -> None:
    before = _state(conn, sids)
    _rematch(conn, sids, res)
    _refresh_ignored(conn, sids, cfg, res)
    _recount(conn, sids)
    _score(conn, sids, enricher, cfg)
    after = _state(conn, sids)
    for sid, (cls_b, sev_b, lab_b) in before.items():
        cls_a, sev_a, lab_a = after[sid]
        res.before_class[cls_b] += 1
        res.after_class[cls_a] += 1
        res.before_label[lab_b] += 1
        res.after_label[lab_a] += 1
        res.transitions[(cls_b, cls_a)] += 1
        if (cls_b, sev_b) != (cls_a, sev_a):
            res.changed += 1


def rescore(conn: Any, enricher: Enricher, cfg: ScoringConfig, since: datetime | None = None,
            batch_size: int = 500, dry_run: bool = False, progress: bool = False) -> RescoreResult:
    """Re-score every session that started at or after ``since`` (all when None).

    ``conn`` must not be in autocommit mode: each batch is committed (or, with
    ``dry_run``, rolled back) on its own.
    """
    res = RescoreResult(dry_run=dry_run)
    last: tuple[Any, str] | None = None
    conn.rollback()  # start clean; every batch is its own transaction
    while True:
        rows = conn.execute(
            "SELECT start_ts, session_id FROM honeylens.sessions "
            "WHERE (%(since)s::timestamptz IS NULL OR start_ts >= %(since)s::timestamptz) "
            "AND (%(lts)s::timestamptz IS NULL OR (start_ts, session_id) > (%(lts)s::timestamptz, %(lsid)s::text)) "
            "ORDER BY start_ts, session_id LIMIT %(n)s",
            {"since": since, "lts": last[0] if last else None, "lsid": last[1] if last else None, "n": batch_size},
        ).fetchall()
        conn.rollback()
        if not rows:
            break
        sids = [r[1] for r in rows]
        for attempt in range(1, RETRIES + 1):
            snapshot = RescoreResult(dry_run=dry_run)
            try:
                _batch(conn, sids, enricher, cfg, snapshot)
                if dry_run:
                    conn.rollback()
                else:
                    conn.commit()
                break
            except (psycopg.errors.DeadlockDetected, psycopg.errors.SerializationFailure):
                conn.rollback()
                if attempt == RETRIES:
                    raise
                log.warning("batch conflicted with the live pipeline, retrying", extra={"attempt": attempt})
                time.sleep(0.5 * attempt)
        _merge(res, snapshot)
        res.sessions += len(sids)
        res.batches += 1
        last = (rows[-1][0], rows[-1][1])
        if progress:
            print(f"  ... {res.sessions} sessions, {res.changed} changed", flush=True)
    return res


def _merge(into: RescoreResult, part: RescoreResult) -> None:
    for name in ("changed", "matches_added", "matches_removed", "commands_remapped", "ignored_added", "ignored_removed"):
        setattr(into, name, getattr(into, name) + getattr(part, name))
    for name in ("before_class", "after_class", "before_label", "after_label", "transitions"):
        getattr(into, name).update(getattr(part, name))


_RELATIVE = re.compile(r"^(\d{1,4})d$")


def parse_since(text: str | None, now: datetime | None = None) -> datetime | None:
    """``--since`` value: an ISO date/time (UTC if no zone) or ``<N>d`` for N days ago."""
    if not text:
        return None
    m = _RELATIVE.match(text.strip())
    if m:
        return (now or datetime.now(UTC)) - timedelta(days=int(m.group(1)))
    value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    """Console entry point ``honeylens-rescore``."""
    parser = argparse.ArgumentParser(
        prog="honeylens-rescore",
        description="Re-match commands and re-score stored sessions with the current rules (raw data is never touched).")
    parser.add_argument("--dry-run", action="store_true", help="show the before/after summary, write nothing")
    parser.add_argument("--since", help="only sessions that started at/after this time: ISO date/time (UTC) or e.g. 7d")
    parser.add_argument("--batch-size", type=int, default=500, help="sessions per transaction (default 500)")
    parser.add_argument("--progress", action="store_true", help="print a line after every batch")
    args = parser.parse_args(argv)
    setup_logging()
    if not 1 <= args.batch_size <= 5000:
        parser.error("--batch-size must be 1-5000")
    try:
        since = parse_since(args.since)
    except ValueError:
        parser.error("--since must be an ISO date/time such as 2026-10-01 or a number of days such as 7d")
    default_rules()  # fail fast on a bad rules file
    require_secret("HL_DB_PASSWORD")
    settings = Settings()
    cfg = ScoringConfig.from_settings(settings)
    enricher = build_enricher(settings)
    started = time.monotonic()
    with psycopg.connect(settings.dsn(), autocommit=False) as conn:
        res = rescore(conn, enricher, cfg, since, args.batch_size, args.dry_run, args.progress)
    print(res.summary())
    print(f"  took {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
