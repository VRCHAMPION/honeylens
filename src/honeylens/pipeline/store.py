"""Write a batch of events to PostgreSQL in ONE transaction.

Order inside the transaction:

1. insert raw events (``ON CONFLICT DO NOTHING``) -> learn which are NEW,
2. insert child rows (logins, commands, downloads, ATT&CK matches) for new events,
3. upsert session basics (start/end time, IP, client...),
4. recount session totals from the child tables,
5. enrich + score + summarise every touched session,
6. save file offsets.

If anything fails, PostgreSQL rolls back everything, offsets included, and the
pipeline retries the same lines later. Because of step 1, a retry or a full
replay of old files can never create duplicates. This gives us
"effectively-once" processing without a message queue.

All SQL uses ``%s`` placeholders (parameterized queries): attacker text is
sent separately from the SQL, so SQL injection is impossible.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from psycopg.types.json import Jsonb

from honeylens.config import Network, Settings, ip_in
from honeylens.enrich.geo import Enricher
from honeylens.mitre.attack import match_command
from honeylens.pipeline.events import Event
from honeylens.pipeline.sanitize import defang
from honeylens.pipeline.scoring import SessionFacts, score_session
from honeylens.pipeline.tailer import FileState


@dataclass(frozen=True)
class ScoringConfig:
    """Store-level settings that change how sessions are scored or flagged."""

    brute_window_min: int = 60
    brute_min_failures: int = 20
    ignore_networks: tuple[Network, ...] = field(default_factory=tuple)

    @classmethod
    def from_settings(cls, settings: Settings) -> ScoringConfig:
        """Build from environment-backed :class:`Settings` (raises on a bad HL_IGNORE_IPS)."""
        return cls(settings.brute_window_min, settings.brute_min_failures, settings.ignore_networks)

    @property
    def brute_enabled(self) -> bool:
        """Per-IP brute-force detection is on when both values are positive."""
        return self.brute_window_min > 0 and self.brute_min_failures > 0


DEFAULT_CONFIG = ScoringConfig()


@dataclass
class BatchStats:
    """Counters for one batch."""

    inserted: int = 0
    duplicates: int = 0
    sessions_updated: int = 0


def _insert_raw(conn: Any, events: list[Event], source: dict[str, str]) -> set[str]:
    new: set[str] = set()
    with conn.cursor() as cur:
        for ev in events:
            cur.execute(
                "INSERT INTO honeylens.raw_events "
                "(event_uid, eventid, session_id, src_ip, ts, sensor, is_simulated, payload, source_file) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid) DO NOTHING RETURNING event_uid",
                (
                    ev.event_uid, ev.eventid, ev.session_id, ev.src_ip, ev.ts, ev.sensor,
                    ev.is_simulated, Jsonb(ev.raw), source.get(ev.event_uid, "")[:255],
                ),
            )
            row = cur.fetchone()
            if row:
                new.add(row[0])
    return new


def _insert_children(conn: Any, events: list[Event]) -> None:
    logins, commands, downloads, matches = [], [], [], []
    for ev in events:
        f = ev.fields
        if "success" in f:
            logins.append((ev.event_uid, ev.session_id, ev.ts, ev.src_ip,
                           f["username"], f["password"], f["success"], ev.is_simulated))
        elif "command" in f:
            found = match_command(f["command"]) if f["command"] else []
            commands.append((ev.event_uid, ev.session_id, ev.ts, ev.src_ip,
                             f["command"], f["known"], bool(found), ev.is_simulated))
            for m in found:
                matches.append((ev.event_uid, ev.session_id, ev.ts, m.rule_id, m.technique,
                                m.technique_name, m.tactic, m.confidence, ev.is_simulated))
        elif "url" in f:
            downloads.append((ev.event_uid, ev.session_id, ev.ts, ev.src_ip, f["url"], f["url_host"],
                              f["shasum"], f["outfile"], ev.eventid, ev.is_simulated))
    with conn.cursor() as cur:
        if logins:
            cur.executemany(
                "INSERT INTO honeylens.login_attempts (event_uid, session_id, ts, src_ip, username, password, success, is_simulated) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid) DO NOTHING", logins)
        if commands:
            cur.executemany(
                "INSERT INTO honeylens.commands (event_uid, session_id, ts, src_ip, command, known, mapped, is_simulated) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid) DO NOTHING", commands)
        if downloads:
            cur.executemany(
                "INSERT INTO honeylens.downloads "
                "(event_uid, session_id, ts, src_ip, url, url_host, shasum, outfile, eventid, is_simulated) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid) DO NOTHING", downloads)
        if matches:
            cur.executemany(
                "INSERT INTO honeylens.attack_matches "
                "(event_uid, session_id, ts, rule_id, technique_id, technique_name, tactic, confidence, is_simulated) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_uid, rule_id) DO NOTHING", matches)


def _upsert_sessions(conn: Any, events: list[Event], cfg: ScoringConfig = DEFAULT_CONFIG) -> list[str]:
    per: dict[str, dict[str, Any]] = {}
    for ev in events:
        s = per.setdefault(ev.session_id, {
            "start": ev.ts, "end": ev.ts, "ip": ev.src_ip, "sim": ev.is_simulated, "sensor": ev.sensor,
            "src_port": None, "dst_port": None, "protocol": None, "client": None, "hassh": None, "duration": None,
        })
        s["start"] = min(s["start"], ev.ts)
        s["end"] = max(s["end"], ev.ts)
        s["ip"] = s["ip"] or ev.src_ip
        s["sim"] = s["sim"] or ev.is_simulated
        f = ev.fields
        for k_from, k_to in (("src_port", "src_port"), ("dst_port", "dst_port"), ("protocol", "protocol"),
                             ("client_version", "client"), ("hassh", "hassh"), ("duration", "duration")):
            if f.get(k_from) not in (None, ""):
                s[k_to] = f[k_from]
    with conn.cursor() as cur:
        for sid, s in per.items():
            cur.execute(
                "INSERT INTO honeylens.sessions (session_id, src_ip, src_port, dst_port, protocol, sensor, client_version, hassh, "
                "start_ts, end_ts, duration_s, is_simulated) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (session_id) DO UPDATE SET "
                "src_ip = COALESCE(sessions.src_ip, EXCLUDED.src_ip), "
                "src_port = COALESCE(EXCLUDED.src_port, sessions.src_port), "
                "dst_port = COALESCE(EXCLUDED.dst_port, sessions.dst_port), "
                "protocol = COALESCE(EXCLUDED.protocol, sessions.protocol), "
                "client_version = COALESCE(EXCLUDED.client_version, sessions.client_version), "
                "hassh = COALESCE(EXCLUDED.hassh, sessions.hassh), "
                "start_ts = LEAST(sessions.start_ts, EXCLUDED.start_ts), "
                "end_ts = GREATEST(sessions.end_ts, EXCLUDED.end_ts), "
                "duration_s = COALESCE(EXCLUDED.duration_s, sessions.duration_s), "
                "is_simulated = sessions.is_simulated OR EXCLUDED.is_simulated, updated_at = now()",
                (sid, s["ip"], s["src_port"], s["dst_port"], s["protocol"], s["sensor"], s["client"], s["hassh"],
                 s["start"], s["end"], s["duration"], s["sim"]),
            )
            if ip_in(s["ip"], cfg.ignore_networks):
                cur.execute(
                    "INSERT INTO honeylens.ignored_sessions (session_id, src_ip) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (sid, s["ip"]))
    return list(per)


def _recount(conn: Any, session_ids: list[str]) -> None:
    conn.execute(
        """
        UPDATE honeylens.sessions s SET
          login_attempts = COALESCE(l.total, 0),
          login_failures = COALESCE(l.failed, 0),
          login_success  = COALESCE(l.ok, FALSE),
          username       = l.username,
          commands_count = COALESCE(c.n, 0),
          downloads_count = COALESCE(d.n, 0),
          -- Grows with every batch: the larger of Cowrie's reported duration (from
          -- session.closed) and the observed event span. GREATEST ignores NULLs.
          duration_s = GREATEST(s.duration_s, EXTRACT(EPOCH FROM (s.end_ts - s.start_ts)))
        FROM (SELECT unnest(%s::text[]) AS sid) ids
        LEFT JOIN LATERAL (
            SELECT count(*) total, count(*) FILTER (WHERE NOT success) failed, bool_or(success) ok,
                   (array_agg(username ORDER BY ts DESC) FILTER (WHERE success))[1] username
            FROM honeylens.login_attempts WHERE session_id = ids.sid) l ON TRUE
        LEFT JOIN LATERAL (SELECT count(*) n FROM honeylens.commands WHERE session_id = ids.sid) c ON TRUE
        -- Only real download ATTEMPTS (with a URL). Cowrie also logs files written by
        -- shell redirection (echo > file) as file_download with no URL; those are not downloads.
        LEFT JOIN LATERAL (SELECT count(*) n FROM honeylens.downloads WHERE session_id = ids.sid AND coalesce(url, '') <> '') d ON TRUE
        WHERE s.session_id = ids.sid
        """,
        (session_ids,),
    )


def ip_window_failures(conn: Any, ip: str, start: Any, window_min: int) -> int:
    """Failed logins from ``ip`` within +/- ``window_min`` minutes of ``start``, across all sessions.

    Uses the partial index ``login_failed_ip_ts_idx (src_ip, ts) WHERE NOT success``
    (migration 006), so it is an index range scan, never a table scan.
    """
    span = timedelta(minutes=window_min)
    row = conn.execute(
        "SELECT count(*) FROM honeylens.login_attempts WHERE src_ip = %s AND NOT success AND ts >= %s AND ts <= %s",
        (ip, start - span, start + span)).fetchone()
    return int(row[0])


def _facts(conn: Any, sid: str, cfg: ScoringConfig = DEFAULT_CONFIG) -> tuple[SessionFacts, dict[str, Any]]:
    facts = SessionFacts()
    row = conn.execute(
        "SELECT login_failures, login_success, downloads_count, client_version, host(src_ip), username, commands_count, "
        "start_ts, login_attempts FROM honeylens.sessions WHERE session_id = %s", (sid,)).fetchone()
    facts.login_failures, facts.login_success, facts.downloads = row[0], row[1], row[2]
    facts.client_version = row[3] or ""
    meta = {"ip": row[4], "username": row[5], "commands": row[6]}
    if cfg.brute_enabled and row[4] and row[6] == 0 and row[8] > 0:
        # Only login-only sessions can be upgraded, so only they pay for the query.
        facts.ip_brute_threshold = cfg.brute_min_failures
        facts.ip_window_minutes = cfg.brute_window_min
        facts.ip_window_failures = ip_window_failures(conn, row[4], row[7], cfg.brute_window_min)
    ok = conn.execute(
        "SELECT min(ts) FROM honeylens.login_attempts WHERE session_id = %s AND success", (sid,)).fetchone()
    facts.login_success_ts = ok[0] if ok else None
    facts.command_ts = [r[0] for r in conn.execute(
        "SELECT ts FROM honeylens.commands WHERE session_id = %s ORDER BY ts", (sid,)).fetchall()]
    for rule_id, tech, tactic, conf in conn.execute(
            "SELECT DISTINCT rule_id, technique_id, tactic, confidence FROM honeylens.attack_matches WHERE session_id = %s",
            (sid,)).fetchall():
        facts.rule_ids.add(rule_id)
        facts.techniques.add(tech)
        facts.tactics.add(tactic)
        if conf == "high":
            facts.high_conf_techniques.add(tech)
    return facts, meta


def _summary(meta: dict[str, Any], facts: SessionFacts, result: Any, country: str) -> str:
    ip = meta["ip"] or "unknown IP"
    parts = [f"{defang(ip)}{f' ({country})' if country else ''}"]
    if facts.login_success:
        parts.append(f"logged in as '{meta['username'] or '?'}' after {facts.login_failures} failed attempts")
    elif facts.login_failures:
        parts.append(f"failed {facts.login_failures} logins")
    else:
        parts.append("connected without logging in")
    if meta["commands"]:
        parts.append(f"ran {meta['commands']} commands")
    if facts.downloads:
        parts.append(f"tried {facts.downloads} downloads")
    text = ", ".join(parts) + "."
    if facts.techniques:
        text += f" Techniques: {', '.join(sorted(facts.techniques))}."
    text += f" Class: {result.classification}; severity {result.severity} ({result.label}); actor: {result.actor_type}."
    return text


def _score(conn: Any, session_ids: list[str], enricher: Enricher, cfg: ScoringConfig = DEFAULT_CONFIG) -> None:
    for sid in session_ids:
        facts, meta = _facts(conn, sid, cfg)
        res = score_session(facts)
        geo = None
        if meta["ip"]:
            try:
                ipaddress.ip_address(meta["ip"])
                geo = enricher.lookup(meta["ip"], conn)
            except ValueError:
                geo = None
        conn.execute(
            "UPDATE honeylens.sessions SET classification=%s, severity=%s, severity_label=%s, score_reasons=%s, "
            "actor_type=%s, median_cmd_gap_s=%s, country_code=%s, country=%s, city=%s, asn=%s, as_org=%s, "
            "lat=%s, lon=%s, geo_source=%s, updated_at=now() WHERE session_id=%s",
            (res.classification, res.severity, res.label, Jsonb(res.reasons), res.actor_type, res.median_gap_s,
             geo.country_code if geo else None, geo.country if geo else None, geo.city if geo else None,
             geo.asn if geo else None, geo.as_org if geo else None, geo.lat if geo else None,
             geo.lon if geo else None, geo.source if geo else None, sid),
        )
        conn.execute(
            "INSERT INTO honeylens.session_summaries (session_id, summary, techniques, tactics) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (session_id) DO UPDATE SET summary=EXCLUDED.summary, techniques=EXCLUDED.techniques, "
            "tactics=EXCLUDED.tactics, updated_at=now()",
            (sid, _summary(meta, facts, res, geo.country if geo else ""), sorted(facts.techniques), sorted(facts.tactics)),
        )


def _upgrade_burst_neighbours(conn: Any, session_ids: list[str], enricher: Enricher, cfg: ScoringConfig) -> int:
    """Re-score earlier login-only 'scanner' sessions whose IP just crossed the brute-force threshold.

    Sessions are scored when their events arrive, so the first few connections
    of a burst were scored before the IP had enough failures. After each batch,
    for every source IP in it, the still-'scanner' login-only sessions of that IP
    whose window overlaps the batch are re-scored once. Each session is
    upgraded at most once (it stops being 'scanner'), so the extra cost is
    bounded. Uses the (src_ip, start_ts) index from migration 006.
    """
    if not cfg.brute_enabled or not session_ids:
        return 0
    span = timedelta(minutes=cfg.brute_window_min)
    rows = conn.execute(
        "SELECT src_ip, min(start_ts), max(start_ts) FROM honeylens.sessions "
        "WHERE session_id = ANY(%s) AND src_ip IS NOT NULL AND classification = 'brute-forcer' GROUP BY src_ip",
        (session_ids,)).fetchall()
    todo: list[str] = []
    for ip, lo, hi in rows:
        todo += [r[0] for r in conn.execute(
            "SELECT session_id FROM honeylens.sessions WHERE src_ip = %s AND start_ts >= %s AND start_ts <= %s "
            "AND classification = 'scanner' AND commands_count = 0 AND login_attempts > 0 AND NOT (session_id = ANY(%s))",
            (ip, lo - span, hi + span, session_ids)).fetchall()]
    if todo:
        _score(conn, todo, enricher, cfg)
    return len(todo)


def save_offsets(conn: Any, states: dict[str, FileState]) -> None:
    """Persist file offsets (same transaction as the events)."""
    with conn.cursor() as cur:
        for st in states.values():
            cur.execute(
                "INSERT INTO honeylens.ingest_offsets (file_key, path, byte_offset, head_hash) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (file_key) DO UPDATE SET path=EXCLUDED.path, byte_offset=EXCLUDED.byte_offset, "
                "head_hash=COALESCE(EXCLUDED.head_hash, ingest_offsets.head_hash), updated_at=now()",
                (st.key, st.path[:512], st.offset, st.head_hash),
            )


def load_offsets(conn: Any) -> list[tuple[str, str, int, str | None]]:
    """Read saved offsets."""
    return [tuple(r) for r in conn.execute(
        "SELECT file_key, path, byte_offset, head_hash FROM honeylens.ingest_offsets").fetchall()]  # type: ignore[misc]


def write_batch(conn: Any, events: list[Event], enricher: Enricher, offsets: dict[str, FileState],
                source: dict[str, str] | None = None, cfg: ScoringConfig = DEFAULT_CONFIG) -> BatchStats:
    """Store events + offsets atomically. Caller owns commit/rollback."""
    stats = BatchStats()
    new_uids = _insert_raw(conn, events, source or {})
    new_events = [e for e in events if e.event_uid in new_uids]
    stats.inserted = len(new_events)
    stats.duplicates = len(events) - len(new_events)
    if new_events:
        _insert_children(conn, new_events)
        sids = _upsert_sessions(conn, new_events, cfg)
        _recount(conn, sids)
        _score(conn, sids, enricher, cfg)
        stats.sessions_updated = len(sids) + _upgrade_burst_neighbours(conn, sids, enricher, cfg)
    save_offsets(conn, offsets)
    return stats


def recompute_all(conn: Any, enricher: Enricher, cfg: ScoringConfig = DEFAULT_CONFIG) -> int:
    """Rebuild counts/scores for every session (after rule changes).

    Kept for ``honeylens-pipeline --recompute``. It only re-scores; the full
    backfill (re-matching commands against the current rules, refreshing the
    ignore flag) is ``honeylens-rescore``.
    """
    sids = [r[0] for r in conn.execute("SELECT session_id FROM honeylens.sessions").fetchall()]
    groups: dict[int, list[str]] = defaultdict(list)
    for i, sid in enumerate(sids):
        groups[i // 500].append(sid)
    for chunk in groups.values():
        _recount(conn, chunk)
        _score(conn, chunk, enricher, cfg)
    return len(sids)
