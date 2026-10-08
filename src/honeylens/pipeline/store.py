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
from dataclasses import dataclass
from typing import Any

from psycopg.types.json import Jsonb

from honeylens.enrich.geo import Enricher
from honeylens.mitre.attack import match_command
from honeylens.pipeline.events import Event
from honeylens.pipeline.sanitize import defang
from honeylens.pipeline.scoring import SessionFacts, score_session
from honeylens.pipeline.tailer import FileState


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


def _upsert_sessions(conn: Any, events: list[Event]) -> list[str]:
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
          duration_s = COALESCE(s.duration_s, EXTRACT(EPOCH FROM (s.end_ts - s.start_ts)))
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


def _facts(conn: Any, sid: str) -> tuple[SessionFacts, dict[str, Any]]:
    facts = SessionFacts()
    row = conn.execute(
        "SELECT login_failures, login_success, downloads_count, client_version, host(src_ip), username, commands_count "
        "FROM honeylens.sessions WHERE session_id = %s", (sid,)).fetchone()
    facts.login_failures, facts.login_success, facts.downloads = row[0], row[1], row[2]
    facts.client_version = row[3] or ""
    meta = {"ip": row[4], "username": row[5], "commands": row[6]}
    ok = conn.execute(
        "SELECT min(ts) FROM honeylens.login_attempts WHERE session_id = %s AND success", (sid,)).fetchone()
    facts.login_success_ts = ok[0] if ok else None
    facts.command_ts = [r[0] for r in conn.execute(
        "SELECT ts FROM honeylens.commands WHERE session_id = %s ORDER BY ts", (sid,)).fetchall()]
    for tech, tactic, conf in conn.execute(
            "SELECT DISTINCT technique_id, tactic, confidence FROM honeylens.attack_matches WHERE session_id = %s",
            (sid,)).fetchall():
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


def _score(conn: Any, session_ids: list[str], enricher: Enricher) -> None:
    for sid in session_ids:
        facts, meta = _facts(conn, sid)
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
                source: dict[str, str] | None = None) -> BatchStats:
    """Store events + offsets atomically. Caller owns commit/rollback."""
    stats = BatchStats()
    new_uids = _insert_raw(conn, events, source or {})
    new_events = [e for e in events if e.event_uid in new_uids]
    stats.inserted = len(new_events)
    stats.duplicates = len(events) - len(new_events)
    if new_events:
        _insert_children(conn, new_events)
        sids = _upsert_sessions(conn, new_events)
        _recount(conn, sids)
        _score(conn, sids, enricher)
        stats.sessions_updated = len(sids)
    save_offsets(conn, offsets)
    return stats


def recompute_all(conn: Any, enricher: Enricher) -> int:
    """Rebuild counts/scores for every session (after rule changes)."""
    sids = [r[0] for r in conn.execute("SELECT session_id FROM honeylens.sessions").fetchall()]
    groups: dict[int, list[str]] = defaultdict(list)
    for i, sid in enumerate(sids):
        groups[i // 500].append(sid)
    for chunk in groups.values():
        _recount(conn, chunk)
        _score(conn, chunk, enricher)
    return len(sids)
