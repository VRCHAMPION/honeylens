"""Read report data from PostgreSQL with the READ-ONLY ``hl_report`` role.

All queries are parameterized and limited (TOP-N), so the report stays small
even after months of data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

FILTERS = {"all": None, "real": False, "simulated": True}


@dataclass
class Window:
    """The reporting week and the week before it (for week-over-week)."""

    start: datetime
    end: datetime

    @property
    def prev(self) -> Window:
        """The previous window of the same length."""
        span = self.end - self.start
        return Window(self.start - span, self.start)


@dataclass
class ReportData:
    """Everything the template and exporters need."""

    window: Window
    data_filter: str
    totals: dict[str, Any] = field(default_factory=dict)
    prev_totals: dict[str, Any] = field(default_factory=dict)
    sim_share: float = 0.0
    countries: list[dict[str, Any]] = field(default_factory=list)
    asns: list[dict[str, Any]] = field(default_factory=list)
    ips: list[dict[str, Any]] = field(default_factory=list)
    usernames: list[dict[str, Any]] = field(default_factory=list)
    passwords: list[dict[str, Any]] = field(default_factory=list)
    pairs: list[dict[str, Any]] = field(default_factory=list)
    commands: list[dict[str, Any]] = field(default_factory=list)
    unmapped: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[dict[str, Any]] = field(default_factory=list)
    tactics: list[dict[str, Any]] = field(default_factory=list)
    classes: list[dict[str, Any]] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    notable: list[dict[str, Any]] = field(default_factory=list)
    ioc_ips: list[dict[str, Any]] = field(default_factory=list)
    ioc_urls: list[dict[str, Any]] = field(default_factory=list)
    ioc_hashes: list[dict[str, Any]] = field(default_factory=list)
    daily: list[dict[str, Any]] = field(default_factory=list)


def _rows(conn: Any, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


SIM = "(%(sim)s::boolean IS NULL OR is_simulated = %(sim)s::boolean)"


def _totals(conn: Any, w: Window, sim: bool | None) -> dict[str, Any]:
    p = {"a": w.start, "b": w.end, "sim": sim}
    row = _rows(conn, f"""
        SELECT count(*) AS sessions,
               count(DISTINCT src_ip) AS unique_ips,
               coalesce(sum(login_attempts),0) AS login_attempts,
               count(*) FILTER (WHERE login_success) AS successful_logins,
               coalesce(sum(commands_count),0) AS commands,
               coalesce(sum(downloads_count),0) AS downloads,
               count(*) FILTER (WHERE severity >= 50) AS high_or_critical,
               count(DISTINCT country_code) FILTER (WHERE country_code <> '') AS countries
        FROM honeylens.sessions WHERE start_ts >= %(a)s AND start_ts < %(b)s AND {SIM}""", p)[0]
    row["techniques"] = _rows(conn, f"""SELECT count(DISTINCT technique_id) AS n FROM honeylens.attack_matches
        WHERE ts >= %(a)s AND ts < %(b)s AND {SIM}""", p)[0]["n"]
    return row


def load(conn: Any, end: datetime, days: int = 7, data_filter: str = "all", top: int = 10) -> ReportData:
    """Run all report queries for the window ending at ``end``."""
    if data_filter not in FILTERS:
        raise ValueError("data_filter must be all, real or simulated")
    sim = FILTERS[data_filter]
    w = Window(end - timedelta(days=days), end)
    p = {"a": w.start, "b": w.end, "sim": sim, "top": top}
    d = ReportData(window=w, data_filter=data_filter)
    d.totals = _totals(conn, w, sim)
    d.prev_totals = _totals(conn, w.prev, sim)
    share = _rows(conn, """SELECT count(*) FILTER (WHERE is_simulated) AS s, count(*) AS n FROM honeylens.sessions
        WHERE start_ts >= %(a)s AND start_ts < %(b)s""", p)[0]
    d.sim_share = (share["s"] / share["n"]) if share["n"] else 0.0
    sess = f"FROM honeylens.sessions WHERE start_ts >= %(a)s AND start_ts < %(b)s AND {SIM}"
    d.countries = _rows(conn, f"""SELECT coalesce(nullif(country,''),'Unknown') AS country, country_code,
        count(*) AS sessions, count(DISTINCT src_ip) AS ips {sess} GROUP BY 1,2 ORDER BY 3 DESC LIMIT %(top)s""", p)
    d.asns = _rows(conn, f"""SELECT asn, coalesce(nullif(as_org,''),'Unknown') AS as_org, count(*) AS sessions,
        count(DISTINCT src_ip) AS ips {sess} GROUP BY 1,2 ORDER BY 3 DESC LIMIT %(top)s""", p)
    d.ips = _rows(conn, f"""SELECT host(src_ip) AS ip, max(country) AS country, max(as_org) AS as_org,
        count(*) AS sessions, sum(login_attempts) AS logins, max(severity) AS max_severity,
        bool_or(is_simulated) AS simulated {sess} GROUP BY src_ip ORDER BY 4 DESC, 6 DESC LIMIT %(top)s""", p)
    la = f"FROM honeylens.login_attempts WHERE ts >= %(a)s AND ts < %(b)s AND {SIM}"
    d.usernames = _rows(conn, f"SELECT username, count(*) AS attempts {la} GROUP BY 1 ORDER BY 2 DESC LIMIT %(top)s", p)
    d.passwords = _rows(conn, f"SELECT password, count(*) AS attempts {la} GROUP BY 1 ORDER BY 2 DESC LIMIT %(top)s", p)
    d.pairs = _rows(conn, f"""SELECT username, password, count(*) AS attempts, bool_or(success) AS worked
        {la} GROUP BY 1,2 ORDER BY 3 DESC LIMIT %(top)s""", p)
    cm = f"FROM honeylens.commands WHERE ts >= %(a)s AND ts < %(b)s AND {SIM}"
    d.commands = _rows(conn, f"""SELECT command, count(*) AS times, count(DISTINCT session_id) AS sessions, bool_or(mapped) AS mapped
        {cm} GROUP BY 1 ORDER BY 2 DESC LIMIT %(top)s""", p)
    d.unmapped = _rows(conn, f"""SELECT command, count(*) AS times {cm} AND NOT mapped
        GROUP BY 1 ORDER BY 2 DESC LIMIT %(top)s""", p)
    am = f"FROM honeylens.attack_matches WHERE ts >= %(a)s AND ts < %(b)s AND {SIM}"
    d.techniques = _rows(conn, f"""SELECT technique_id, technique_name, tactic, count(*) AS matches,
        count(DISTINCT session_id) AS sessions {am} GROUP BY 1,2,3 ORDER BY 5 DESC, 4 DESC LIMIT 25""", p)
    d.tactics = _rows(conn, f"""SELECT tactic, count(DISTINCT session_id) AS sessions, count(DISTINCT technique_id) AS techniques
        {am} GROUP BY 1 ORDER BY 2 DESC""", p)
    d.classes = _rows(conn, f"""SELECT coalesce(classification,'unknown') AS classification, count(*) AS sessions,
        round(avg(severity)::numeric,1) AS avg_severity {sess} GROUP BY 1 ORDER BY 2 DESC""", p)
    d.actors = _rows(conn, f"""SELECT coalesce(actor_type,'unknown') AS actor_type, count(*) AS sessions
        {sess} GROUP BY 1 ORDER BY 2 DESC""", p)
    d.notable = _rows(conn, """SELECT s.session_id, host(s.src_ip) AS ip, s.start_ts, s.classification, s.severity,
        s.severity_label, s.actor_type, s.commands_count, s.is_simulated, ss.summary, ss.techniques
        FROM honeylens.sessions s LEFT JOIN honeylens.session_summaries ss USING (session_id)
        WHERE s.start_ts >= %(a)s AND s.start_ts < %(b)s AND (%(sim)s::boolean IS NULL OR s.is_simulated = %(sim)s::boolean)
        ORDER BY s.severity DESC NULLS LAST, s.commands_count DESC, s.start_ts LIMIT 8""", p)
    d.ioc_ips = _rows(conn, f"""SELECT host(src_ip) AS ip, max(country_code) AS country_code, max(asn) AS asn,
        count(*) AS sessions, max(severity) AS max_severity, min(start_ts) AS first_seen, max(end_ts) AS last_seen,
        bool_or(is_simulated) AS simulated, array_agg(DISTINCT classification) AS classes
        {sess} AND (login_success OR severity >= 25) GROUP BY src_ip ORDER BY 5 DESC, 4 DESC LIMIT 200""", p)
    dl = f"FROM honeylens.downloads WHERE ts >= %(a)s AND ts < %(b)s AND {SIM}"
    d.ioc_urls = _rows(conn, f"""SELECT url, url_host, count(*) AS attempts, count(DISTINCT session_id) AS sessions,
        min(ts) AS first_seen, max(ts) AS last_seen, bool_or(is_simulated) AS simulated
        {dl} AND url <> '' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 200""", p)
    d.ioc_hashes = _rows(conn, f"""SELECT shasum, count(*) AS seen, min(ts) AS first_seen, bool_or(is_simulated) AS simulated
        {dl} AND shasum <> '' GROUP BY 1 ORDER BY 2 DESC LIMIT 200""", p)
    d.daily = _rows(conn, f"""SELECT date_trunc('day', start_ts AT TIME ZONE 'Asia/Kolkata') AS day, count(*) AS sessions
        {sess} GROUP BY 1 ORDER BY 1""", p)
    return d
