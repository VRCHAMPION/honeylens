#!/usr/bin/env python3
"""Generate the five Grafana dashboard JSON files in grafana/dashboards/.

Why a generator instead of hand-editing JSON: Grafana dashboard JSON is long
and repetitive. Building it from small Python helpers keeps every dashboard
consistent (same data filter, same IST timezone, same simulated-data banner)
and makes reviews easy. The generated JSON files ARE committed, so Grafana can
load them without Python.

Run:  python scripts/build_dashboards.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "grafana" / "dashboards"
DS = {"type": "grafana-postgresql-datasource", "uid": "honeylens-pg"}
# The data filter: 'all', 'real' or 'simulated'. The dropdown has fixed values,
# but a crafted dashboard URL (?var-data=...) can set any text, so the value is
# always interpolated with Grafana's :sqlstring format (quoted + escaped).
SIM = "(${data:sqlstring} = 'all' OR {col} = (${data:sqlstring} = 'simulated'))"


def sim(col: str = "is_simulated") -> str:
    """SQL condition for the $data filter on a given column."""
    return SIM.replace("{col}", col)


class Board:
    """Small helper that lays panels out on Grafana's 24-column grid."""

    def __init__(self, uid: str, title: str, description: str, file: str) -> None:
        self.uid, self.title, self.description, self.file = uid, title, description, file
        self.panels: list[dict] = []
        self.x = self.y = self.row_h = 0
        self.next_id = 1
        self.extra_vars: list[dict] = []

    def _place(self, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def newline(self) -> None:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0

    def add(self, ptype: str, title: str, sql: str | list[str], w: int, h: int, fmt: str = "table",
            description: str = "", **opts: object) -> dict:
        sqls = [sql] if isinstance(sql, str) else sql
        panel = {
            "id": self.next_id, "type": ptype, "title": title, "description": description,
            "datasource": DS, "gridPos": self._place(w, h),
            "targets": [{"refId": chr(65 + i), "datasource": DS, "format": fmt, "rawQuery": True,
                         "editorMode": "code", "rawSql": " ".join(s.split())} for i, s in enumerate(sqls)],
            "fieldConfig": opts.pop("fieldConfig", {"defaults": {}, "overrides": []}),
            "options": opts.pop("options", {}),
        }
        panel.update(opts)
        self.next_id += 1
        self.panels.append(panel)
        return panel

    def text(self, title: str, md: str, w: int, h: int) -> None:
        self.panels.append({"id": self.next_id, "type": "text", "title": title, "gridPos": self._place(w, h),
                            "options": {"mode": "markdown", "content": md}})
        self.next_id += 1

    def stat(self, title: str, sql: str, w: int = 4, unit: str = "short", thresholds: list | None = None,
             description: str = "", h: int = 3) -> None:
        # Compact console style: coloured VALUE on the normal panel background (no
        # big coloured boxes). Colour only carries meaning via thresholds.
        steps = thresholds or [{"color": "text", "value": None}]
        self.add("stat", title, sql, w, h, description=description,
                 fieldConfig={"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps},
                                           "color": {"mode": "thresholds"}}, "overrides": []},
                 options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                          "colorMode": "value", "graphMode": "none", "textMode": "value",
                          "justifyMode": "auto", "text": {"valueSize": 26}})

    def banner(self) -> None:
        """One thin row: a DATA MODE indicator computed from the data, plus one line of context."""
        self.add("stat", "", (
            "SELECT CASE WHEN count(*) = 0 THEN 'NO DATA' "
            "WHEN bool_and(is_simulated) THEN 'SIMULATED' WHEN NOT bool_or(is_simulated) THEN 'REAL' "
            "ELSE 'MIXED · ' || round(100.0 * count(*) FILTER (WHERE is_simulated) / count(*)) || '% SIM' END AS \"DATA MODE\" "
            "FROM honeylens.sessions WHERE $__timeFilter(start_ts)"), 6, 2,
            description="Computed from the sessions in the time range (ignores the Data filter). "
                        "SIMULATED = made by the HoneyLens simulator; REAL = internet attackers.",
            fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": "text"}, "mappings": [
                {"type": "value", "options": {"SIMULATED": {"color": "#b45309", "index": 0},
                                              "REAL": {"color": "#15803d", "index": 1},
                                              "NO DATA": {"color": "#475569", "index": 2}}},
                {"type": "regex", "options": {"pattern": "^MIXED.*", "result": {"color": "#a16207", "index": 3}}}]},
                "overrides": []},
            options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "/.*/", "values": False},
                     "colorMode": "background_solid", "graphMode": "none", "textMode": "value_and_name",
                     "justifyMode": "center", "text": {"titleSize": 11, "valueSize": 16}},
            transparent=False)
        self.text("", (
            "<div style='font-family:monospace;font-size:12px;line-height:1.5;color:#c7ccd6;"
            "border-left:3px solid #b45309;padding:2px 8px'>"
            "Simulated = RFC 5737 documentation IPs, private Docker addresses or the synthetic generator "
            "(never real attackers). Filter with <b>Data</b> = all / real / simulated. "
            "Times in IST (Asia/Kolkata); stored in UTC.</div>"), 18, 2)

    def to_json(self) -> dict:
        variables = [{
            "name": "data", "label": "Data", "type": "custom", "query": "all,real,simulated",
            "current": {"text": "all", "value": "all"}, "options": [
                {"text": v, "value": v, "selected": v == "all"} for v in ("all", "real", "simulated")],
            "description": "all = everything; real = internet attackers only; simulated = HoneyLens simulator only",
        }] + self.extra_vars
        return {
            "uid": self.uid, "title": self.title, "description": self.description, "tags": ["honeylens"],
            "timezone": "Asia/Kolkata", "editable": False, "graphTooltip": 1, "schemaVersion": 41,
            "time": {"from": "now-7d", "to": "now"}, "refresh": "1m",
            "templating": {"list": variables}, "panels": self.panels, "version": 1,
            "links": [{"title": "HoneyLens dashboards", "type": "dashboards", "tags": ["honeylens"], "asDropdown": True}],
        }


SEV_STEPS = [{"color": "#3f6f4f", "value": None}, {"color": "#8a7a2a", "value": 25},
             {"color": "#a8571c", "value": 50}, {"color": "#a32626", "value": 75}]
# One fixed, restrained colour per behaviour class (same in every panel).
CLASS_COLORS = {"scanner": "#5b7db1", "brute-forcer": "#c99a2e", "intruder": "#d27d2d",
                "malware-dropper": "#c0392b", "cryptominer-like": "#8e2c2c", "honeypot-prober": "#4f9d9d",
                "unknown": "#6b7280"}
CLASS_OVERRIDES = [{"matcher": {"id": "byName", "options": k},
                    "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": v}}]}
                   for k, v in CLASS_COLORS.items()]
S_WHERE = f"FROM honeylens.sessions WHERE $__timeFilter(start_ts) AND {sim()}"


def soc_overview() -> Board:
    b = Board("hl-soc-overview", "HoneyLens · 1. SOC Overview",
              "Big picture: how much attack traffic, from where, and what kind.", "01-soc-overview.json")
    b.banner()
    b.stat("Sessions", f"SELECT count(*) AS \"Sessions\" {S_WHERE}")
    b.stat("Unique source IPs", f"SELECT count(DISTINCT src_ip) AS \"IPs\" {S_WHERE}")
    b.stat("Login attempts", f"SELECT coalesce(sum(login_attempts),0) AS \"Logins\" {S_WHERE}")
    b.stat("Successful (fake) logins", f"SELECT count(*) FILTER (WHERE login_success) AS \"Success\" {S_WHERE}")
    b.stat("Commands run", f"SELECT coalesce(sum(commands_count),0) AS \"Commands\" {S_WHERE}")
    b.stat("High / critical sessions", f"SELECT count(*) FILTER (WHERE severity >= 50) AS \"High+\" {S_WHERE}",
           thresholds=[{"color": "text", "value": None}, {"color": "#e05252", "value": 1}])
    b.newline()
    b.add("timeseries", "Sessions per hour by behaviour class",
          f"SELECT $__timeGroupAlias(start_ts, 1h), classification AS metric, count(*) AS value {S_WHERE} "
          f"GROUP BY 1, 2 ORDER BY 1", 14, 9, fmt="time_series",
          fieldConfig={"defaults": {"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 70,
                                               "lineWidth": 1}},
                       "overrides": CLASS_OVERRIDES},
          options={"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}})
    b.add("piechart", "Behaviour classes", f"SELECT classification AS metric, count(*) AS value {S_WHERE} GROUP BY 1 ORDER BY 2 DESC",
          10, 9, options={"reduceOptions": {"values": True, "calcs": ["lastNotNull"]}, "pieType": "donut",
                          "legend": {"displayMode": "table", "placement": "right", "values": ["value", "percent"]}},
          fieldConfig={"defaults": {}, "overrides": CLASS_OVERRIDES})
    b.add("geomap", "Where sessions come from (registered location, not attribution)",
          f"SELECT avg(lat) AS latitude, avg(lon) AS longitude, coalesce(nullif(country,''),'Unknown') AS country, "
          f"count(*) AS sessions {S_WHERE} AND lat IS NOT NULL GROUP BY country", 12, 10,
          options={"view": {"id": "zero", "lat": 20, "lon": 30, "zoom": 1},
                   # Offline basemap: the country outlines that ship inside Grafana. No
                   # third-party tile server is contacted (privacy, and CARTO now needs a key).
                   "basemap": {"type": "geojson", "name": "Countries",
                               "config": {"src": "public/maps/countries.geojson",
                                          "style": {"color": {"fixed": "#3a3f4b"}, "opacity": 0.6}}},
                   "layers": [{"type": "markers", "name": "Sessions", "location": {"mode": "coords", "latitude": "latitude", "longitude": "longitude"},
                               "config": {"showLegend": True, "style": {
                                   "size": {"field": "sessions", "min": 5, "max": 30, "fixed": 6},
                                   "color": {"fixed": "#d27d2d"}, "opacity": 0.7}}}],
                   "controls": {"showZoom": True, "mouseWheelZoom": False}})
    b.add("table", "Top countries", f"SELECT coalesce(nullif(country,''),'Unknown') AS \"Country\", count(*) AS \"Sessions\", "
          f"count(DISTINCT src_ip) AS \"IPs\" {S_WHERE} GROUP BY 1 ORDER BY 2 DESC LIMIT 10", 6, 10)
    b.add("table", "Top networks (ASN)", f"SELECT CASE WHEN asn IS NULL THEN '' ELSE 'AS' || asn END AS \"ASN\", "
          f"coalesce(nullif(as_org,''),'Unknown') AS \"Organisation\", count(*) AS \"Sessions\" {S_WHERE} "
          f"GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10", 6, 10)
    b.add("table", "Top source IPs", f"SELECT host(src_ip) AS \"IP\", max(country) AS \"Country\", count(*) AS \"Sessions\", "
          f"max(severity) AS \"Max severity\", bool_or(is_simulated) AS \"Simulated\" {S_WHERE} GROUP BY src_ip "
          f"ORDER BY 3 DESC LIMIT 15", 12, 9,
          fieldConfig={"defaults": {}, "overrides": [{"matcher": {"id": "byName", "options": "Max severity"}, "properties": [
              {"id": "custom.cellOptions", "value": {"type": "color-background"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": SEV_STEPS}}]}]})
    b.add("barchart", "Severity distribution", f"SELECT severity_label AS \"Severity\", count(*) AS \"Sessions\" {S_WHERE} "
          f"GROUP BY 1 ORDER BY min(severity)", 12, 9, options={"xField": "Severity", "orientation": "vertical"})
    return b


def creds_commands() -> Board:
    b = Board("hl-creds-commands", "HoneyLens · 2. Credentials & Commands",
              "What attackers type: usernames, passwords and shell commands.", "02-credentials-commands.json")
    b.banner()
    la = f"FROM honeylens.login_attempts WHERE $__timeFilter(ts) AND {sim()}"
    cm = f"FROM honeylens.commands WHERE $__timeFilter(ts) AND {sim()}"
    b.add("timeseries", "Login attempts per hour (failed vs succeeded)",
          f"SELECT $__timeGroupAlias(ts, 1h), CASE WHEN success THEN 'succeeded' ELSE 'failed' END AS metric, "
          f"count(*) AS value {la} GROUP BY 1, 2 ORDER BY 1", 24, 8, fmt="time_series",
          fieldConfig={"defaults": {"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}},
                       "overrides": []})
    b.add("table", "Top usernames", f"SELECT username AS \"Username\", count(*) AS \"Attempts\" {la} GROUP BY 1 ORDER BY 2 DESC LIMIT 15", 6, 11)
    b.add("table", "Top passwords (typed into a FAKE server)", f"SELECT password AS \"Password\", count(*) AS \"Attempts\" {la} "
          f"GROUP BY 1 ORDER BY 2 DESC LIMIT 15", 6, 11)
    b.add("table", "Top username / password pairs", f"SELECT username AS \"Username\", password AS \"Password\", count(*) AS \"Attempts\", "
          f"bool_or(success) AS \"Worked\" {la} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15", 12, 11)
    b.add("table", "Top commands", f"SELECT command AS \"Command\", count(*) AS \"Times\", count(DISTINCT session_id) AS \"Sessions\", "
          f"bool_or(mapped) AS \"ATT&CK mapped\" {cm} GROUP BY 1 ORDER BY 2 DESC LIMIT 20", 14, 12)
    b.add("table", "Unmapped commands (ideas for new rules)", f"SELECT command AS \"Command\", count(*) AS \"Times\" {cm} AND NOT mapped "
          f"GROUP BY 1 ORDER BY 2 DESC LIMIT 20", 10, 12)
    b.add("barchart", "SSH client software", f"SELECT coalesce(nullif(client_version,''),'(none)') AS \"Client\", count(*) AS \"Sessions\" "
          f"{S_WHERE} GROUP BY 1 ORDER BY 2 DESC LIMIT 10", 12, 9, options={"xField": "Client", "orientation": "horizontal"})
    b.add("table", "Download attempts (never fetched)", f"SELECT url AS \"URL\", url_host AS \"Host\", count(*) AS \"Attempts\" "
          f"FROM honeylens.downloads WHERE $__timeFilter(ts) AND {sim()} AND url <> '' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15", 12, 9)
    return b


def attack_behaviour() -> Board:
    b = Board("hl-attack-behaviour", "HoneyLens · 3. ATT&CK & Behaviour",
              "MITRE ATT&CK techniques matched by regex rules, plus behaviour classes and bot-vs-human timing.",
              "03-attack-behaviour.json")
    b.banner()
    am = f"FROM honeylens.attack_matches WHERE $__timeFilter(ts) AND {sim()}"
    b.add("barchart", "Sessions per ATT&CK tactic", f"SELECT tactic AS \"Tactic\", count(DISTINCT session_id) AS \"Sessions\" {am} "
          f"GROUP BY 1 ORDER BY 2 DESC", 10, 10, options={"xField": "Tactic", "orientation": "horizontal"})
    b.add("table", "Techniques seen", f"SELECT technique_id AS \"ID\", technique_name AS \"Technique\", tactic AS \"Tactic\", "
          f"count(DISTINCT session_id) AS \"Sessions\", count(*) AS \"Matches\" {am} GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 25", 14, 10)
    b.add("timeseries", "Top techniques per day", f"SELECT $__timeGroupAlias(ts, 1d), technique_id AS metric, count(DISTINCT session_id) AS value "
          f"{am} AND technique_id IN (SELECT technique_id {am} GROUP BY 1 ORDER BY count(*) DESC LIMIT 6) GROUP BY 1, 2 ORDER BY 1",
          12, 9, fmt="time_series")
    b.add("piechart", "Bot vs human (command timing)", f"SELECT coalesce(actor_type,'unknown') AS metric, count(*) AS value {S_WHERE} "
          f"AND commands_count > 0 GROUP BY 1", 6, 9, options={"reduceOptions": {"values": True, "calcs": ["lastNotNull"]},
                                                              "pieType": "pie", "legend": {"displayMode": "list", "placement": "bottom"}})
    b.add("barchart", "Average severity by class", f"SELECT classification AS \"Class\", round(avg(severity)::numeric,1) AS \"Avg severity\" "
          f"{S_WHERE} GROUP BY 1 ORDER BY 2 DESC", 6, 9, options={"xField": "Class", "orientation": "horizontal"})
    b.add("table", "Rule hits (which detection rules fire)", f"SELECT rule_id AS \"Rule\", technique_id AS \"Technique\", confidence AS \"Confidence\", "
          f"count(*) AS \"Hits\" {am} GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 20", 12, 10)
    b.add("table", "Command coverage", f"SELECT count(*) FILTER (WHERE mapped) AS \"Mapped commands\", count(*) FILTER (WHERE NOT mapped) AS "
          f"\"Unmapped commands\", round(100.0 * count(*) FILTER (WHERE mapped) / greatest(count(*),1), 1) AS \"Mapped %\" "
          f"FROM honeylens.commands WHERE $__timeFilter(ts) AND {sim()}", 12, 10)
    return b


def session_explorer() -> Board:
    b = Board("hl-session-explorer", "HoneyLens · 4. Session Explorer",
              "Drill into individual sessions: score reasons, commands, techniques.", "04-session-explorer.json")
    b.extra_vars.append({
        "name": "session", "label": "Session", "type": "query", "datasource": DS,
        "query": f"SELECT session_id FROM honeylens.sessions WHERE $__timeFilter(start_ts) AND {sim()} "
                 f"ORDER BY severity DESC NULLS LAST, start_ts DESC LIMIT 300",
        "refresh": 2, "includeAll": False, "sort": 0,
        "description": "Pick a session (highest severity first).",
    })
    b.banner()
    b.add("table", "Sessions (highest severity first)", f"SELECT start_ts AS \"Start (IST)\", session_id AS \"Session\", host(src_ip) AS \"IP\", "
          f"country AS \"Country\", classification AS \"Class\", severity AS \"Severity\", actor_type AS \"Actor\", "
          f"login_attempts AS \"Logins\", commands_count AS \"Cmds\", is_simulated AS \"Sim\" {S_WHERE} "
          f"ORDER BY severity DESC NULLS LAST, start_ts DESC LIMIT 200", 24, 10,
          fieldConfig={"defaults": {}, "overrides": [{"matcher": {"id": "byName", "options": "Severity"}, "properties": [
              {"id": "custom.cellOptions", "value": {"type": "color-background"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": SEV_STEPS}}]}]})
    one = "FROM honeylens.v_session_overview WHERE session_id = ${session:sqlstring}"
    b.add("stat", "Selected session severity", f"SELECT severity AS \"Severity\" {one}", 4, 6,
          fieldConfig={"defaults": {"min": 0, "max": 100, "thresholds": {"mode": "absolute", "steps": SEV_STEPS},
                                    "color": {"mode": "thresholds"}}, "overrides": []},
          options={"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none"})
    b.add("table", "Summary", f"SELECT summary AS \"Summary\", classification AS \"Class\", actor_type AS \"Actor\", "
          f"median_cmd_gap_s AS \"Median gap (s)\" {one}", 20, 6,
          options={"cellHeight": "lg"}, fieldConfig={"defaults": {"custom": {"cellOptions": {"type": "auto", "wrapText": True}}}, "overrides": []})
    b.add("table", "Why this score (transparent points)", "SELECT r->>'rule' AS \"Rule\", (r->>'points')::int AS \"Points\", r->>'detail' AS \"Detail\" "
          "FROM honeylens.sessions, jsonb_array_elements(score_reasons) r WHERE session_id = ${session:sqlstring}", 10, 9)
    b.add("table", "Commands in this session", "SELECT ts AS \"Time (IST)\", command AS \"Command\", mapped AS \"Mapped\" "
          "FROM honeylens.commands WHERE session_id = ${session:sqlstring} ORDER BY ts", 14, 9)
    b.add("table", "ATT&CK matches in this session", "SELECT ts AS \"Time (IST)\", technique_id AS \"Technique\", technique_name AS \"Name\", "
          "tactic AS \"Tactic\", rule_id AS \"Rule\" FROM honeylens.attack_matches WHERE session_id = ${session:sqlstring} ORDER BY ts", 12, 8)
    b.add("table", "Logins in this session", "SELECT ts AS \"Time (IST)\", username AS \"Username\", password AS \"Password\", success AS \"OK\" "
          "FROM honeylens.login_attempts WHERE session_id = ${session:sqlstring} ORDER BY ts", 12, 8)
    return b


def pipeline_health() -> Board:
    b = Board("hl-pipeline-health", "HoneyLens · 5. Pipeline Health",
              "Is the data pipeline alive and keeping up? (These metrics are about HoneyLens itself.)", "05-pipeline-health.json")
    b.text("", "<div style='font-family:monospace;font-size:12px;color:#c7ccd6;border-left:3px solid #5b7db1;padding:2px 8px'>"
              "Source: <code>honeylens.pipeline_stats</code> (one row per batch + a heartbeat every 30 s). "
              "These metrics describe HoneyLens itself, not attackers. Times in IST.</div>", 24, 2)
    ps = "FROM honeylens.pipeline_stats WHERE $__timeFilter(ts)"
    b.stat("Seconds since last heartbeat", "SELECT round(extract(epoch FROM now() - max(ts))) AS \"Seconds\" FROM honeylens.pipeline_stats", 4, "s",
           [{"color": "#3fae6a", "value": None}, {"color": "#d29922", "value": 90}, {"color": "#e05252", "value": 300}])
    b.stat("Events ingested", f"SELECT coalesce(sum(events_ingested),0) AS \"Events\" {ps}")
    b.stat("Duplicates skipped", f"SELECT coalesce(sum(duplicates),0) AS \"Dupes\" {ps}")
    b.stat("Malformed lines", f"SELECT coalesce(sum(malformed),0) AS \"Malformed\" {ps}",
           thresholds=[{"color": "#3fae6a", "value": None}, {"color": "#d29922", "value": 1}])
    b.stat("Oversized lines", f"SELECT coalesce(sum(oversized),0) AS \"Oversized\" {ps}",
           thresholds=[{"color": "#3fae6a", "value": None}, {"color": "#d29922", "value": 1}])
    b.stat("Unread backlog", "SELECT lag_bytes AS \"Backlog\" FROM honeylens.pipeline_stats ORDER BY ts DESC LIMIT 1", 4, "bytes",
           [{"color": "#3fae6a", "value": None}, {"color": "#d29922", "value": 1000000}])
    b.newline()
    b.add("timeseries", "Events ingested per 5 minutes", f"SELECT $__timeGroupAlias(ts, 5m), sum(events_ingested) AS \"ingested\", "
          f"sum(duplicates) AS \"duplicates\", sum(malformed) AS \"malformed\", sum(ignored) AS \"ignored (healthchecks)\" {ps} GROUP BY 1 ORDER BY 1",
          12, 9, fmt="time_series")
    b.add("timeseries", "Batch duration (ms)", f"SELECT ts AS time, batch_ms AS \"batch ms\" {ps} AND events_ingested > 0 ORDER BY 1",
          12, 9, fmt="time_series", fieldConfig={"defaults": {"unit": "ms"}, "overrides": []})
    b.add("table", "Recent batches", f"SELECT ts AS \"Time (IST)\", lines_read AS \"Lines\", events_ingested AS \"Ingested\", "
          f"duplicates AS \"Dupes\", malformed AS \"Malformed\", oversized AS \"Oversized\", ignored AS \"Ignored\", "
          f"batch_ms AS \"ms\", db_errors AS \"DB errors\" {ps} ORDER BY ts DESC LIMIT 20", 14, 10)
    b.add("piechart", "Enrichment source (sessions)", "SELECT coalesce(geo_source,'none') AS metric, count(*) AS value "
          "FROM honeylens.sessions WHERE $__timeFilter(start_ts) GROUP BY 1", 5, 10,
          options={"reduceOptions": {"values": True, "calcs": ["lastNotNull"]}, "pieType": "donut",
                   "legend": {"displayMode": "list", "placement": "bottom"}})
    b.add("table", "Row counts", "SELECT 'raw_events' AS \"Table\", count(*) AS \"Rows\" FROM honeylens.raw_events UNION ALL "
          "SELECT 'sessions', count(*) FROM honeylens.sessions UNION ALL SELECT 'commands', count(*) FROM honeylens.commands "
          "UNION ALL SELECT 'attack_matches', count(*) FROM honeylens.attack_matches UNION ALL "
          "SELECT 'enrichment_cache', count(*) FROM honeylens.enrichment_cache", 5, 10)
    return b


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for board in (soc_overview(), creds_commands(), attack_behaviour(), session_explorer(), pipeline_health()):
        (OUT / board.file).write_text(json.dumps(board.to_json(), indent=2) + "\n", encoding="utf-8")
        print("wrote", board.file, len(board.panels), "panels")


if __name__ == "__main__":
    main()
