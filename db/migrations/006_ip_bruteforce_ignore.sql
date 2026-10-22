-- 006_ip_bruteforce_ignore.sql : per-IP brute-force detection + HL_IGNORE_IPS.
-- New behaviour = new migration file. Old files are never edited.

-- 1. Sessions from the operator's own test/admin IPs (HL_IGNORE_IPS) stay in the
--    database (nothing is deleted) but are listed here and left out of reports,
--    IOC exports and dashboards. The pipeline adds rows at ingest;
--    honeylens-rescore refreshes the list after HL_IGNORE_IPS changes.
--    A side table (instead of a new column on sessions) keeps 002's
--    "SELECT s.*" view re-runnable, and gives every table ONE filter:
--      session_id NOT IN (SELECT session_id FROM honeylens.ignored_sessions)
--    The list is tiny, so PostgreSQL hashes it once per query.
CREATE TABLE IF NOT EXISTS honeylens.ignored_sessions (
    session_id  TEXT PRIMARY KEY REFERENCES honeylens.sessions (session_id) ON DELETE CASCADE,
    src_ip      INET,
    reason      TEXT NOT NULL DEFAULT 'HL_IGNORE_IPS',
    ignored_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Per-IP brute-force window: "failed logins from this IP between t-W and t+W".
--    A partial index on failed logins only keeps it small and makes the count an
--    index range scan (no full-table scan per session).
CREATE INDEX IF NOT EXISTS login_failed_ip_ts_idx ON honeylens.login_attempts (src_ip, ts) WHERE NOT success;
-- Finding earlier 'scanner' sessions of the same IP to upgrade after a burst.
CREATE INDEX IF NOT EXISTS sessions_ip_start_idx ON honeylens.sessions (src_ip, start_ts);

-- 3. Convenience view for ad-hoc SQL and custom panels: internet attackers only
--    (not simulated, not from an ignored IP).
CREATE OR REPLACE VIEW honeylens.real_sessions AS
SELECT s.* FROM honeylens.sessions s
WHERE NOT s.is_simulated
  AND s.session_id NOT IN (SELECT session_id FROM honeylens.ignored_sessions);

-- 005's default privileges already cover objects created here; explicit grants
-- keep this file correct on its own too.
GRANT SELECT, INSERT, UPDATE, DELETE ON honeylens.ignored_sessions TO hl_pipeline;
GRANT SELECT ON honeylens.ignored_sessions, honeylens.real_sessions TO hl_grafana, hl_report;
GRANT SELECT ON honeylens.real_sessions TO hl_pipeline;
