-- 002_views_retention.sql : read-friendly views and the retention function
-- CREATE OR REPLACE makes these idempotent.

-- Commands no rule recognised: the "to-do list" for new detection rules.
CREATE OR REPLACE VIEW honeylens.v_unmapped_commands AS
SELECT command,
       count(*)                     AS times_seen,
       count(DISTINCT src_ip)       AS distinct_ips,
       min(ts)                      AS first_seen,
       max(ts)                      AS last_seen,
       bool_or(is_simulated)        AS any_simulated,
       bool_and(is_simulated)       AS all_simulated
FROM honeylens.commands
WHERE NOT mapped
GROUP BY command;

-- Credentials pairs with counts.
CREATE OR REPLACE VIEW honeylens.v_credentials AS
SELECT username, password, success, is_simulated,
       count(*) AS attempts, count(DISTINCT src_ip) AS distinct_ips,
       min(ts) AS first_seen, max(ts) AS last_seen
FROM honeylens.login_attempts
GROUP BY username, password, success, is_simulated;

-- Session list joined with its summary (used by Session Explorer + report).
CREATE OR REPLACE VIEW honeylens.v_session_overview AS
SELECT s.*, ss.summary, ss.techniques, ss.tactics
FROM honeylens.sessions s
LEFT JOIN honeylens.session_summaries ss USING (session_id);

-- Technique counts per day.
CREATE OR REPLACE VIEW honeylens.v_attack_daily AS
SELECT date_trunc('day', ts) AS day, technique_id, technique_name, tactic, is_simulated,
       count(*) AS matches, count(DISTINCT session_id) AS sessions
FROM honeylens.attack_matches
GROUP BY 1, 2, 3, 4, 5;

-- Retention: delete data older than keep_days. Returns rows deleted per table.
-- Why: honeypots collect a LOT of data; old raw events have little value and
-- fill the small free-tier disk. 0 or negative = keep everything.
CREATE OR REPLACE FUNCTION honeylens.apply_retention(keep_days INTEGER)
RETURNS TABLE (table_name TEXT, rows_deleted BIGINT)
LANGUAGE plpgsql AS $$
DECLARE
    cutoff TIMESTAMPTZ := now() - make_interval(days => keep_days);
    n BIGINT;
BEGIN
    IF keep_days IS NULL OR keep_days <= 0 THEN
        RETURN;
    END IF;
    DELETE FROM honeylens.raw_events WHERE ts < cutoff;            GET DIAGNOSTICS n = ROW_COUNT; table_name := 'raw_events';     rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.login_attempts WHERE ts < cutoff;        GET DIAGNOSTICS n = ROW_COUNT; table_name := 'login_attempts'; rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.commands WHERE ts < cutoff;              GET DIAGNOSTICS n = ROW_COUNT; table_name := 'commands';       rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.downloads WHERE ts < cutoff;             GET DIAGNOSTICS n = ROW_COUNT; table_name := 'downloads';      rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.attack_matches WHERE ts < cutoff;        GET DIAGNOSTICS n = ROW_COUNT; table_name := 'attack_matches'; rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.sessions WHERE start_ts < cutoff;        GET DIAGNOSTICS n = ROW_COUNT; table_name := 'sessions';       rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.pipeline_stats WHERE ts < cutoff;        GET DIAGNOSTICS n = ROW_COUNT; table_name := 'pipeline_stats'; rows_deleted := n; RETURN NEXT;
    DELETE FROM honeylens.enrichment_cache WHERE expires_at < now(); GET DIAGNOSTICS n = ROW_COUNT; table_name := 'enrichment_cache'; rows_deleted := n; RETURN NEXT;
END;
$$;
