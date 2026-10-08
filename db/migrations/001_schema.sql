-- 001_schema.sql : core tables
-- Every statement uses IF NOT EXISTS so running the file twice is harmless
-- (idempotent). The migration runner also records each file in
-- honeylens.schema_migrations so it is normally applied only once.
--
-- Time rule: every timestamp column is TIMESTAMPTZ and stored in UTC.
-- Grafana and the report convert to Asia/Kolkata (IST) only for display.

CREATE SCHEMA IF NOT EXISTS honeylens;

CREATE TABLE IF NOT EXISTS honeylens.schema_migrations (
    version     TEXT PRIMARY KEY,
    checksum    TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every Cowrie event exactly as received (after size checks), as JSONB.
-- event_uid = SHA-256 of the raw line, so replaying a log file cannot create
-- duplicates (INSERT ... ON CONFLICT DO NOTHING).
CREATE TABLE IF NOT EXISTS honeylens.raw_events (
    id            BIGSERIAL PRIMARY KEY,
    event_uid     TEXT NOT NULL UNIQUE,
    eventid       TEXT NOT NULL,
    session_id    TEXT,
    src_ip        INET,
    ts            TIMESTAMPTZ NOT NULL,
    sensor        TEXT,
    is_simulated  BOOLEAN NOT NULL DEFAULT FALSE,
    payload       JSONB NOT NULL,
    source_file   TEXT,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS raw_events_ts_idx ON honeylens.raw_events (ts);
CREATE INDEX IF NOT EXISTS raw_events_session_idx ON honeylens.raw_events (session_id);
CREATE INDEX IF NOT EXISTS raw_events_eventid_idx ON honeylens.raw_events (eventid);

-- One row per SSH/Telnet connection (Cowrie "session"), rebuilt from events.
CREATE TABLE IF NOT EXISTS honeylens.sessions (
    session_id        TEXT PRIMARY KEY,
    src_ip            INET,
    src_port          INTEGER,
    dst_port          INTEGER,
    protocol          TEXT,
    sensor            TEXT,
    client_version    TEXT,
    hassh             TEXT,
    start_ts          TIMESTAMPTZ NOT NULL,
    end_ts            TIMESTAMPTZ,
    duration_s        DOUBLE PRECISION,
    login_attempts    INTEGER NOT NULL DEFAULT 0,
    login_failures    INTEGER NOT NULL DEFAULT 0,
    login_success     BOOLEAN NOT NULL DEFAULT FALSE,
    username          TEXT,
    commands_count    INTEGER NOT NULL DEFAULT 0,
    downloads_count   INTEGER NOT NULL DEFAULT 0,
    is_simulated      BOOLEAN NOT NULL DEFAULT FALSE,
    country_code      TEXT,
    country           TEXT,
    city              TEXT,
    asn               INTEGER,
    as_org            TEXT,
    lat               DOUBLE PRECISION,
    lon               DOUBLE PRECISION,
    geo_source        TEXT,
    classification    TEXT,
    severity          INTEGER CHECK (severity BETWEEN 0 AND 100),
    severity_label    TEXT,
    score_reasons     JSONB,
    actor_type        TEXT,          -- bot | human | unknown (timing heuristic)
    median_cmd_gap_s  DOUBLE PRECISION,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_start_idx ON honeylens.sessions (start_ts);
CREATE INDEX IF NOT EXISTS sessions_ip_idx ON honeylens.sessions (src_ip);
CREATE INDEX IF NOT EXISTS sessions_class_idx ON honeylens.sessions (classification);
CREATE INDEX IF NOT EXISTS sessions_sim_idx ON honeylens.sessions (is_simulated, start_ts);

CREATE TABLE IF NOT EXISTS honeylens.login_attempts (
    id            BIGSERIAL PRIMARY KEY,
    event_uid     TEXT NOT NULL UNIQUE,
    session_id    TEXT NOT NULL,
    ts            TIMESTAMPTZ NOT NULL,
    src_ip        INET,
    username      TEXT NOT NULL,
    password      TEXT NOT NULL,   -- fake honeypot credentials typed by attackers
    success       BOOLEAN NOT NULL,
    is_simulated  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS login_ts_idx ON honeylens.login_attempts (ts);
CREATE INDEX IF NOT EXISTS login_session_idx ON honeylens.login_attempts (session_id);

CREATE TABLE IF NOT EXISTS honeylens.commands (
    id            BIGSERIAL PRIMARY KEY,
    event_uid     TEXT NOT NULL UNIQUE,
    session_id    TEXT NOT NULL,
    ts            TIMESTAMPTZ NOT NULL,
    src_ip        INET,
    command       TEXT NOT NULL,
    known         BOOLEAN NOT NULL DEFAULT TRUE,  -- FALSE = Cowrie "command.failed"
    mapped        BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE = at least one ATT&CK rule fired
    is_simulated  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS commands_ts_idx ON honeylens.commands (ts);
CREATE INDEX IF NOT EXISTS commands_session_idx ON honeylens.commands (session_id);

-- URLs attackers TRIED to download. HoneyLens never fetches these.
CREATE TABLE IF NOT EXISTS honeylens.downloads (
    id            BIGSERIAL PRIMARY KEY,
    event_uid     TEXT NOT NULL UNIQUE,
    session_id    TEXT NOT NULL,
    ts            TIMESTAMPTZ NOT NULL,
    src_ip        INET,
    url           TEXT,
    url_host      TEXT,
    shasum        TEXT,
    outfile       TEXT,
    eventid       TEXT NOT NULL,
    is_simulated  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS downloads_ts_idx ON honeylens.downloads (ts);

CREATE TABLE IF NOT EXISTS honeylens.enrichment_cache (
    ip            INET PRIMARY KEY,
    country_code  TEXT,
    country       TEXT,
    city          TEXT,
    asn           INTEGER,
    as_org        TEXT,
    lat           DOUBLE PRECISION,
    lon           DOUBLE PRECISION,
    source        TEXT NOT NULL,
    is_private    BOOLEAN NOT NULL DEFAULT FALSE,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS honeylens.attack_matches (
    id              BIGSERIAL PRIMARY KEY,
    event_uid       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    rule_id         TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    is_simulated    BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (event_uid, rule_id)
);
CREATE INDEX IF NOT EXISTS attack_ts_idx ON honeylens.attack_matches (ts);
CREATE INDEX IF NOT EXISTS attack_session_idx ON honeylens.attack_matches (session_id);
CREATE INDEX IF NOT EXISTS attack_tech_idx ON honeylens.attack_matches (technique_id);

CREATE TABLE IF NOT EXISTS honeylens.session_summaries (
    session_id   TEXT PRIMARY KEY REFERENCES honeylens.sessions (session_id) ON DELETE CASCADE,
    summary      TEXT NOT NULL,
    techniques   TEXT[] NOT NULL DEFAULT '{}',
    tactics      TEXT[] NOT NULL DEFAULT '{}',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per pipeline flush: the pipeline's own health metrics.
CREATE TABLE IF NOT EXISTS honeylens.pipeline_stats (
    id                BIGSERIAL PRIMARY KEY,
    ts                TIMESTAMPTZ NOT NULL DEFAULT now(),
    lines_read        INTEGER NOT NULL DEFAULT 0,
    events_ingested   INTEGER NOT NULL DEFAULT 0,
    duplicates        INTEGER NOT NULL DEFAULT 0,
    malformed         INTEGER NOT NULL DEFAULT 0,
    oversized         INTEGER NOT NULL DEFAULT 0,
    sessions_updated  INTEGER NOT NULL DEFAULT 0,
    batch_ms          DOUBLE PRECISION,
    lag_bytes         BIGINT NOT NULL DEFAULT 0,
    files_tracked     INTEGER NOT NULL DEFAULT 0,
    db_errors         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS pipeline_stats_ts_idx ON honeylens.pipeline_stats (ts);

-- Read position in each log file. Updated in the SAME transaction as the
-- events, so after a crash we never skip or double-count lines.
CREATE TABLE IF NOT EXISTS honeylens.ingest_offsets (
    file_key     TEXT PRIMARY KEY,   -- "<device>:<inode>" survives renames during rotation
    path         TEXT NOT NULL,
    byte_offset  BIGINT NOT NULL,
    head_hash    TEXT,               -- hash of the first bytes, detects inode reuse
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
