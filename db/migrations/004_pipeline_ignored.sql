-- 004_pipeline_ignored.sql : count events we deliberately ignore.
-- Added during testing: Docker's healthcheck opens a TCP connection to
-- Cowrie from 127.0.0.1 every 10 seconds, which Cowrie logs as a session.
-- The pipeline skips loopback-source events (HL_IGNORE_LOOPBACK=true) and
-- counts them here so nothing disappears silently.
-- New column = new migration file. Old files are never edited.
ALTER TABLE honeylens.pipeline_stats ADD COLUMN IF NOT EXISTS ignored INTEGER NOT NULL DEFAULT 0;
