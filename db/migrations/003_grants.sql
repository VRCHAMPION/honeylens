-- 003_grants.sql : least-privilege permissions
-- The three LOGIN roles are created (with passwords from .env) by the migration
-- runner BEFORE this file runs, because SQL files must never contain secrets.
--
--   hl_pipeline  read + write  (the only role that can change data)
--   hl_grafana   read only     (dashboards)
--   hl_report    read only     (weekly report / IOC exports)
--
-- Why separate roles: if Grafana is ever compromised, the attacker can read
-- honeypot data but cannot delete or poison it.

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA honeylens FROM PUBLIC;

GRANT USAGE ON SCHEMA honeylens TO hl_pipeline, hl_grafana, hl_report;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA honeylens TO hl_pipeline;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA honeylens TO hl_pipeline;
GRANT EXECUTE ON FUNCTION honeylens.apply_retention(INTEGER) TO hl_pipeline;
REVOKE ALL ON honeylens.schema_migrations FROM hl_pipeline;
GRANT SELECT ON honeylens.schema_migrations TO hl_pipeline;

GRANT SELECT ON ALL TABLES IN SCHEMA honeylens TO hl_grafana, hl_report;
REVOKE EXECUTE ON FUNCTION honeylens.apply_retention(INTEGER) FROM PUBLIC;

-- Read-only roles: also block writes at the session level as a second lock.
ALTER ROLE hl_grafana SET default_transaction_read_only = on;
ALTER ROLE hl_report  SET default_transaction_read_only = on;
ALTER ROLE hl_grafana SET statement_timeout = '30s';
ALTER ROLE hl_report  SET statement_timeout = '120s';
