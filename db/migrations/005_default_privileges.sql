-- 005_default_privileges.sql : grants for tables added by FUTURE migrations.
-- 003_grants.sql grants on tables that existed when it ran ("ON ALL TABLES").
-- A table created later would get no grants, so the pipeline could not write
-- it and Grafana/the report could not read it. Default privileges fix that for
-- every table/sequence the migration role creates in the honeylens schema from
-- now on. The same least-privilege split as 003 applies.
-- New behaviour = new migration file. Old files are never edited.
ALTER DEFAULT PRIVILEGES IN SCHEMA honeylens
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hl_pipeline;
ALTER DEFAULT PRIVILEGES IN SCHEMA honeylens
    GRANT USAGE, SELECT ON SEQUENCES TO hl_pipeline;
ALTER DEFAULT PRIVILEGES IN SCHEMA honeylens
    GRANT SELECT ON TABLES TO hl_grafana, hl_report;
