# Data dictionary

All tables live in the PostgreSQL schema `honeylens`. Every timestamp is `TIMESTAMPTZ` stored in
**UTC**; Grafana and the report display **IST (Asia/Kolkata, UTC+05:30)**.
`is_simulated = TRUE` means the row came from the HoneyLens simulator (SIMULATED), `FALSE` means a
real source (REAL). Rule: RFC 5737 IP, private/loopback IP (default setting) or the synthetic flag ⇒ simulated.

## raw_events - every accepted Cowrie event

| Column | Type | Meaning |
|---|---|---|
| id | bigserial | row id |
| event_uid | text, unique | SHA-256 of the raw log line - replay protection |
| eventid | text | Cowrie event type, e.g. `cowrie.login.failed` |
| session_id | text | Cowrie session id (validated `[A-Za-z0-9_-]{1,64}`) |
| src_ip | inet | attacker IP (NULL if invalid) |
| ts | timestamptz | event time (UTC) |
| sensor | text | Cowrie sensor name |
| is_simulated | bool | see above |
| payload | jsonb | scrubbed copy of the whole event (control chars stripped, sizes limited) |
| source_file | text | log file path when read |
| ingested_at | timestamptz | when the pipeline stored it |

## sessions - one row per connection

| Column | Meaning |
|---|---|
| session_id (PK) | Cowrie session id |
| src_ip, src_port, dst_port, protocol, sensor | connection details |
| client_version | SSH client banner, e.g. `SSH-2.0-Go` (great bot fingerprint) |
| hassh | HASSH fingerprint of the client's key-exchange offer |
| start_ts, end_ts, duration_s | timing |
| login_attempts, login_failures, login_success, username | login facts (username = last successful) |
| commands_count | commands typed |
| downloads_count | download ATTEMPTS with a URL (never fetched) |
| country_code, country, city, asn, as_org, lat, lon, geo_source | enrichment (`demo` / `mmdb` / `api` / `local` / `none`) |
| classification | `scanner`, `brute-forcer`, `intruder`, `malware-dropper`, `cryptominer-like`, `honeypot-prober`, `unknown` |
| severity, severity_label | 0-100 score; low <25, medium 25-49, high 50-74, critical ≥75 |
| score_reasons | JSON list of `{rule, points, detail}` - why the score is what it is |
| actor_type, median_cmd_gap_s | bot / human / unknown from command timing |
| is_simulated, updated_at | flags |

## login_attempts

event_uid (unique), session_id, ts, src_ip, username, password (typed into a FAKE server), success, is_simulated.

## commands

event_uid (unique), session_id, ts, src_ip, command (sanitized, ≤4096 chars), known (FALSE = Cowrie
did not recognise the command), mapped (TRUE = at least one ATT&CK rule matched), is_simulated.

## downloads

event_uid, session_id, ts, src_ip, url, url_host, shasum (SHA-256 if Cowrie recorded one), outfile,
eventid (`cowrie.session.file_download[.failed]` / `file_upload`), is_simulated.
Rows with an empty `url` are files written by shell redirection, not downloads.

## attack_matches

event_uid + rule_id (unique together), session_id, ts, technique_id, technique_name, tactic,
confidence (high / medium / low), is_simulated.

## enrichment_cache

ip (PK), country_code, country, city, asn, as_org, lat, lon, source, is_private, fetched_at, expires_at (default 30 days).

## session_summaries

session_id (PK, FK → sessions, cascade delete), summary (one plain-English sentence, IP defanged),
techniques (text[]), tactics (text[]), updated_at.

## pipeline_stats - one row per batch + a heartbeat every 30 s

ts, lines_read, events_ingested, duplicates, malformed, oversized, ignored (loopback healthchecks),
sessions_updated, batch_ms, lag_bytes (unread bytes in tracked files), files_tracked, db_errors (since process start).

## ingest_offsets

file_key (PK, `device:inode`), path (latest name), byte_offset, head_hash (SHA-256 of the first 64
bytes, detects inode reuse), updated_at.

## schema_migrations

version (file name), checksum (SHA-256 of the file), applied_at.

## Views and functions

| Name | What |
|---|---|
| `v_unmapped_commands` | commands with no rule match, grouped, with counts and first/last seen |
| `v_credentials` | username/password pairs with counts |
| `v_session_overview` | sessions joined with summaries |
| `v_attack_daily` | technique counts per day |
| `apply_retention(keep_days)` | deletes data older than N days, returns rows deleted per table; ≤0 disables |

## Roles

| Role | Rights |
|---|---|
| `hl_pipeline` | SELECT/INSERT/UPDATE/DELETE on HoneyLens tables, EXECUTE apply_retention |
| `hl_grafana` | SELECT only; session forced read-only; 30 s statement timeout |
| `hl_report` | SELECT only; session forced read-only; 120 s statement timeout |
| `POSTGRES_USER` (admin) | owner; used only by the `migrate` job |
