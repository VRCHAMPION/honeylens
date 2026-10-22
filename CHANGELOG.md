# Changelog

All notable changes to HoneyLens. Dates are in IST.

## Unreleased - real-data fix pass

Fixes found by running HoneyLens on a real cloud VM (Azure for Students) for two weeks.

### Detection and scoring
- **Per-IP brute-force window.** SSH bots open one connection per password guess, so per-session
  counting labelled them `scanner`. A login-only session is now `brute-forcer` when its source IP
  made at least `HL_BRUTE_MIN_FAILURES` (default 20) failed logins within +/- `HL_BRUTE_WINDOW_MIN`
  (default 60) minutes across sessions (new score reason `ip_brute_force`, 5 points). Earlier
  sessions of an IP are upgraded once it crosses the threshold. Backed by new indexes (migration 006).
- **Download-and-execute scoring.** New reason `download_execute` (25 points) for a fetch piped into
  a shell, an `scp -i key user@host:path` pull, or `chmod +x`/`./run` after a fetch. One-command
  droppers now score high instead of medium. `login_success` is still counted once.
- **Honeypot-probe detection.** New rules for the shell-behaviour probe family (`===SHELL_BEHAVIOR===`,
  `./xxxxxx`, the `filter` test script) map to T1497.001 System Checks with high confidence, which
  classifies the session `honeypot-prober` regardless of command count. Droppers still outrank probers.
- **Command normalisation.** Rules also run on a normalised copy of each command: `/bin/./uname`,
  `/usr/bin//uname` and `./` prefixes collapse, and `echo -e`/`printf` `\xNN` escapes are decoded.
  The stored command text is unchanged.
- **New rules (70 total):** RouterOS `/ip ... print` (T1016) and `/system ... print` (T1082), bare
  `ps` (T1057), Telegram tdata / SMS-modem hunting and `locate` (T1083), download piped to a shell
  (T1059.004), `scp -i` pulls and `scp -t` uploads (T1105), `echo X | cat -n` liveness check (T1497.001).

### IOCs and reports
- URLs (http/https/ftp/tftp), scp sources (`user@host:path`) and IPv4s are extracted from command
  text into the IOC CSV, STIX bundle and HTML report (defanged), labelled "seen in command (never
  fetched)". Private/reserved addresses, `HL_SENSOR_IP` and `HL_IGNORE_IPS` are never exported.
- scp uploads (a local path in `downloads.url`) are exported as `file-path` rows, not URLs; their
  SHA-256 is kept.

### Operations
- **`HL_IGNORE_IPS`** (IPs/CIDRs): sessions from your own test machines are kept but listed in the new
  `honeylens.ignored_sessions` table and left out of reports, IOC exports and every Grafana panel.
  New view `honeylens.real_sessions` (not simulated, not ignored).
- **`honeylens-rescore`** (also `python -m honeylens.pipeline.rescore`): batch backfill that re-matches
  stored commands and recomputes class, severity, reasons, summaries and the ignore list. Idempotent,
  never touches raw data, `--dry-run` before/after summary, `--since`.
- Migration `006_ip_bruteforce_ignore.sql`.

### Docs
- Cloud deployment marked **VERIFIED** on Azure for Students (Standard B2ats_v2); Oracle and AWS
  instructions marked untested alternatives. New sections on updating a deployment, rescoring and
  `HL_IGNORE_IPS`. Removed a link to the deleted `docs/archive/`.

## 1.0.0 - 2026-10-09

First public release.
