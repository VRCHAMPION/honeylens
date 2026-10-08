# HoneyLens Final Release Audit

**Audit date:** 2026-10-08

**CURRENT VERDICT: HOSTED CI VERIFIED; CLOUD DEPLOYMENT AND THROUGHPUT REMAIN UNVERIFIED**

The private GitHub repository is [VRCHAMPION/honeylens](https://github.com/VRCHAMPION/honeylens).
Commit `b8602c9` passed [GitHub Actions run 37808655086](https://github.com/VRCHAMPION/honeylens/actions/runs/37808655086):
all four jobs succeeded. The PostgreSQL-backed pytest job passed 373 tests at 85.69% combined
coverage (the configured gate is 80%). Lint/static checks, the full-history Gitleaks scan, image
checks, Docker integration, and the generated-secret/package check also passed.

The non-gating Trivy report listed 44 HIGH/CRITICAL findings for `honeylens:1.0.0`; the separate
gate for fixed CRITICAL findings in that image passed. This is not a zero-vulnerability claim.
Cloud-provider behavior and the previously quoted throughput remain unverified, so this CI result
does not establish a deployed or production-validated release.

The final source tree contains 135 tracked files totaling 2,208,748 bytes. Its clean `honeylens-project.zip`
contains the same 135 paths, passes the ZIP integrity check, and passes the package secret-exposure
scan. The archive is kept outside the repository.

The numbered sections below preserve the initial Windows pre-push audit. Their staged/no-remote,
63.98% coverage, and locally blocked-service entries describe that earlier snapshot; the hosted
results above supersede those entries for checks exercised by GitHub Actions.

## 1. Repository and environment — initial local snapshot

| Item | Result |
|---|---|
| OS | **VERIFIED:** Windows 11 Home, x64, build 26200 |
| Python | **VERIFIED:** Python 3.11.9 in a fresh temporary venv; requires Python 3.11+ |
| Docker / Compose | **BLOCKED:** commands not found |
| PostgreSQL | **BLOCKED:** psql, pg_isready, service, and HL_TEST_PG unavailable |
| Grafana | **BLOCKED:** 12.4.12 is the configured image; no running service |
| Git | **VERIFIED:** local repository initialized on main; all candidate files staged |
| Commits / remote | **VERIFIED:** 0 commits, no remote; no history exists |
| Working-tree candidate | **VERIFIED:** exact staged inventory follows |
| Repository size | See matching current statistics in docs/GITHUB_AUDIT_REPORT.md |

**Repository statistics:** 135 staged candidate files; 2,204,626 bytes (2.102 MiB); 17 Markdown files. The repository has no
commit history, so these staged additions are the first reviewable candidate rather than a diff
against a commit.

The local Git initialization was explicitly requested by the continuation task. It creates no
fabricated history. The index is a first reviewable staging state only.

## 2. Git, staged files, and history

- git status --short --branch: **VERIFIED**, no commits yet on main; candidate files staged.
- .env.example: **VERIFIED** staged and not ignored.
- .env, .env.* except .env.example, .mmdb, databases, logs, archives, captures, private keys,
  .venv, .coverage, and caches: **VERIFIED** ignored by rules; generated cache entries are not staged.
- git diff --cached --check: **VERIFIED** after removing trailing whitespace and extra blank EOFs.
- Gitleaks history scan: **UNVERIFIED**; it reports 0 commits scanned. Do not interpret that as a
  clean history.
- Working-tree Gitleaks and synthetic canary: **VERIFIED**; no leaks found and the generated canary was detected.
- No remote was created and no commit, push, or history rewrite occurred.

## 3. Security findings and remaining risk

**Fixed in the candidate:** unsafe pre-firewall public startup ordering; incomplete .env.* filtering;
simulator DNS resolution before allowlist rejection; CSV spreadsheet formula bypass via leading
whitespace/BOM; non-finite JSON accepted before PostgreSQL JSONB; missing optional API egress for
the pipeline; stale Grafana PostgreSQL version metadata; vulnerable old setuptools floor; and
unsupported README coverage/throughput claims.

**Current secret results:** **VERIFIED**; Gitleaks directory scan, generated canary, and
scripts/check_secrets_exposure.py found no real secrets or forbidden runtime files. Fake Cowrie
credentials and CI-only database values are explicitly demo/test material. No real attacker dataset
was present. Historical secrets are **UNVERIFIED** because there are no commits.

**Remaining security verification:** Docker network and port enforcement, container runtime identity,
database grants, image vulnerabilities, cloud firewall behavior, and history exposure are not
runtime-verified. No specific remaining source-code vulnerability is asserted from these blocked
checks.

## 4. Python tests, skips, and coverage

Fresh isolated run on Python 3.11.9:

- **VERIFIED:** 373 collected; 321 passed; 52 skipped; 0 test failures.
- **FAILED:** combined branch/line coverage 63.98%, below configured --cov-fail-under=80.
- **VERIFIED:** Ruff all checks passed; Bandit exit 0 with annotation warnings only; pip-audit found
  no known vulnerabilities (the editable HoneyLens project is skipped by pip-audit).

The following table enumerates all 52 skipped test cases. BLOCKED means the test did not execute
because the required local service or OS privilege was unavailable.

| Test IDs | Status | Why | Required environment |
|---|---|---|---|
| tests/test_compose_hardening.py::test_service_groups_are_complete; test_common_hardening[cowrie,grafana,migrate,pipeline,postgres,report,report-scheduler,simulator,synthetic]; test_long_running_have_healthcheck_and_restart[cowrie,grafana,pipeline,postgres,report-scheduler]; test_one_shots_do_not_restart_or_healthcheck[migrate,report,simulator,synthetic]; test_non_root_users; test_only_postgres_adds_capabilities_and_only_minimum; tests/test_compose_safety.py::test_real_compose_files | **BLOCKED (22)** | Docker CLI unavailable | Docker Engine and Compose plugin |
| tests/test_db.py::test_first_run_applied_everything; test_second_and_third_run_are_noops; test_raw_sql_files_are_idempotent_on_their_own; test_changed_migration_is_detected; test_is_simulated_everywhere; test_pipeline_role_can_write; test_read_only_roles[hl_grafana,hl_report]; test_roles_are_not_superusers; test_weak_role_password_refused; test_retention_deletes_old_rows_only | **BLOCKED (11)** | HL_TEST_PG not set; PostgreSQL absent | disposable PostgreSQL test database |
| tests/test_pipeline_db.py::test_synthetic_end_to_end; test_replay_creates_no_duplicates_and_restart_resumes; test_rotation_malformed_oversized_hostile; test_outage_then_recovery; test_unique_session_counts_consistent; test_loopback_healthcheck_events_ignored | **BLOCKED (6)** | HL_TEST_PG not set; PostgreSQL absent | disposable PostgreSQL test database |
| tests/test_report.py::test_report_sections_and_escaping; test_week_over_week_has_both_weeks; test_mask_ips; test_csv_injection_neutralised; test_stix_bundle_shape; test_navigator_and_write_all; test_enrichment_cache_roundtrip; test_report_cli; test_no_attribution_language; test_scheduler_runs_real_report_at_monday_slot; test_stix_normal_output_valid_with_stix2_library; test_stix_masked_output_valid_with_stix2_library | **BLOCKED (12)** | HL_TEST_PG not set; PostgreSQL absent | disposable PostgreSQL test database |
| tests/test_tailer.py::test_symlinks_ignored | **BLOCKED (1)** | Windows denied symlink creation (WinError 1314) | Windows Developer Mode or elevated privileges |

Coverage is low primarily in migrate.py (24%), pipeline/runner.py (26%), pipeline/store.py (14%),
reporting/render.py (16%), reporting/data.py (47%), and reporting/exports.py (49%). The
database-backed test cases above are designed to exercise these paths. This audit does not claim
they passed.

## 5. Docker, PostgreSQL, integration, performance, and Grafana

| Check | Status | Result |
|---|---|---|
| Laptop/cloud Compose semantic validation | **BLOCKED** | no Docker CLI; only YAML syntax parsed with PyYAML |
| Configured published ports / actual docker ps bindings | **BLOCKED** | scripts/check_ports.py cannot spawn missing docker |
| Container users, capabilities, health, limits, logs, restart | **BLOCKED** | no Docker runtime |
| PostgreSQL migrations/idempotency/checksums/roles/grants/retention | **BLOCKED** | no server/client/test DSN |
| Read-only write-denial / offset rollback / outage recovery | **BLOCKED** | PostgreSQL integration tests did not execute |
| scripts/integration_test.py | **BLOCKED** | reviewed first: starts with docker compose down -v; not run without a disposable Docker stack |
| Start/end/duration/events/sessions/duplicates/malformed/oversized/recovery | **BLOCKED** | no integration run; no values fabricated |
| scripts/perf_test.py | **BLOCKED** | requires PostgreSQL and creates/drops a database |
| Grafana health/datasource/panels/variables/IST | **BLOCKED** | check script received connection refused at localhost:3000 |
| Simulator guard unit tests | **VERIFIED** | unit suite passed; rejected hostname is blocked before resolver use |
| Simulator live mode | **BLOCKED** | no controlled Compose Cowrie target; no public test targets were used |
| STIX/Navigator sample validation and ATT&CK rules | **VERIFIED** | see quality gates below |

The raw YAML syntax check parsed nine laptop services and three cloud-override services. This is not
equivalent to docker compose config, resolved-secret validation, or runtime port inspection.

## 6. Performance and image security

No new throughput result is available. The prior ~6,400 events/sec value remains **UNVERIFIED**.
OS/Python test metadata is recorded, but PostgreSQL version, event/session rates, and query latency
were not measured because the benchmark service is absent.

No image was built. **Trivy image scan: BLOCKED**: there are no built images or Docker daemon, so
high/critical counts and fixable counts are **not measured**, not zero. **Hadolint: BLOCKED**:
the configured CI invocation uses a Docker image and Docker is unavailable. **ShellCheck:
VERIFIED**, 0.11.0, all seven shell scripts, severity style. sh -n also passed all seven.

## 7. Reporting, static validation, and GitHub Actions

| Check | Status | Evidence |
|---|---|---|
| STIX 2.1 sample | **VERIFIED** | 112 indicators, 24 attack-patterns, 1 identity, 1 report |
| Navigator layers | **VERIFIED** | format 4.5; 29 and 53 technique entries |
| ATT&CK rules | **VERIFIED** | 60 rules validated |
| Markdown links/images | **VERIFIED** | final local scan result is recorded after report generation |
| AI/tool artifact sweep | **VERIFIED** | no accidental source/docs branding or prompt/tool artifacts; six PNGs have no text metadata |
| CI action/image pins | **VERIFIED (static)** | six action refs use full 40-character SHAs; three scanner images use SHA256 digests |
| CI workflow permissions | **VERIFIED (static)** | contents: read |
| CI runtime / 80% workflow gate | **UNVERIFIED** | no remote/hosted workflow execution; local threshold failed |
| Cloud firewall/provider behavior | **UNVERIFIED** | no cloud VM deployment |
| Cowrie userdb unit tests | **VERIFIED** | tests/test_cowrie_userdb.py: 4 passed |
| Cowrie userdb checker | **BLOCKED** | standalone script cannot import Cowrie because the package is not installed on this host |
| Pre-commit configuration | **VERIFIED** | pre-commit validate-config |

The workflow targets Python 3.12; pyproject.toml supports Python 3.11+, and this audit ran on 3.11.9.
This is within the supported range, but hosted execution on either version was not observed.

## 8. Release package and fresh-unzip verification

**VERIFIED: initial pre-push package** `scripts/package.sh` built the original candidate outside the repository with
a temporary Python standard-library ZIP shim because the host ZIP utility is unavailable. The ZIP
integrity check passed, it contains 135 files and all required paths, and forbidden entries counted
0. `scripts/check_secrets_exposure.py` passed against the final archive; the package script also ran
that check at build time. No archive is staged.

**VERIFIED: fresh-unzip checks** extracted to a new temporary directory with no hidden workspace
state. A clean Python 3.11.9 venv installed `.[dev]` using the Windows trust store; pip check passed.
From the extracted project, pytest reported 321 passed and 52 environment/privilege skips; Ruff,
STIX (112 indicators, 24 attack-patterns), both Navigator layers (29 and 53 entries), all 60 rules,
pre-commit config, Compose YAML syntax, shell syntax, and the project secret checker passed. The
Docker Compose semantic/runtime checks remain **BLOCKED**. A search found no absolute references to
the original workspace in the extracted files.

**Initial archive size:** 1,385,591 bytes (pre-push candidate ZIP, outside the repository under the
system temp folder). The current-branch archive is recorded with the current status at the top of
this audit.

### Commands and execution notes

```text
python -m pytest --cov=honeylens --cov-report=term-missing --cov-fail-under=80
ruff check .
bandit -q -c pyproject.toml -r src scripts
python -c "from pip._vendor import truststore; truststore.inject_into_ssl(); from pip_audit._cli import audit; audit()" --skip-editable --progress-spinner off
python scripts/check_secrets_exposure.py . --allow-local-env
gitleaks dir --redact --no-banner .
gitleaks git --redact --no-banner .
python scripts/check_cowrie_userdb.py
python scripts/check_ports.py
python scripts/check_grafana.py
shellcheck --severity=style scripts/*.sh deploy/*.sh
python -m pip check
python scripts/validate_stix.py docs/samples/iocs.stix.json
python scripts/validate_navigator.py docs/samples/attack-navigator-layer.json
python scripts/validate_navigator.py docs/samples/attack-navigator-coverage-layer.json
python -m honeylens.pipeline --check-rules
python -m pre_commit validate-config
sh scripts/package.sh "$OUTDIR"
python scripts/check_secrets_exposure.py "$OUTDIR/honeylens-project.zip"
```

`docker version` and `docker compose version` could not start because Docker is absent;
`check_ports.py` was likewise **BLOCKED**. `check_grafana.py` got connection refused at
localhost:3000. The integration script was read first and not run because it starts with
`docker compose down -v`; the performance script was not run because it creates/drops a database.
The Docker-dependent semantic Compose, runtime, Trivy-image, PostgreSQL, and Hadolint checks are
therefore **BLOCKED**, not passed. ShellCheck ran at style severity across the seven shell scripts.
```

## 9. Documentation, changes, and disposition

Documentation changes correct stale audit status and retain historical results in dated sections.
The README may claim verified repository counts (five dashboards, eight personas, 60 ATT&CK
rules / nine tactics / 45 techniques, and the explicitly scoped local test result). It must label
63.98% as local and below the CI gate. It may not present the old throughput as measured evidence or
describe samples as real attacker data.

No application source was deleted. The earlier audit removed 13 generated paths (.venv/,
src/honeylens.egg-info/, .pytest_cache/, .ruff_cache/, .coverage, and eight __pycache__/
directories); regenerated caches from this verification are removed before final inventory.
Intentional Cowrie fake credentials, six screenshots, sample HTML/CSV/STIX/Navigator data, MITRE
snapshot, licenses and attribution remain in the candidate.

### Initial staged-file inventory (before push)

| PATH | TYPE | SIZE (bytes) | TRACKED/STAGED | REASON |
|---|---|---:|---|---|
| `.dockerignore` | Config | 850 | STAGED (new) | Project build, container, or repository configuration |
| `.editorconfig` | Config | 283 | STAGED (new) | Project build, container, or repository configuration |
| `.env.example` | Env template | 1,841 | STAGED (new) | Safe placeholder-only environment template |
| `.gitattributes` | Config | 413 | STAGED (new) | Project build, container, or repository configuration |
| `.github/workflows/ci.yml` | YAML | 6,180 | STAGED (new) | Pinned GitHub Actions workflow |
| `.gitignore` | Config | 1,026 | STAGED (new) | Project build, container, or repository configuration |
| `.pre-commit-config.yaml` | YAML | 1,258 | STAGED (new) | Project build, container, or repository configuration |
| `DEPLOY_CLOUD.md` | Markdown | 20,474 | STAGED (new) | Project build, container, or repository configuration |
| `Dockerfile` | Dockerfile | 1,879 | STAGED (new) | Project build, container, or repository configuration |
| `LICENSE` | License | 1,347 | STAGED (new) | Project license and attribution |
| `README.md` | Markdown | 8,563 | STAGED (new) | Project build, container, or repository configuration |
| `RUN_ON_LAPTOP.md` | Markdown | 5,068 | STAGED (new) | Project build, container, or repository configuration |
| `SECURITY.md` | Markdown | 6,888 | STAGED (new) | Project build, container, or repository configuration |
| `cowrie/README.md` | Markdown | 908 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/cowrie.cfg` | CFG | 2,794 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/honeyfs/etc/hostname` | Config | 12 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/honeyfs/etc/issue` | Config | 26 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/honeyfs/etc/motd` | Config | 286 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/honeyfs/etc/os-release` | Config | 267 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `cowrie/userdb.txt` | Text | 693 | STAGED (new) | Cowrie configuration and fake/demo filesystem |
| `db/migrations/001_schema.sql` | SQL | 7,841 | STAGED (new) | PostgreSQL schema and migrations |
| `db/migrations/002_views_retention.sql` | SQL | 3,392 | STAGED (new) | PostgreSQL schema and migrations |
| `db/migrations/003_grants.sql` | SQL | 1,490 | STAGED (new) | PostgreSQL schema and migrations |
| `db/migrations/004_pipeline_ignored.sql` | SQL | 503 | STAGED (new) | PostgreSQL schema and migrations |
| `deploy/README.md` | Markdown | 996 | STAGED (new) | Operator/cloud deployment support |
| `deploy/backup.sh` | POSIX shell | 1,144 | STAGED (new) | Operator/cloud deployment support |
| `deploy/disk-guard.sh` | POSIX shell | 779 | STAGED (new) | Operator/cloud deployment support |
| `deploy/egress-lockdown.sh` | POSIX shell | 2,253 | STAGED (new) | Operator/cloud deployment support |
| `deploy/move-admin-ssh.sh` | POSIX shell | 1,353 | STAGED (new) | Operator/cloud deployment support |
| `deploy/verify-egress.sh` | POSIX shell | 3,800 | STAGED (new) | Operator/cloud deployment support |
| `docker-compose.cloud.yml` | YAML | 1,442 | STAGED (new) | Project build, container, or repository configuration |
| `docker-compose.yml` | YAML | 11,347 | STAGED (new) | Project build, container, or repository configuration |
| `docs/ANALYST_PLAYBOOK.md` | Markdown | 3,653 | STAGED (new) | Project, security, or audit documentation |
| `docs/ARCHITECTURE.md` | Markdown | 7,672 | STAGED (new) | Project, security, or audit documentation |
| `docs/DATA_DICTIONARY.md` | Markdown | 4,658 | STAGED (new) | Project, security, or audit documentation |
| `docs/FINAL_RELEASE_AUDIT.md` | Markdown | 30,347 | STAGED (new) | Project, security, or audit documentation |
| `docs/FINDINGS_TEMPLATE.md` | Markdown | 1,347 | STAGED (new) | Project, security, or audit documentation |
| `docs/GITHUB_AUDIT_REPORT.md` | Markdown | 28,921 | STAGED (new) | Project, security, or audit documentation |
| `docs/MITRE_COVERAGE.md` | Markdown | 12,863 | STAGED (new) | Project, security, or audit documentation |
| `docs/PROJECT_DEEP_DIVE.md` | Markdown | 31,068 | STAGED (new) | Project, security, or audit documentation |
| `docs/THREAT_MODEL.md` | Markdown | 5,378 | STAGED (new) | Project, security, or audit documentation |
| `docs/samples/README.md` | Markdown | 838 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/attack-navigator-coverage-layer.json` | JSON | 9,068 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/attack-navigator-layer.json` | JSON | 5,242 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/iocs.csv` | CSV | 14,521 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/iocs.stix.json` | JSON | 95,452 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/synthetic-cowrie-events-sample.json` | JSON | 67,334 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/weekly-report-masked.html` | HTML | 27,969 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/samples/weekly-report.html` | HTML | 30,401 | STAGED (new) | Intentional SIMULATED sample/export |
| `docs/screenshots/01-soc-overview.png` | PNG image | 253,244 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/02-credentials-commands.png` | PNG image | 139,887 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/03-attack-behaviour.png` | PNG image | 211,419 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/04-session-explorer.png` | PNG image | 253,608 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/05-pipeline-health.png` | PNG image | 143,821 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/06-weekly-report.png` | PNG image | 157,063 | STAGED (new) | Intentional dashboard/report screenshot |
| `docs/screenshots/README.md` | Markdown | 218 | STAGED (new) | Intentional dashboard/report screenshot |
| `grafana/dashboards/01-soc-overview.json` | JSON | 28,660 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/dashboards/02-credentials-commands.json` | JSON | 12,422 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/dashboards/03-attack-behaviour.json` | JSON | 11,913 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/dashboards/04-session-explorer.json` | JSON | 13,483 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/dashboards/05-pipeline-health.json` | JSON | 16,226 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/provisioning/dashboards/honeylens.yml` | YAML | 401 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `grafana/provisioning/datasources/honeylens.yml` | YAML | 728 | STAGED (new) | Grafana provisioning and SQL-backed dashboards |
| `pyproject.toml` | TOML | 2,669 | STAGED (new) | Project build, container, or repository configuration |
| `scripts/build_dashboards.py` | Python | 24,097 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/capture_screenshots.py` | Python | 3,168 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/check_cowrie_userdb.py` | Python | 1,293 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/check_grafana.py` | Python | 5,295 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/check_ports.py` | Python | 5,393 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/check_secrets_exposure.py` | Python | 5,630 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/download_geoip.sh` | POSIX shell | 1,161 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/gen_mitre_coverage.py` | Python | 5,012 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/integration_test.py` | Python | 16,060 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/make_env.py` | Python | 1,198 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/package.sh` | POSIX shell | 2,291 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/perf_test.py` | Python | 3,482 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/trivy_summary.py` | Python | 2,019 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/update_attack_snapshot.py` | Python | 3,655 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/validate_navigator.py` | Python | 3,990 | STAGED (new) | Build, validation, packaging, or operator utility |
| `scripts/validate_stix.py` | Python | 2,355 | STAGED (new) | Build, validation, packaging, or operator utility |
| `src/honeylens/__init__.py` | Python | 558 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/config.py` | Python | 3,795 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/enrich/__init__.py` | Python | 0 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/enrich/geo.py` | Python | 14,021 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/logutil.py` | Python | 1,648 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/migrate.py` | Python | 4,997 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/mitre/__init__.py` | Python | 0 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/mitre/attack.py` | Python | 8,301 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/mitre/data/enterprise-attack-19.2.min.json` | JSON | 151,417 | STAGED (new) | Bundled offline ATT&CK reference snapshot |
| `src/honeylens/mitre/rules.yaml` | YAML | 24,244 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/__init__.py` | Python | 0 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/__main__.py` | Python | 120 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/events.py` | Python | 7,295 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/runner.py` | Python | 9,681 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/sanitize.py` | Python | 3,864 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/scoring.py` | Python | 5,953 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/store.py` | Python | 14,028 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/pipeline/tailer.py` | Python | 8,410 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/__init__.py` | Python | 0 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/__main__.py` | Python | 119 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/cli.py` | Python | 2,024 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/data.py` | Python | 8,409 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/exports.py` | Python | 6,567 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/render.py` | Python | 8,204 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/scheduler.py` | Python | 6,986 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/reporting/templates/weekly.html` | HTML | 11,831 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/secretcheck.py` | Python | 3,605 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/__init__.py` | Python | 0 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/__main__.py` | Python | 119 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/cli.py` | Python | 3,574 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/guard.py` | Python | 3,266 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/live.py` | Python | 3,942 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/personas.py` | Python | 6,117 | STAGED (new) | HoneyLens application runtime source |
| `src/honeylens/simulator/synthetic.py` | Python | 5,020 | STAGED (new) | HoneyLens application runtime source |
| `tests/__init__.py` | Python | 0 | STAGED (new) | Automated regression and integration tests |
| `tests/conftest.py` | Python | 2,678 | STAGED (new) | Automated regression and integration tests |
| `tests/test_compose_hardening.py` | Python | 2,949 | STAGED (new) | Automated regression and integration tests |
| `tests/test_compose_safety.py` | Python | 3,080 | STAGED (new) | Automated regression and integration tests |
| `tests/test_cowrie_userdb.py` | Python | 1,781 | STAGED (new) | Automated regression and integration tests |
| `tests/test_db.py` | Python | 5,002 | STAGED (new) | Automated regression and integration tests |
| `tests/test_enrich.py` | Python | 1,489 | STAGED (new) | Automated regression and integration tests |
| `tests/test_enrich_api_limits.py` | Python | 4,609 | STAGED (new) | Automated regression and integration tests |
| `tests/test_events_scoring.py` | Python | 4,278 | STAGED (new) | Automated regression and integration tests |
| `tests/test_exports.py` | Python | 852 | STAGED (new) | Automated regression and integration tests |
| `tests/test_navigator_validation.py` | Python | 2,120 | STAGED (new) | Automated regression and integration tests |
| `tests/test_pipeline_db.py` | Python | 6,901 | STAGED (new) | Automated regression and integration tests |
| `tests/test_report.py` | Python | 8,153 | STAGED (new) | Automated regression and integration tests |
| `tests/test_rules.py` | Python | 3,574 | STAGED (new) | Automated regression and integration tests |
| `tests/test_sanitize.py` | Python | 1,441 | STAGED (new) | Automated regression and integration tests |
| `tests/test_scheduler.py` | Python | 4,193 | STAGED (new) | Automated regression and integration tests |
| `tests/test_secretcheck.py` | Python | 4,052 | STAGED (new) | Automated regression and integration tests |
| `tests/test_secrets_exposure.py` | Python | 4,644 | STAGED (new) | Automated regression and integration tests |
| `tests/test_simulator.py` | Python | 3,848 | STAGED (new) | Automated regression and integration tests |
| `tests/test_stix_validation.py` | Python | 1,860 | STAGED (new) | Automated regression and integration tests |
| `tests/test_tailer.py` | Python | 3,018 | STAGED (new) | Automated regression and integration tests |

## 14. Remaining verification boundaries

- **VERIFIED:** hosted CI, PostgreSQL-backed pytest and migrations, Docker Compose safety and
  integration, Grafana datasource/panels, generated exports, full-history Gitleaks, and the
  configured Trivy critical-fix gate, as recorded above.
- **UNVERIFIED:** cloud-provider deployment/firewall behavior and the historical throughput claim.
- Review the Trivy HIGH/CRITICAL findings before making broader vulnerability claims; the configured
  fixed-CRITICAL gate is narrower than an all-findings clean bill of health.
