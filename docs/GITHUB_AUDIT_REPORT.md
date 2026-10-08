# HoneyLens GitHub Readiness Audit

**Audit date:** 2026-10-08

**Scope:** HoneyLens project root and the staged GitHub candidate
**Verdict:** **NOT READY to claim a verified release.** The local repository is initialized on
main with a reviewable staged candidate and no commit or remote. The working-tree secret scan is
clean, but the 80% CI coverage gate failed at 63.98%; Docker, PostgreSQL integration, hosted CI, and
historical secret exposure remain blocked or unverified.

## Executive verdict

HoneyLens is a coherent, deliberately scoped SSH honeypot analytics project. The included
screenshots and examples are clearly simulated, dependencies are pinned, SQL uses bound values,
viewing roles are read-only, and the runtime configuration aims to limit ports and privileges.
The audit found and fixed concrete gaps in secret-file filtering, CSV spreadsheet safety, hostile
JSON numbers, simulator DNS behavior, optional API egress, cloud firewall order, Gitleaks CI, and
documentation claims.

The current staged tree is suitable for review. A public push should wait until the
Compose/cloud configuration and package workflow are validated in a Docker-enabled environment
and GitHub CI passes its 80% coverage gate. The empty main branch has no commit history or remote
to inspect. The candidate is staged; no commit, push, or history rewrite was performed.

## Repository statistics

Counts are from the staged candidate working tree, excluding Git internals and ignored runtime caches.

| Measure | Result |
|---|---:|
| Candidate files | 135 |
| Total size | 2.102 MiB / 2,204,626 bytes (under the 25 MB target) |
| Python files | 66: 31 application modules, 19 test modules, 14 utility scripts, and 2 test support modules |
| Markdown files | 17, including this report, deep dive, and release audit |
| SQL migrations | 4 |
| Compose files | 2 |
| Grafana dashboards | 5 |
| Screenshots | 6, approximately 1.10 MiB total |
| `.git` directories | 0 |
| Files matching known secret/runtime artifact patterns | 0 in the final tree |

The six screenshots are the largest directory by bytes and are useful dashboard/report previews.
The bundled 151,417-byte ATT&CK v19.2 snapshot supports offline rule validation. Sample exports
include a 95,452-byte STIX bundle and 67,334-byte synthetic Cowrie event set. These are intentional
and all are well within the repository size budget.

### Largest 20 files

Sizes in bytes; paths are relative to the repository root.

| File | Bytes | Disposition |
|---|---:|---|
| `docs/screenshots/04-session-explorer.png` | 253,608 | Keep, generated but intentional |
| `docs/screenshots/01-soc-overview.png` | 253,244 | Keep, generated but intentional |
| `docs/screenshots/03-attack-behaviour.png` | 211,419 | Keep, generated but intentional |
| `docs/screenshots/06-weekly-report.png` | 157,063 | Keep, generated but intentional |
| `src/honeylens/mitre/data/enterprise-attack-19.2.min.json` | 151,417 | Keep |
| `docs/screenshots/05-pipeline-health.png` | 143,821 | Keep, generated but intentional |
| `docs/screenshots/02-credentials-commands.png` | 139,887 | Keep, generated but intentional |
| `docs/samples/iocs.stix.json` | 95,452 | Keep |
| `docs/samples/synthetic-cowrie-events-sample.json` | 67,334 | Keep |
| `docs/PROJECT_DEEP_DIVE.md` | 31,068 | Keep |
| `docs/samples/weekly-report.html` | 30,401 | Keep |
| `docs/FINAL_RELEASE_AUDIT.md` | 30,347 | Keep |
| `docs/GITHUB_AUDIT_REPORT.md` | 28,921 | Keep |
| `grafana/dashboards/01-soc-overview.json` | 28,660 | Keep |
| `docs/samples/weekly-report-masked.html` | 27,969 | Keep |
| `src/honeylens/mitre/rules.yaml` | 24,244 | Keep |
| `scripts/build_dashboards.py` | 24,097 | Keep |
| `DEPLOY_CLOUD.md` | 20,474 | Keep |
| `grafana/dashboards/05-pipeline-health.json` | 16,226 | Keep |
| `scripts/integration_test.py` | 16,060 | Keep |

### Largest 20 directories

Recursive byte totals; parent directories include child contents.

| Directory | Bytes |
|---|---:|
| `docs/` | 1,535,992 |
| `docs/screenshots/` | 1,159,260 |
| `src/` | 328,115 |
| `src/honeylens/` | 328,115 |
| `docs/samples/` | 250,825 |
| `src/honeylens/mitre/` | 183,962 |
| `src/honeylens/mitre/data/` | 151,417 |
| `scripts/` | 86,099 |
| `grafana/` | 83,833 |
| `grafana/dashboards/` | 82,704 |
| `tests/` | 70,522 |
| `src/honeylens/pipeline/` | 49,351 |
| `src/honeylens/reporting/` | 44,140 |
| `src/honeylens/simulator/` | 22,038 |
| `src/honeylens/enrich/` | 14,021 |
| `db/` | 13,226 |
| `db/migrations/` | 13,226 |
| `src/honeylens/reporting/templates/` | 11,831 |
| `deploy/` | 10,325 |
| `.github/` | 6,180 |

## Files kept, ignored, removed, and investigated

### Kept

- **Application and runtime:** `src/honeylens/`, `Dockerfile`, both Compose files, `pyproject.toml`,
  `db/migrations/`, `grafana/`, and `cowrie/`.
- **Engineering and deployment:** `scripts/`, `deploy/`, `.github/workflows/ci.yml`,
  `.pre-commit-config.yaml`, `.gitattributes`, `.editorconfig`, `.dockerignore`, and `.gitignore`.
- **Tests:** all 19 `tests/test_*.py` modules and test fixtures.
- **Documentation and license:** root Markdown, `docs/*.md`, `docs/samples/README.md`,
  `docs/screenshots/README.md`, `LICENSE`, and the new project explanation/audit reports.
- **Generated but intentional:** six dashboard/report screenshots; the compact ATT&CK snapshot;
  generated ATT&CK coverage documentation and Navigator layer; sample HTML reports, IOC CSV/STIX,
  Navigator layers, and the explicitly simulated event file. These are not disposable caches.
- **Environment template:** `.env.example` contains placeholders and remains eligible for GitHub.

### Ignore

There are **0 ignored local artifacts remaining in the final working tree**. The updated
`.gitignore` and `.dockerignore` now cover `.env` and `.env.*`, keys/certificates, local credentials,
GeoIP databases, logs, captures, output/report folders, database files, archives, Terraform state,
Docker credentials, Python/build/test caches, virtual environments, OS metadata, and IDE state.
`.env.example` is explicitly re-included in `.gitignore` and intentionally omitted from the Docker
build context. Required docs, screenshots, the ATT&CK snapshot, and sample exports are not excluded.

The packaging script excludes local environment variants and restores only `.env.example`; its
result is scanned by `check_secrets_exposure.py`. At the time of the earlier audit, packaging was
not run because no ZIP utility was installed. The final verification below records the later build
using a temporary standard-library ZIP shim outside the repository.

### Removed during this audit

No application source, test, screenshot, sample, or documentation file was removed. I removed
13 generated audit paths: `.venv/`, `src/honeylens.egg-info/`, `.pytest_cache/`, `.ruff_cache/`,
`.coverage`, and eight `__pycache__/` directories. The first five paths contained 911 files in
total; the number of `.pyc` files inside the eight cache directories was not retained. The
temporary virtual environment used for checks is outside the repository under the system temp
directory.

### Investigate

No remaining candidate file has an unexplained purpose. Git is initialized on main with no commits
or remote; historical source-control state does not exist in this workspace.

## Security findings

No real secret value, private key, GeoIP database, `.env` file, local database, large log, or
captured real attacker dataset was found in the final workspace scan. Fake Cowrie passwords and
the commented throwaway CI database credential are test/demo material; they are not production
credentials. The secret exposure script reported no local `.env` values because there is no local
`.env` file.

| Severity | Finding | Status |
|---|---|---|
| **HIGH** | CI and pre-commit pinned Gitleaks 8.30.1; an upstream report describes default secret matches silently failing in that release. | Fixed by pinning Gitleaks 8.30.0 to a published GHCR digest in CI, using v8.30.0 for pre-commit, and adding a generated-token canary check before history scanning. The local Windows 8.30.0 binary matched the synthetic canary. Upstream report: [Gitleaks issue 2170](https://github.com/gitleaks/gitleaks/issues/2170). |
| **HIGH** | Cloud guide started publicly published Cowrie before applying host egress rules. | Fixed: the guide and script comments now apply the firewall before `docker compose up`; runtime behavior remains **UNVERIFIED** on a cloud host. |
| **MEDIUM** | `.env.*` variants other than `.env.example` were not consistently ignored, rejected by the exposure scanner, or excluded from packages. | Fixed in `.gitignore`, the scanner, and `package.sh`; regression tests cover `.env.production`, nested environment files, and the safe template. |
| **MEDIUM** | Unapproved simulator hostnames were sent to DNS before the destination was rejected. | Fixed: unapproved names are rejected before resolver use; a resolver-must-not-run regression test passes. |
| **MEDIUM** | Spreadsheet formula values with leading whitespace or a BOM could bypass the CSV prefix check. | Fixed and covered by standalone CSV export tests. |
| **MEDIUM** | Python's JSON decoder accepted `NaN`, `Infinity`, and overflow-to-infinity floats that PostgreSQL JSONB cannot store. | Fixed by rejecting non-finite values at parse time; regression tests pass. |
| **MEDIUM** | Internal laptop networking prevented the optional configured IPInfo provider from reaching its API. | Fixed in Compose: only the pipeline joins the new normal `egress` network; Cowrie/simulator/Grafana remain on the internal edge. Actual routes need Docker verification. |
| **LOW** | Grafana provisioned PostgreSQL server-version metadata said 17 while Compose uses PostgreSQL 18. | Removed the stale override so Grafana can detect the connected server version. |
| **INFO** | README's former 85% coverage and ~6,400 events/second statements were not supported by a reproducible result in this workspace. | Replaced with measured local test/coverage results and **UNVERIFIED** benchmark language. |
| **INFO** | The dashboard datasource, image tags, and cloud runtime cannot be exercised without Docker; DB migrations/roles need PostgreSQL. | Unverified checks are listed below; no runtime pass is claimed. |
| **INFO** | Build tooling initially included ambient `setuptools` 65.5.0, which `pip-audit` reported with four advisory IDs. | Fixed by raising the build/dev minimum to 83.0.0; `pip-audit --skip-editable` then reported no known vulnerabilities. |

### Scanner results

- `gitleaks 8.30.0 dir --redact .`: **PASS**, no leaks in the directory scan.
- Gitleaks synthetic-canary check: **PASS**; generated test token was detected with a redacted report.
- `python scripts/check_secrets_exposure.py . --allow-local-env`: **PASS**; no forbidden files,
  private-key material, resolved Compose output, or supplied local secret values.
- `pip-audit --skip-editable`: **PASS** after updating the audit environment to `setuptools 84.0.0`;
  no known vulnerabilities reported. The editable HoneyLens install is skipped by pip-audit.
- Git history secret scan: **UNVERIFIED**, because Git history is absent.
- Trivy, ShellCheck, Hadolint, Docker Compose config, running-container port inspection, and the
  release ZIP build: **UNVERIFIED** here; the required local executables are absent.

## Test results and coverage

Final pytest run on Windows with Python 3.11.9 is the source for README numbers:

| Result | Count | Reason/scope |
|---|---:|---|
| Collected | 373 | Includes parametrized cases. |
| Passed | 321 | Local unit/static and supported test cases. |
| Skipped | 52 | 29 database tests require a PostgreSQL test DSN; 22 Docker/Compose checks require Docker; one symlink creation requires Windows Developer Mode or elevated privileges. |
| Failed | 0 | — |
| Combined line/branch coverage | 64% | Local report while the PostgreSQL/Docker cases above were skipped. |

The local 64% result does not prove the workflow's 80% gate. GitHub CI defines a PostgreSQL service
for its tests, but only a hosted workflow run can establish the final coverage result.

### Test inventory

- **Parsing, sanitization, scoring:** `test_events_scoring.py`, `test_sanitize.py`.
- **ATT&CK detection and Navigator:** `test_rules.py`, `test_navigator_validation.py`.
- **Simulator/personas/Cowrie fake credentials:** `test_simulator.py`, `test_cowrie_userdb.py`.
- **Enrichment/privacy/rate limits:** `test_enrich.py`, `test_enrich_api_limits.py`.
- **Tail/recovery behavior:** `test_tailer.py` covers complete/partial lines, oversized lines,
  symlink handling, and file rename/rotation behavior.
- **Database, roles, migration, pipeline, and report:** `test_db.py`, `test_pipeline_db.py`,
  `test_report.py`; all need `HL_TEST_PG` and were skipped here.
- **Report/export safety:** standalone `test_exports.py`; DB-backed `test_report.py`; STIX
  validation in `test_stix_validation.py`.
- **Secret handling and Compose policy:** `test_secretcheck.py`, `test_secrets_exposure.py`,
  `test_compose_safety.py`, `test_compose_hardening.py`.
- **Scheduling:** `test_scheduler.py`.
- **Integration/performance:** `scripts/integration_test.py` and `scripts/perf_test.py` are
  operational scripts rather than pytest modules. Neither was run; integration starts by deleting
  Compose volumes unless `--keep` is supplied, and performance creates/drops a temporary database.

Untested-in-this-environment critical paths include PostgreSQL outage/restart recovery, actual
database role permissions, migration ordering on PostgreSQL, Grafana panel queries, Docker port
bindings, host firewall packet counters, and cloud-provider ingress/egress.

## Documentation and artifact audit

I read every Markdown document present: root README/setup/security/cloud files, architecture,
threat model, data dictionary, analyst playbook, ATT&CK coverage, findings template, and the Cowrie,
deployment, screenshot, and sample directories' READMEs. The requested `CHANGES`, `TEST_REPORT`,
`PROGRESS`, `INTERVIEW_PREP`, `DEMO_VIDEO_SCRIPT`, `RESUME_AND_LINKEDIN`, and `GITHUB_SETUP` files
do not exist; none is referenced as an existing document.

Fixed documentation/configuration truth gaps:

- README now reports 373 collected, 321 passed, 52 skipped, and 63.98% local line/branch coverage,
  with scope. It marks the old throughput number and real-session count **UNVERIFIED**.
- README now has verified counts for dashboards/personas/rules/tactics/techniques and adds
  limitations and roadmap sections.
- Architecture/security/threat docs describe the internal edge, pipeline-only optional API
  egress, simulator pre-DNS rejection, and CSV formula guard.
- Cloud guide applies egress rules before public Cowrie startup, documents AWS Organizations Free
  plan impact, and now labels local/cloud runtime validation **UNVERIFIED** for this audit.
- Deployment helper docs no longer claim ShellCheck or Docker tests were rerun in this environment.
- The weekly report methodology includes conditional DB-IP Lite attribution.
- Grafana datasource no longer claims PostgreSQL 17 metadata against PostgreSQL 18.
- Added [PROJECT_DEEP_DIVE.md](PROJECT_DEEP_DIVE.md), covering data flow, components, tables,
  dashboards, technologies, threat controls, limitations, tests, performance, use cases, and
  interview summaries.

Remaining inconsistencies/limits: image tags are versioned but not content-digest pinned; the
Docker base image performs an apt upgrade at build time, so exact OS package output can vary. The
performance figure has no retained benchmark output/hardware record. Cloud docs describe an
operator procedure, not a tested cloud deployment. The only declared relational foreign key is
the summary-to-session relationship; other child tables rely on pipeline behavior. These are
disclosed limitations, not grounds to claim verified production readiness.

### AI/tool artifact audit

Searches found no accidental model branding, prompt/system text, tool-call JSON, agent scratch
files, fake citations, watermarks, TODO-to-user notes, or AI-authorship claims. Screenshots retain
the normal Grafana UI/footer and contain simulated-data labels; no suspicious watermark or
artifact was found. Existing MITRE, DB-IP, and Cowrie attribution was preserved. Audit-created
Python virtualenv/build metadata/caches were removed as generated workspace artifacts.

## Project explanation

HoneyLens makes a fake SSH endpoint, records the commands and login attempts clients send to it,
and turns those logs into searchable sessions, ATT&CK observations, heuristic severity scores,
dashboards, and weekly exports. It separates the service that accepts connections from the
pipeline that writes data and from Grafana/report roles that only read. It is designed to study
interaction with an emulated shell, not to run real malware or attribute activity to people.

The full beginner-to-advanced walkthrough is in [PROJECT_DEEP_DIVE.md](PROJECT_DEEP_DIVE.md).

## Technology stack

| Technology | Purpose | Why used | Trade-off |
|---|---|---|---|
| Python | Parsing, enrichment, rules, scoring, CLI and reports | One approachable language and strong data tooling | Runtime and package surface larger than a small compiled service |
| Docker / Compose | Service isolation and laptop/cloud assembly | Repeatable multi-service setup with limits, networks, volumes and health checks | Runtime behavior must be exercised with Docker; not verified here |
| Cowrie | Emulated SSH honeypot and JSON event producer | Collects commands without providing a real shell | Low interaction; sophisticated clients can fingerprint it |
| PostgreSQL | Event, session, enrichment, metrics and offset storage | SQL queries, JSONB, indexes, transactions and role grants | Needs a service and migrations; DB tests skipped here |
| Grafana | Five provisioned SQL dashboards | Familiar operational dashboards and query variables | Dashboard panel behavior needs a running stack |
| MITRE ATT&CK | Tactic/technique vocabulary and offline snapshot | Common detection engineering language | Regex matches remain heuristic evidence |
| GeoIP / ASN | Optional network context | Useful network grouping and maps | Approximate, privacy-sensitive, not attribution |
| STIX 2.1 / Navigator | Portable indicator and ATT&CK-layer exports | Interoperable report outputs; validators pass locally | More complex formats; real STIX indicators are not defanged |
| JSON / YAML / SQL | Event interchange, editable rules, schema/query language | Structured input and reviewable detection data | Schema drift and validation require tests/migrations |
| pytest / Ruff / Bandit / pip-audit | Tests, lint, Python security and dependency checks | Fast repeatable local/CI gates | Tests cannot replace Docker, database, or manual review |
| Gitleaks / ShellCheck / Hadolint / Trivy | Secret, shell, Dockerfile, and image checks in CI | Covers risk areas outside Python unit tests | Gitleaks fixed/canary-checked; others not executable locally |
| GitHub Actions | Hosted CI and image integration checks | Runs pinned tools on pushes and pull requests | Hosted execution and 80% gate are unverified |

## Architecture and security model

Cowrie emits rotating JSON logs to a named volume. A non-root Python pipeline reads that volume
read-only, sanitizes hostile content, deduplicates events, enriches source addresses, maps command
strings to tested rules, scores sessions, and commits data and offsets in one transaction.
PostgreSQL has three application roles: `hl_pipeline` read/write; `hl_grafana` SELECT-only; and
`hl_report` SELECT-only. Grafana and reports do not receive the database superuser credentials.

Laptop ports are configured as loopback only; the project port checker requires the Docker CLI,
which was absent. Containers use capability drops, non-root users, read-only filesystems where
supported, resource caps and limited logs. Cowrie has no forwarding/tunnels/SFTP/Telnet, and
outbound fetch behavior is constrained. The cloud host firewall blocks new Cowrie egress and now
must be configured before public startup. Simulator host checks reject unapproved names before
DNS. Optional IPInfo can disclose public source IPs if configured. SQL uses parameters, report HTML
escapes attacker content, and CSV formula-like values are prefixed. These source-level controls
pass unit tests where runnable; Compose, database, and cloud enforcement remain **UNVERIFIED**.

## Real-world value

The codebase can support security education, controlled SSH telemetry research, university labs,
SOC exercises, and a single-sensor prototype. To become a product it would need tested multi-tenant
separation, managed sensor rollout, stronger retention/privacy controls, operator authentication,
reproducible cloud firewall enforcement, alert delivery, and a supported update process.

## Interview summary

“I built an SSH honeypot analytics pipeline around Cowrie. Python validates and sanitizes its
JSON logs, deduplicates them with transactionally persisted offsets, enriches network context,
maps commands to tested MITRE ATT&CK rules, and stores explainable session scores in PostgreSQL.
Five Grafana dashboards and HTML/CSV/STIX/Navigator outputs make the data useful. I focused on
least privilege and safe handling of hostile input, and I clearly separate simulated samples from
real observations. The local suite passed 321 cases; Docker/database/cloud checks still need to
run in CI or a deployment environment.”

## GitHub readiness and proposed tree

The 135 files in the staged index are the proposed candidate. There are no commits or remote,
so there is no prior history to inspect. The staged-file audit in
`docs/FINAL_RELEASE_AUDIT.md` gives the complete path, file type, byte size, staged status, and
reason for every candidate file. The retained tree includes the GitHub workflow, Cowrie config and
fake filesystem, four SQL migrations, cloud/laptop deployment helpers, docs and intentional
samples/screenshots, five Grafana dashboards, Python source, and tests. Do not push runtime
artifacts covered by `.gitignore`.

## Previous audit quality gate (superseded by the final verification below)

| Check | Result |
|---|---|
| pytest with coverage | **VERIFIED:** 321 passed, 52 skipped; 64% combined local coverage |
| Ruff | **VERIFIED:** all checks passed |
| Bandit | **VERIFIED:** exit 0; emitted advisory/no-sec annotation warnings, no failed findings |
| pip-audit | **VERIFIED:** no known vulnerabilities after setuptools floor update |
| Gitleaks working-tree scan and synthetic canary | **VERIFIED:** no leaks; canary detected |
| STIX sample validation | **VERIFIED:** 112 indicators, 24 ATT&CK patterns, identity and report parsed |
| Navigator validation | **VERIFIED:** both sample layers valid format 4.5 |
| ATT&CK rule validation | **VERIFIED:** 60 rules OK |
| Markdown local link/image paths | **VERIFIED:** 16 Markdown files; 17 local links/image paths, 1 image, 0 missing targets |
| Compose resolved config / port check | **UNVERIFIED:** Docker CLI unavailable |
| PostgreSQL migrations, grants, and DB tests | **UNVERIFIED:** no test PostgreSQL DSN/service |
| Docker integration, image build, Trivy | **UNVERIFIED:** Docker unavailable |
| ShellCheck, Hadolint, release packaging | **UNVERIFIED:** ShellCheck/Hadolint/zip not installed |
| POSIX shell syntax | **VERIFIED:** `sh -n` passed on all 7 scripts with Git for Windows shell |
| Git status/diff/history | **UNVERIFIED:** no `.git` directory |
| GitHub Actions hosted run / 80% gate | **UNVERIFIED** |
| Cloud egress and provider/account checks | **UNVERIFIED** |

## Final verification - 2026-10-08

This dated section records the fresh verification pass requested after the earlier audit. The
previous quality-gate table above is preserved as historical evidence; the results below supersede
its environment-dependent entries.

### Environment and repository state

| Item | Result |
|---|---|
| OS | **VERIFIED:** Windows 11 Home, x64, build 26200 |
| Python | **VERIFIED:** clean temporary Python 3.11.9 environment; project requires Python 3.11+ |
| Docker / Compose | **BLOCKED:** neither CLI is installed |
| PostgreSQL | **BLOCKED:** no psql, pg_isready, local service, or test DSN |
| Grafana | **BLOCKED:** configured Grafana 12.4.12 service is not running; localhost:3000 refused the check |
| Git | **VERIFIED:** initialized empty main branch as requested; staged review candidate, no commit, no remote |
| History | **UNVERIFIED:** Gitleaks reports 0 commits scanned; no history exists to audit |

.env.example is staged and not ignored. git check-ignore matched .env, .env.production,
nested .env.staging, databases, logs, archives, MMDBs, captures, .venv, coverage output, and
private-key paths. git status --ignored --short showed only generated coverage/test/build caches;
they are excluded from the staged candidate and are removed before final inventory.

### Current check results

| Check | Status | Evidence / limitation |
|---|---|---|
| Full pytest suite | **VERIFIED:** 321 passed, 52 skipped, 0 test failures | Python 3.11.9; complete skip inventory is in FINAL_RELEASE_AUDIT.md |
| Configured 80% coverage gate | **FAILED:** 63.98% | pytest --cov=honeylens --cov-report=term-missing --cov-fail-under=80; database/service paths dominate uncovered statements |
| Ruff | **VERIFIED** | `ruff check .`; all checks passed |
| Bandit | **VERIFIED** | exit 0; advisory nosec/fake-password annotations, no failed findings |
| pip-audit | **VERIFIED** | no known vulnerabilities; editable HoneyLens distribution is explicitly skipped |
| Working-tree Gitleaks | **VERIFIED** | pinned local Gitleaks 8.30.0 found no leaks |
| Gitleaks canary | **VERIFIED** | generated synthetic token detected; token and report output were not exposed |
| Project secret exposure check | **VERIFIED** | no forbidden files, private keys, local secret values, or resolved Compose evidence |
| Gitleaks history scan | **UNVERIFIED** | 0 commits scanned; this is not a clean-history claim |
| Compose YAML syntax | **VERIFIED, syntax only** | PyYAML parsed laptop (9 services) and cloud (3 services) files including !override |
| Markdown local paths | **VERIFIED** | 17 Markdown files; 17 local link/image paths; 0 missing |
| Docker Compose semantic config / live ports | **BLOCKED** | Docker unavailable; check_ports.py cannot launch docker compose |
| PostgreSQL migrations / role permissions / DB tests | **BLOCKED** | no server or test DSN; 29 DB tests skipped |
| Docker integration / actual ports / Grafana panels | **BLOCKED** | Docker unavailable; check_grafana.py received connection refused |
| Performance benchmark | **BLOCKED** | perf_test.py requires PostgreSQL and creates/drops a database; not run |
| Trivy / image build | **BLOCKED** | Docker unavailable; no images built or scanned; vulnerability counts are not zero claims |
| Hadolint | **BLOCKED** | configured CI invocation runs it in Docker; Docker unavailable |
| ShellCheck | **VERIFIED** | ShellCheck 0.11.0, all seven shell scripts, style severity |
| POSIX shell syntax | **VERIFIED** | sh -n scripts/*.sh deploy/*.sh |
| STIX / Navigator / ATT&CK rules | **VERIFIED** | STIX: 112 indicators, 24 patterns, identity/report; Navigator: 29 and 53 entries; 60 rules valid |
| Simulator safety unit tests | **VERIFIED** | simulator tests passed, including rejection before resolver use; live network mode not run |
| Cloud deployment / egress | **UNVERIFIED** | docs reviewed; no provider VM deployed |
| GitHub Actions | **UNVERIFIED** | workflow syntax and pins reviewed; no remote or hosted run |
| Release ZIP / clean extraction | **VERIFIED** | 135 files; ZIP integrity clean; 0 forbidden entries; final extracted copy passed supported checks; exact bytes in FINAL_RELEASE_AUDIT.md |
| Documentation / AI artifact sweep | **VERIFIED** | 17 Markdown files, 17 local paths with no missing targets; PNGs have no text metadata; AI/tool terms occur only in audit text |

The 63.98% local result is not a fabricated or suppressed success: CI requires 80%, and this run failed
that threshold. The lowest-coverage modules are migrate.py (24%), pipeline/runner.py (26%),
pipeline/store.py (14%), reporting/render.py (16%), reporting/data.py (47%), and
reporting/exports.py (49%). The 29 PostgreSQL skips include migration, role, ingestion, report,
STIX, Navigator, retention, and outage-recovery cases that exercise much of those modules.
No tests were added solely to increase coverage. The hosted 80% result remains **UNVERIFIED**.

Cloud documentation distinguishes private Tailscale/bastion administration from the
source-IP-restricted public SSH fallback. Firewall-before-Cowrie ordering, private PostgreSQL and
Grafana, account isolation, backups, disk retention, reclamation and billing caveats are documented;
none is represented as deployed evidence.
