# SECURITY

HoneyLens deliberately invites attackers. These rules keep that safe. Each rule lists **how it is
enforced** and **how it is tested**.

## 1. The laptop stays private

| Rule | Enforced by | Tested by |
|---|---|---|
| Only `127.0.0.1:2222` (Cowrie) and `127.0.0.1:3000` (Grafana) are published | `docker-compose.yml` `ports:` | `scripts/check_ports.py` (static + `--live`), `tests/test_compose_safety.py`, integration step 2 |
| PostgreSQL has no published port; it is on an `internal: true` network | compose `networks.backend.internal` | `check_ports.py` fails if postgres publishes |
| Cowrie, simulator and Grafana cannot reach the internet in laptop mode; only pipeline has optional API egress | `networks.edge.internal`, `networks.egress`, pipeline network list | static assertion in `tests/test_compose_safety.py`; runtime needs Docker |
| No host networking, privileged mode, or Docker socket mounts | compose review | `check_ports.py` fails on any of them |
| Containers run non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges` | compose `x-hardening` anchor, `user:`, `read_only:` | integration step 9 (`docker inspect`) |
| Resource limits (CPU, memory, PIDs) on every service | compose `deploy.resources.limits` | `docker compose config -q` + `tests/test_compose_hardening.py` |

PostgreSQL's official entrypoint needs a few capabilities (CHOWN, DAC_OVERRIDE, FOWNER, SETUID,
SETGID) to fix folder ownership before dropping to the `postgres` user; only those are added back.

## 2. The simulator cannot attack anyone

* Live mode connects only to: loopback, a Compose service of this project that resolves to a
  private Docker address (default `cowrie`), or a host listed exactly in `HL_SIM_ALLOWED_HOSTS`.
  Unapproved hostnames are rejected before DNS resolution; connection checks run before SSH data
  is sent (`src/honeylens/simulator/guard.py`). Tests:
  `tests/test_simulator.py` (public IPs, public domains, a "cowrie" name resolving to a public IP,
  LAN addresses, mixed DNS answers, multicast and 0.0.0.0 are all refused).
* No scanning, exploits, malware, EICAR test strings, live malware URLs or real mining pools.
  Personas use RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
  `.invalid` / `.test` domains only; a test scans every persona command to prove it.

## 3. Attacker data is hostile

| Threat | Defence | Test |
|---|---|---|
| SQL injection | every query uses bound parameters (`%s`); only constant SQL fragments are joined | `'; DROP TABLE ...` stored as text, table survives (unit + integration) |
| XSS (Cross-Site Scripting) in the report | Jinja2 autoescape, strict Content-Security-Policy, no JavaScript in the report | `<script>` and `<img onerror>` render escaped |
| XSS in Grafana | Grafana escapes table cells; text panels contain only our static text | manual review |
| Terminal escape (ANSI) and control characters | stripped at ingest (`sanitize.clean_text`) | unit tests |
| Huge input / disk filling | per-field limits (command 4096 chars...), 64 KiB max line, oversized lines skipped in chunks | 300 KB line test |
| ReDoS (Regular expression Denial of Service) | bounded regexes, 4096-char cap before matching | every rule timed on hostile 4 KB strings (< 0.5 s) |
| CSV injection (Excel formulas) | cells with formula prefixes after spaces/BOM/control whitespace are prefixed with `'` | `tests/test_exports.py` |
| Malicious downloads | HoneyLens never fetches URLs; Cowrie outbound is bound to loopback, cloud egress is firewalled | integration: `wget` inside Cowrie produced `file_download.failed`, no file |
| Symlink tricks in the log folder | tailer ignores symlinks; pipeline mounts the Cowrie volume read-only | unit test |

## 4. Least privilege in the database

* `hl_pipeline` - read/write on HoneyLens tables only; not superuser, cannot create databases/roles.
* `hl_grafana`, `hl_report` - `SELECT` only, plus `default_transaction_read_only = on` and
  statement timeouts as a second lock. Tests try INSERT/UPDATE/DELETE/CREATE/function calls.
* `PUBLIC` loses all rights on the database, the `public` schema and the `honeylens` schema.
* The PostgreSQL superuser is used only by the one-shot `migrate` job.

## 5. Secrets

* `.env` (git-ignored) holds all passwords; `scripts/make_env.py` generates random ones and sets
  file mode 600. Migrations refuse role passwords shorter than 12 characters.
* No secret is baked into images (`.dockerignore` excludes `.env`); `gitleaks` scans the tree;
  pre-commit blocks `.env`, `*.mmdb` and private keys.
* GeoIP databases, captured attacker files, Cowrie logs and reports are git-ignored and excluded
  from the release ZIP.

## 6. Reports and ethics

* URLs and IPs are **defanged** in reports (`hxxp[://]198[.]51[.]100[.]7`); `--mask-ips` hides
  host parts before public sharing.
* **No attribution claims, no hack-back.** GeoIP shows where an IP is registered, not who the
  attacker is; the report says so. IOCs are labelled low-confidence.

## 7. Cloud (not yet tested on a real VM)

Dedicated account/compartment/VPC with nothing else in it; only Cowrie (port 22) is public; admin
SSH moved to port 22022 (keys only) and reached over Tailscale or a cloud bastion with no public
ingress rule; a source-IP-restricted public rule is a labelled fallback only (it is not private).
Grafana is reached through an SSH tunnel. Cowrie egress (to the Internet, other containers and the VM
itself) is dropped by `deploy/egress-lockdown.sh` and proven with `deploy/verify-egress.sh`, which uses
only local targets. See DEPLOY_CLOUD.md.

## 8. Secret exposure in evidence and the release ZIP

* Validation always uses `docker compose config -q` (quiet: prints nothing). A plain
  `docker compose config` prints every resolved password, so its output is never saved in logs,
  evidence or docs. `scripts/check_ports.py` reads the JSON form in memory and prints only ports.
* `scripts/check_secrets_exposure.py` fails if a ZIP or folder contains `.env` variants other than
  `.env.example`, private keys
  (PEM/OpenSSH/PuTTY, sshd/Cowrie host keys), GeoIP databases, `.git`, coverage files, any of the
  **actual** secret values from the local `.env`, or resolved compose output in test logs.
  It names the file and variable, never the value.
* `scripts/package.sh` runs it on every ZIP it builds and deletes the ZIP on failure; CI runs it on
  the working tree (after the integration test has written its logs) and on the built ZIP.
* Tests: `tests/test_secrets_exposure.py`. CI runs Gitleaks over full Git history and first checks
  that the pinned scanner detects a generated test token. A local directory scan cannot inspect
  history when the workspace has no `.git` metadata.

## Reporting a problem

Open a GitHub issue without exploit details, or email the maintainer listed in the GitHub profile.
