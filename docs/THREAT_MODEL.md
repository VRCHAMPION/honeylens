# Threat model

**What:** a list of what could go wrong, who could cause it, and what HoneyLens does about it.
**Why:** a honeypot invites attackers by design, so we must think like them about our own system.
Method: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege) applied to each component.

## Assets (what we protect)

1. The laptop / VM running HoneyLens and anything else on its network.
2. Third parties on the internet (our honeypot must never attack them).
3. The integrity of collected data (reports must be trustworthy).
4. Secrets: database passwords, Grafana admin password, cloud credentials.
5. The analyst's browser (viewing hostile data in Grafana / the report).

## Actors

| Actor | Can reach | Goal |
|---|---|---|
| Internet attacker (cloud mode) | Cowrie port 22 only | get a shell, run bots/miners, pivot, detect the honeypot |
| Malicious log content | anything that displays logs | XSS, terminal escape injection, SQL injection, resource exhaustion |
| Local user on the same Wi-Fi (laptop) | nothing (loopback-only ports) | reach Grafana/Postgres |
| Supply chain | images and Python packages | malicious updates |
| The operator (you) | everything | mistakes: exposing ports, committing secrets, attacking someone by accident |

## Threats and controls

| # | Threat (STRIDE) | Control | Residual risk |
|---|---|---|---|
| T1 | Attacker escapes Cowrie's emulated shell to the container (E) | Cowrie never executes commands (emulation); non-root uid 999, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, PID/memory limits | Cowrie/Twisted 0-day - keep image pinned AND updated |
| T2 | Container escape to host (E) | no privileged mode, no Docker socket, no host network | kernel 0-day; use a dedicated VM (cloud rule) |
| T3 | Honeypot used to attack others / download malware (T, legal) | Laptop edge network has no outbound NAT (masquerade off); Cowrie `out_addr=127.0.0.1`; cloud DOCKER-USER + INPUT egress DROP; forwarding/tunnelling off | misconfigured cloud firewall - verify with `deploy/verify-egress.sh` (local targets only) |
| T3b | Attacker reaches the real admin SSH (S/E) | sshd on 22022, keys only, no root; reached over Tailscale or a cloud bastion with no public ingress rule | fallback C (22022 from your IP/32) is still public - use only temporarily |
| T4 | Hostile log content -> SQL injection (T) | parameterized queries only | none known; tested with injection payloads |
| T5 | Hostile content -> XSS in report/Grafana (I/E) | Jinja2 autoescape, CSP, no JS; Grafana escapes table cells | Grafana bug; Grafana is loopback/tunnel only |
| T6 | ANSI escape / control characters attack analyst terminal (T) | stripped at ingest; `\n` shown as `⏎` | raw Cowrie log file still contains them - view with `less -R` carefully |
| T7 | Giant lines / log flooding fill disk or RAM (D) | 64 KiB line cap, chunked skipping, field limits, retention, Docker log caps, disk-guard | sustained flood on tiny disk - monitor |
| T8 | ReDoS through crafted commands (D) | bounded regexes, 4096-char cap, timing test | new rules must keep the style (CI tests every rule) |
| T9 | Fake events poisoning statistics (T) | Cowrie is the only writer of the log volume; pipeline mounts it read-only; SHA-256 dedupe | an attacker can still send misleading *commands* - that is the nature of honeypot data |
| T10 | Grafana or report role abused to change data (T) | read-only roles + `default_transaction_read_only` + statement timeout | none |
| T11 | Laptop services exposed on LAN (I) | `127.0.0.1:` bindings checked by `check_ports.py` (static + live) | user edits compose - the checker catches it |
| T12 | Secrets leaked to Git (I) | `.gitignore`, pre-commit hook, gitleaks in CI, random `.env` via script | user pastes secrets elsewhere |
| T13 | Honeypot fingerprinting (I) | realistic hostname/banner/Debian files; default `svr04` removed | experienced attackers can still detect Cowrie (we even detect them doing it: T1497.001) |
| T14 | Simulator pointed at a third party (legal) | guard: loopback / project service / explicit allow-list only; rejects unapproved names before DNS | allow-list misuse by the operator |
| T15 | Supply-chain compromise (T) | exact version pins, Trivy + pip-audit scans, minimal dependencies | pinned images age - rescan monthly |
| T16 | Attribution mistakes / hack-back (legal, reputational) | reports state "not attribution"; no active response features exist | human judgement |
| T17 | Privacy: sending attacker IPs to third parties (I) | API enrichment off by default; offline MMDB; offline Grafana basemap | user enables API |

## Out of scope

Defending against a nation-state that targets the honeypot operator personally; high-interaction
honeypots (real VMs); legal advice for your jurisdiction (read your cloud provider's AUP).

## In short

Modelled with STRIDE. The biggest risks are the honeypot being used against third parties and
hostile log content attacking the analyst. In laptop mode the Cowrie network has no outbound NAT
(masquerade off); in cloud mode host firewall rules (persisted by a systemd unit) also block Cowrie egress. Containers are non-root and mostly read-only,
the DB roles for viewing are read-only, every query is parameterized, and the report is escaped with
a strict CSP and no JavaScript. The pipeline has outbound access for IPInfo only when the
operator adds the `docker-compose.enrich.yml` override (and sets a token).
