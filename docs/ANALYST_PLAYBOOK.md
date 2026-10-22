# Analyst playbook

How to use HoneyLens like a SOC (Security Operations Centre) analyst. Each play: **when**, **where
to look**, **what to decide**.

## Daily 10-minute triage

1. **Pipeline Health** - "Seconds since last heartbeat" < 90 and "Malformed lines" not growing.
   If stale: `docker compose ps`, `docker compose logs --since 30m pipeline`.
2. **SOC Overview** - set Data = **real** (cloud) or **all** (laptop demo). Compare today with the
   7-day shape. A spike of one class (e.g. cryptominer-like) is worth a look.
3. **Session Explorer** - open the top 3 sessions by severity. Read "Why this score" before believing it.
4. Write anything interesting into a copy of [FINDINGS_TEMPLATE.md](FINDINGS_TEMPLATE.md).

## Reading the severity score (0-100)

| Points | Rule |
|---|---|
| +10 | successful (fake) login |
| +2 per 10 failed logins (max 10) | brute force volume |
| +1 per command (max 10) | hands-on activity |
| +5 per ATT&CK tactic (max 25) | breadth of behaviour |
| +3 per high-confidence technique (max 15) | strong evidence |
| +15 | download attempt with a URL |
| +25 | download-and-execute: a fetch piped into a shell (`curl ... \| sh`), an `scp -i key user@host:path` pull, or `chmod +x`/`./run` after a fetch |
| +5 | per-IP brute force: login-only session whose IP made ≥ `HL_BRUTE_MIN_FAILURES` failed logins within ± `HL_BRUTE_WINDOW_MIN` minutes |
| +10 | persistence tactic |
| +10 | defense-impairment tactic (log wiping, firewall off, killing agents) |
| +15 | resource hijacking (cryptominer indicators) |
| +15 | data destruction |

Labels: low <25, medium 25-49, high 50-74, critical ≥75. These are **heuristics** - the
"Why this score" table shows exactly which rules fired.

## Behaviour classes (first match wins)

| Class | Rule | Typical next step |
|---|---|---|
| cryptominer-like | T1496 / T1496.001 matched | note pool host/port and wallet format (do NOT contact the pool) |
| malware-dropper | download URL attempted or T1105 | record URL + hash as IOC; never download it yourself |
| honeypot-prober | high-confidence T1497.001 (e.g. the shell-behaviour probe: `===SHELL_BEHAVIOR===`, `./xxxxxx`, a `filter` test script), or any T1497.001 with ≤6 commands | the actor is checking for honeypots; note client version / HASSH |
| intruder | logged in and ran commands | read the command list; map new behaviour to rules |
| brute-forcer | ≥3 failed logins in the session, or a login-only session that is part of a per-IP burst (see points table), no commands | add credentials to statistics; nothing else |
| scanner | ≤2 login attempts, no commands | ignore unless volume spikes |

Rules run on the stored command and on a normalised copy (`/bin/./uname` → `uname`, `echo -e`
`\xNN` escapes decoded); the stored text never changes.

**Bot vs human:** needs ≥3 commands. Bot = median gap between commands < 1 s and first command < 3 s
after login. Human = median gap ≥ 2 s with uneven gaps. Otherwise unknown.

## Play: new IOC

1. Report section 6 or `iocs.csv` → URL/host/hash. Rows with context "seen in command (never fetched)"
   come from command text (e.g. `curl ... | sh`, `scp user@host:path`), not from a logged download.
   `file-path` rows are files uploaded by the attacker (local paths); their hashes are separate rows.
2. Check reputation in a **read-only** service (e.g. search the hash on VirusTotal - search, do not upload files).
3. Add to a short-lived block list with a note "honeypot-observed, low confidence".
4. Never connect to the URL, never "hack back".

## Play: unmapped commands

Credentials & Commands → "Unmapped commands". For each frequent one: find the ATT&CK technique,
add a rule with positive/negative examples (see MITRE_COVERAGE.md), run tests. After deploying new
rules, run `docker compose exec pipeline honeylens-rescore --dry-run`, then without `--dry-run`, so
older sessions are re-matched and re-scored.

## Play: suspected false positive

Session Explorer → "ATT&CK matches in this session" shows the rule id. Add the misfiring command as a
`negative:` example of that rule, tighten the regex, run `pytest tests/test_rules.py`.

## Play: weekly report

```bash
HL_HOST_UID=$(id -u) HL_HOST_GID=$(id -g) docker compose --profile tools run --rm report honeylens-report --out /out --data real --mask-ips
```

Use `--data real` in the cloud so simulator tests do not pollute numbers. Your own test IPs
(`HL_IGNORE_IPS`) are always left out. Share only the masked version.

## Things you must NOT do

* Do not attribute attacks to countries or groups from GeoIP.
* Do not visit, download or "test" attacker URLs. Do not contact mining pools or C2 (command-and-control) hosts.
* Do not publish unmasked IPs or full credentials lists from REAL data without thinking about privacy.
