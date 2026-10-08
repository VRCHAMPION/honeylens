# Run HoneyLens on your laptop

Time: about 10 minutes the first time (mostly downloading images). Everything stays **private**
to your computer.

## 0. What you need

| Tool | Windows | macOS | Linux |
|---|---|---|---|
| Docker | Docker Desktop (WSL 2 backend) | Docker Desktop (Apple Silicon or Intel) | Docker Engine + Compose plugin v2 |
| Python 3.11+ | python.org installer (tick "Add to PATH") | `brew install python` | your package manager |
| RAM free | ~2 GB | ~2 GB | ~2 GB |

Check: `docker compose version` must print v2.x. If it says `docker-compose` v1, upgrade.

> Windows: run the commands in **PowerShell** or **WSL**. Use `python` instead of `python3` if
> that is how Python is installed. Git for Windows must not convert line endings: the repository's
> `.gitattributes` forces LF (Line Feed) endings so the shell scripts work inside Linux containers.

## 1. Create your private settings file

```bash
cd honeylens
python scripts/make_env.py
```

**What:** creates `.env` with random passwords. **Why:** never run with example passwords.
`.env` is in `.gitignore`, so it cannot be committed by accident.

## 2. Start the stack

```bash
docker compose up -d --build
docker compose ps
```

Wait until `postgres`, `cowrie`, `pipeline` and `grafana` say **(healthy)** (about 30-60 s).
The one-shot `migrate` service runs first, creates the three database roles and the tables, then
exits with code 0 - that is normal.

**Safety check** (do this once):

```bash
python scripts/check_ports.py --live
```

It must print `PASS: only allowed ports are published, all on 127.0.0.1`.
It also fails if Cowrie (2222) or Grafana (3000) has no published port. Quick manual check:

```bash
curl -s http://127.0.0.1:3000/api/health      # {"database": "ok", ...}
docker compose port cowrie 2222               # 127.0.0.1:2222
```

## 3. Generate SAFE attack data

```bash
# Real SSH sessions from a container to Cowrie (8 personas, 16 sessions):
docker compose --profile sim run --rm simulator
# Plus 14 days of deterministic synthetic events (same output for the same --seed):
docker compose --profile sim run --rm synthetic
```

Or from your own machine (Python venv): `pip install -e .` then
`python -m honeylens.simulator live --target 127.0.0.1 --port 2222 --sessions 8`.

All this data is **SIMULATED**. Dashboards show a warning banner and a "Simulated %" panel.

## 4. Look at the dashboards

Open <http://127.0.0.1:3000>, log in with `admin` and `GF_ADMIN_PASSWORD` from `.env`.
Dashboards → **HoneyLens** folder. Use the **Data** drop-down (all / real / simulated).
Times are in IST (Asia/Kolkata); the database stores UTC.

Check everything at once: `python scripts/check_grafana.py` (datasource health + every panel).

## 5. Try the honeypot yourself

```bash
ssh -p 2222 root@127.0.0.1        # password: admin123   (only the 5 fake pairs in cowrie/README.md work)
```

Type `uname -a`, `cat /etc/passwd`, `wget http://example.invalid/x` and watch them appear in the
Session Explorer within a few seconds. Fake credentials (root/admin123, root/xc3511, admin/admin, ubuntu/ubuntu, pi/raspberry) are listed in `cowrie/userdb.txt` and `cowrie/README.md`; every other pair fails.

## 6. Weekly report and IOC exports

```bash
# Linux/macOS: run as your own user so the files in ./out belong to you
HL_HOST_UID=$(id -u) HL_HOST_GID=$(id -g) docker compose --profile tools run --rm report
# Windows PowerShell:
docker compose --profile tools run --rm report
```

Open `out/weekly-report.html`. The always-on `report-scheduler` service also writes one automatically every Monday 06:00 IST into a dated folder in the `hl_reports` volume (`docker compose exec report-scheduler honeylens-report-scheduler --print-next` shows the next run). Add `--mask-ips` to hide IP host parts before sharing:
`docker compose --profile tools run --rm report honeylens-report --out /out --mask-ips`.

## 7. Optional: real GeoIP data

```bash
sh scripts/download_geoip.sh      # DB-IP Lite City + ASN (CC BY 4.0), saved in ./geoip (git-ignored)
docker compose restart pipeline
```

Simulator IPs always use deterministic DEMO data, so this only matters for real attackers.

**Optional IPInfo API.** No container has internet access by default. If you set
`HL_ENRICH_API_TOKEN` in `.env`, also start with the override that gives ONLY the pipeline outbound
access: `docker compose -f docker-compose.yml -f docker-compose.enrich.yml up -d`.

## 8. Run the tests

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                            # unit tests (DB tests skip without a database)
python scripts/integration_test.py                # full Docker test - WARNING: runs "down -v" (deletes local data)
```

## 9. Stop / clean up

```bash
docker compose stop              # stop, keep data
docker compose down              # remove containers, keep data volumes
docker compose down -v           # remove EVERYTHING including the database
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `port is already allocated` | another program uses 2222 or 3000: stop it, or change the left side of `ports:` (keep `127.0.0.1:`) |
| `127.0.0.1:3000` / `:2222` refused but containers are healthy | `docker compose port grafana 3000` must print an address. If it prints nothing, the service is attached only to `internal: true` networks (Docker then skips the port); keep the `ui` / `edge` networks from `docker-compose.yml`. Loopback publishing with masquerading off was checked with Docker's default `userland-proxy`; if you disabled it in `daemon.json` and the port still fails, re-enable it |
| `migrate` exits non-zero | `docker compose logs migrate` - usually a password under 12 characters in `.env` |
| Dashboards empty | run step 3, set time range to "Last 7 days", Data = all |
| `report` cannot write `./out` (Linux) | use the `HL_HOST_UID=$(id -u)` form in step 6 |
| Apple Silicon / ARM | all images are multi-arch (amd64 + arm64); nothing to change |
