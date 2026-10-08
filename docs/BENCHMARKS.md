# Benchmarks

Throughput numbers mean little without the machine they came from, so every result here records
how it was measured. Re-run with:

```bash
HL_TEST_PG="host=127.0.0.1 port=5432 user=<superuser> password=<pw>" \
  python scripts/perf_test.py --days 7 --per-day 1000
```

The script creates a throw-away database, writes deterministic synthetic Cowrie events, ingests them
with the real `Pipeline` class (sanitise, enrich with demo GeoIP, ATT&CK rules, scoring, batched
transactions), prints the rate, then drops the database.

## 2026-10-08: pipeline ingest

| Setting | Value |
|---|---|
| Machine | Linux VM, aarch64 (ARM64), 2 vCPUs, ~7 GB RAM |
| Python | 3.12.15 |
| PostgreSQL | 18.6 (stock binaries, default `postgresql.conf`) on the same VM, TCP over loopback |
| Docker | not used (pipeline ran directly in a virtualenv) |
| Workload | `--days 7 --per-day 1000`: 108,438 events, 8,750 sessions, 24.6 MB of JSON lines, batch 500 |

| Run | Time | Events/s | Sessions/s | Sample dashboard query |
|---|---|---|---|---|
| 1 | 21.2 s | 5,107 | 412 | 3.8 ms |
| 2 | 18.5 s | 5,850 | 472 | 4.0 ms |
| 3 | 18.4 s | 5,906 | 477 | 3.8 ms |

The pipeline and PostgreSQL shared the same two vCPUs, so this is a conservative small-VM figure,
not a peak. A real honeypot sees far fewer events than this: the point is that ingest is not the
bottleneck, and a backlog (for example after a database outage) is cleared quickly.
