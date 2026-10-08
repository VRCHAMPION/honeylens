# Sample outputs - ALL SIMULATED

Generated on 2026-10-07 by the HoneyLens stack from an integration test run:
16 live simulator SSH sessions through Cowrie + `honeylens-simulator synthetic --seed 42 --days 14`.
No real attacker data. IPs are RFC 5737 documentation addresses; domains end in `.invalid`/`.test`.

| File | What |
|---|---|
| `weekly-report.html` | self-contained weekly report (open in a browser) |
| `weekly-report-masked.html` | same with `--mask-ips` |
| `iocs.csv` | IOC list (IPs, URLs, hashes) |
| `iocs.stix.json` | STIX 2.1 bundle |
| `attack-navigator-layer.json` | ATT&CK Navigator layer: techniques SEEN in the sample week |
| `attack-navigator-coverage-layer.json` | ATT&CK Navigator layer: techniques HoneyLens CAN detect |
| `synthetic-cowrie-events-sample.json` | first 300 synthetic Cowrie-format events |
