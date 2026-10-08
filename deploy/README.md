# deploy/ - cloud helper scripts

| Script | What it does | Status |
|---|---|---|
| `move-admin-ssh.sh` | moves the real admin SSH to port 22022 (keys only); reach it over Tailscale or a bastion (DEPLOY_CLOUD.md step 7) | not verified in this audit; not yet tested on a cloud VM |
| `egress-lockdown.sh` | iptables DOCKER-USER + INPUT rules intended to block new Cowrie outbound connections | not verified in this audit; not yet tested on a cloud VM |
| `verify-egress.sh` | checks egress blocks with local listeners and DROP-rule packet counters | not verified in this audit; not yet tested on a cloud VM |
| `backup.sh` | gzip `pg_dump` of the database, keeps 7 | not run in this audit |
| `disk-guard.sh` | warns at 85% disk use and applies 30-day retention | not verified in this audit |

The scripts are written for POSIX `sh`. ShellCheck and Docker were unavailable during this audit,
so shell lint and runtime behavior remain **UNVERIFIED**. Read DEPLOY_CLOUD.md before running anything.
