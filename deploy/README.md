# deploy/ - cloud helper scripts

| Script | What it does | Status |
|---|---|---|
| `move-admin-ssh.sh` | moves the real admin SSH to port 22022 (keys only); reach it over Tailscale or a bastion (DEPLOY_CLOUD.md step 7) | not yet tested on a cloud VM |
| `egress-lockdown.sh` | iptables (and, when available, ip6tables) DOCKER-USER + INPUT rules that block new Cowrie outbound connections; idempotent | not yet tested on a cloud VM |
| `honeylens-egress-lockdown.service` | systemd unit that re-applies `egress-lockdown.sh` on every boot, before `docker.service` (install steps in the file and DEPLOY_CLOUD.md step 9) | not yet tested on a cloud VM |
| `verify-egress.sh` | checks egress blocks with local listeners and DROP-rule packet counters | not yet tested on a cloud VM |
| `backup.sh` | gzip `pg_dump` of the database, keeps 7 | not yet run on a cloud VM |
| `disk-guard.sh` | warns at 85% disk use and applies 30-day retention | not yet run on a cloud VM |

The scripts are written for POSIX `sh` and are linted with ShellCheck in CI on every push. Their
runtime behaviour on a real cloud VM has not been verified yet. Read DEPLOY_CLOUD.md before running
anything.
