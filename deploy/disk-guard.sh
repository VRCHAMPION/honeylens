#!/bin/sh
# Simple disk-space monitor for a small VM. STATUS: VERIFIED locally (logic), UNVERIFIED on cloud cron.
# Cron (every 30 min):  */30 * * * * /path/to/honeylens/deploy/disk-guard.sh >> /var/log/honeylens-disk.log 2>&1
# If the disk is >= 85% full it prints a warning and runs the retention function
# with a shorter window (30 days) to free space.
set -eu
cd "$(dirname "$0")/.."
USE=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')
echo "$(date -u +%FT%TZ) disk_used=${USE}%"
if [ "$USE" -ge 85 ]; then
  echo "WARNING: disk ${USE}% full - applying 30-day retention and pruning docker images"
  docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT * FROM honeylens.apply_retention(30)"'
  docker image prune -f >/dev/null
fi
