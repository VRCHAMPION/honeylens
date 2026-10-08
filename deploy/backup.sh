#!/bin/sh
# Back up the HoneyLens database (compressed SQL dump) and keep the last 7.
# Tested against the local Compose stack.
#   sh deploy/backup.sh            # writes ./backups/honeylens-YYYYmmdd-HHMMSS.sql.gz
# Restore (DESTROYS current data):
#   gunzip -c backups/FILE.sql.gz | docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
set -eu
cd "$(dirname "$0")/.."
mkdir -p backups
chmod 700 backups
FILE="backups/honeylens-$(date -u +%Y%m%d-%H%M%S).sql.gz"
TMP="$FILE.partial"
# Dump to a temporary file first and check the exit code, so a failed dump
# (database down) never replaces a good backup with an empty one.
if ! docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --clean --if-exists' > "$TMP"; then
  rm -f "$TMP"; echo "BACKUP FAILED: pg_dump error" >&2; exit 1
fi
gzip -9 -c "$TMP" > "$FILE" && rm -f "$TMP"
# Keep the newest 7. File names contain a sortable UTC timestamp and no spaces.
find backups -maxdepth 1 -type f -name 'honeylens-*.sql.gz' | sort -r | tail -n +8 | xargs -r rm -f --
echo "backup written: $FILE ($(du -h "$FILE" | cut -f1))"
