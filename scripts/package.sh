#!/bin/sh
# Build honeylens-project.zip (one top-level folder "honeylens/") without secrets or junk.
# Usage: sh scripts/package.sh [output-dir]
set -eu
SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$(dirname "$SRC")}"
STAGE="$(mktemp -d)"
mkdir -p "$STAGE/honeylens"
( cd "$SRC" && tar cf - \
    --exclude='./.env*' --exclude='*/.env*' --exclude='./.git' --exclude='*/.git' \
    --exclude='*/__pycache__' --exclude='./.venv' --exclude='./venv' \
    --exclude='./.pytest_cache' --exclude='./.ruff_cache' --exclude='./.coverage' --exclude='./htmlcov' \
    --exclude='*.egg-info' --exclude='./geoip' --exclude='*.mmdb' --exclude='*.mmdb.gz' \
    --exclude='./out' --exclude='./backups' --exclude='./captures' --exclude='./cowrie-data' \
    --exclude='./var' --exclude='./reports' --exclude='./dl' --exclude='./tty' \
    --exclude='./build' --exclude='./dist' --exclude='./.terraform' --exclude='*.tfstate*' \
    --exclude='*.pem' --exclude='*.key' --exclude='*.p12' --exclude='*.pfx' --exclude='*.p7b' --exclude='*.p7c' \
    --exclude='*.p7m' --exclude='*.p7s' --exclude='*.p8' --exclude='*.p10' --exclude='*.jks' --exclude='*.keystore' \
    --exclude='*.ppk' --exclude='*.crt' --exclude='*.cer' --exclude='*.der' \
    --exclude='*.db' --exclude='*.sqlite' --exclude='*.sqlite3' --exclude='*.log' --exclude='*.pcap' \
    --exclude='*.zip' --exclude='*.tar' --exclude='*.tar.gz' --exclude='*.tgz' --exclude='*.pyc' \
    --exclude='./honeylens-project.zip' . ) | ( cd "$STAGE/honeylens" && tar xf - )
# The archive omits all local environment variants; restore only the placeholder template.
[ ! -f "$SRC/.env.example" ] || cp "$SRC/.env.example" "$STAGE/honeylens/.env.example"
rm -f "$OUT/honeylens-project.zip"
( cd "$STAGE" && zip -qr -X "$OUT/honeylens-project.zip" honeylens )
rm -rf "$STAGE"
# Refuse to publish a ZIP that contains .env, keys, forbidden files or a local secret value.
ENV_ARG=""
[ -f "$SRC/.env" ] && ENV_ARG="--env $SRC/.env"
# shellcheck disable=SC2086  # ENV_ARG is intentionally split into two words
if ! python3 "$SRC/scripts/check_secrets_exposure.py" "$OUT/honeylens-project.zip" $ENV_ARG; then
  rm -f "$OUT/honeylens-project.zip"
  echo "package.sh: secret-exposure check FAILED - ZIP deleted" >&2
  exit 1
fi
ls -l "$OUT/honeylens-project.zip"
