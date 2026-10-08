#!/bin/sh
# Download free GeoIP databases into ./geoip (git-ignored, NEVER committed).
#
# Default: DB-IP "Lite" City + ASN databases (MMDB format).
#   Licence: Creative Commons Attribution 4.0 (CC BY 4.0).
#   Attribution required: "IP Geolocation by DB-IP" with a link to https://db-ip.com
#   (HoneyLens shows this in the README and report methodology when used.)
# Alternative: MaxMind GeoLite2 (needs a free account + licence key, EULA forbids
#   redistribution). Put GeoLite2-City.mmdb / GeoLite2-ASN.mmdb in ./geoip and set
#   HL_MMDB_CITY / HL_MMDB_ASN in .env.
#
# Usage:  sh scripts/download_geoip.sh            (current month)
#         sh scripts/download_geoip.sh 2026-09    (a specific month)
set -eu
MONTH="${1:-$(date -u +%Y-%m)}"
DEST="$(cd "$(dirname "$0")/.." && pwd)/geoip"
mkdir -p "$DEST"
for KIND in city asn; do
  URL="https://download.db-ip.com/free/dbip-${KIND}-lite-${MONTH}.mmdb.gz"
  echo "downloading $URL"
  curl -fsSL --proto '=https' --max-time 300 -o "$DEST/dbip-${KIND}-lite.mmdb.gz" "$URL"
  gunzip -f "$DEST/dbip-${KIND}-lite.mmdb.gz"
done
ls -l "$DEST"
echo "Done. Restart the pipeline: docker compose restart pipeline"
