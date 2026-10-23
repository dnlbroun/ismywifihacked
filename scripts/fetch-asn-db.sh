#!/usr/bin/env bash
# Download the iptoasn.com combined IPv4+IPv6 database (PDDL, refreshed hourly upstream).
# Usage: scripts/fetch-asn-db.sh [dest_dir]   (default: data/asn)
set -euo pipefail
dest="${1:-data/asn}"
mkdir -p "$dest"
tmp="$(mktemp "$dest/.ip2asn.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
curl --fail --silent --show-error --location --max-time 120 --proto '=https' \
  -o "$tmp" https://iptoasn.com/data/ip2asn-combined.tsv.gz
gzip -t "$tmp"
chmod 644 "$tmp"
mv "$tmp" "$dest/ip2asn-combined.tsv.gz"
echo "saved $dest/ip2asn-combined.tsv.gz"
