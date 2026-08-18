#!/usr/bin/env bash
# demo-scan.sh — run demo-scan.py in a container with many source IPs.
#
# phase-827. The campaign and slow-scan detectors count DISTINCT source IPs in
# a /24; the normal traffic generator has exactly one, so neither could ever
# fire. This binds each connection to its own address on the proxy's network.
#
# The source IPs are real — the proxy reads them from the TCP layer. Nothing
# here enables PROXY-protocol trust or any IP-spoofing path.
#
# Usage:
#   scripts/demo-scan.sh slow-scan     25 IPs x 2 requests  (slow scan)
#   scripts/demo-scan.sh campaign      45 IPs x 3 requests  (campaign; needs
#                                      the fingerprint blacklisted to reach the
#                                      70% block rate)
#   scripts/demo-scan.sh --ips 30 --requests-per-ip 2
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"
# shellcheck disable=SC1091
[ -f .env ] && . ./.env

MODE="${1:-slow-scan}"
# `shift` with no positional arguments returns non-zero, and `set -e` then kills
# the script before it prints anything — which is exactly what `make demo-scan`
# with no arguments did: silence, exit 0-looking, no traffic. Guard the shift on
# there being something to shift.
[ $# -gt 0 ] && shift || true
case "$MODE" in
  slow-scan) ARGS=(--ips 25 --requests-per-ip 2) ;;
  # 45/256 = 0.176 density, above the 0.15 threshold with headroom.
  campaign)  ARGS=(--ips 45 --requests-per-ip 3) ;;
  *)         ARGS=() ;;
esac
ARGS+=("$@")

PROJECT="${COMPOSE_PROJECT_NAME:-ja4proxy}"
NET=$(docker inspect "${PROJECT}-proxy-1" \
        --format '{{range $k,$v := .NetworkSettings.Networks}}{{if $v.IPAddress}}{{$k}} {{end}}{{end}}' 2>/dev/null \
      | tr ' ' '\n' | grep -E 'dmz' | head -1)
: "${NET:=ja4proxy-dmz}"

PROXY_IP=$(docker inspect "${PROJECT}-proxy-1" \
             --format "{{(index .NetworkSettings.Networks \"${NET}\").IPAddress}}" 2>/dev/null)
if [ -z "$PROXY_IP" ]; then
  echo "demo-scan: cannot find the proxy on network '${NET}' — is the stack up?" >&2
  exit 1
fi

# Source /24 is derived from the proxy's own network so the aliases route, and
# is deliberately high in the range (x.x.200.0/24) to stay clear of addresses
# docker's IPAM hands out.
BASE="$(echo "$PROXY_IP" | cut -d. -f1-2).200"

echo "Network ${NET}, proxy ${PROXY_IP}, sourcing from ${BASE}.0/24"
echo

docker run --rm --network "$NET" --cap-add NET_ADMIN \
  -v "$PWD/scripts/demo-scan.py:/demo-scan.py:ro" \
  python:3.12-alpine \
  python3 /demo-scan.py --target-host "$PROXY_IP" --target-port 8080 --base "$BASE" "${ARGS[@]}"
