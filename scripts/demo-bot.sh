#!/usr/bin/env bash
# demo-bot.sh — make ONE deliberately non-browser TLS connection.
#
# phase-826. The bulk generator shows volume; this shows a single, explainable
# event you can point at during a demo. The client below sends no ALPN and a
# short cipher list, which is what makes its JA4 decode as "not browser-shaped"
# in the console.
#
# It connects THROUGH the proxy, so the connection is fingerprinted, scored and
# recorded exactly like any other.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"
# shellcheck disable=SC1091
[ -f .env ] && . ./.env

HOST="${1:-127.0.0.1}"
PORT="${2:-${HOST_PORT_DIRECT:-8081}}"

command -v openssl >/dev/null 2>&1 || { echo "demo-bot: openssl not found" >&2; exit 1; }

echo "Opening one non-browser TLS connection to ${HOST}:${PORT}..."

# -no_alpn is implicit (we simply never offer one); the restricted cipher list
# keeps the count low, which is the other half of the tool signature.
if printf 'GET / HTTP/1.1\r\nHost: demo\r\nConnection: close\r\n\r\n' \
    | timeout 10 openssl s_client -connect "${HOST}:${PORT}" \
        -servername demo.local \
        -cipher 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256' \
        -quiet -verify_quiet 2>/dev/null >/dev/null; then
  echo "  ✓ connection completed"
else
  # A non-zero exit is expected when the proxy RSTs a blacklisted fingerprint —
  # that is a successful demo of enforcement, not a script failure.
  echo "  ✓ connection attempted (closed early — expected if this fingerprint is blocked)"
fi

echo
echo "Now: open the console, find the newest connection, and click its fingerprint."
echo "Expect ALPN 'none offered', a small cipher count, and a 'not browser-shaped' badge."
