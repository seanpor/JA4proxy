#!/bin/bash
# rotate_soar_token.sh — Rotate a JA4proxy Management API SOAR token.
#
# Calls POST /api/v1/tokens/{id}/rotate, reads the new token from the
# response, and logs the rotation event with a timestamp.
#
# Required environment variables:
#   JA4PROXY_MGMT_URL    — Management API base URL (e.g. https://mgmt.example.com:8090)
#   JA4PROXY_API_TOKEN   — Current bearer token with token-rotate permission
#   JA4PROXY_TOKEN_ID    — ID of the token to rotate
#
# Exit codes:
#   0 — success
#   1 — failure (error written to stderr)
#
# Usage:
#   JA4PROXY_MGMT_URL=https://mgmt:8090 \
#   JA4PROXY_API_TOKEN=operator-token-here \
#   JA4PROXY_TOKEN_ID=soar-token-id \
#   bash scripts/rotate_soar_token.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------

: "${JA4PROXY_MGMT_URL:?ERROR: JA4PROXY_MGMT_URL must be set}"
: "${JA4PROXY_API_TOKEN:?ERROR: JA4PROXY_API_TOKEN must be set}"
: "${JA4PROXY_TOKEN_ID:?ERROR: JA4PROXY_TOKEN_ID must be set}"

ROTATE_URL="${JA4PROXY_MGMT_URL}/api/v1/tokens/${JA4PROXY_TOKEN_ID}/rotate"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[${TIMESTAMP}] Rotating SOAR token id=${JA4PROXY_TOKEN_ID} at ${ROTATE_URL}"

# ---------------------------------------------------------------------------
# Call the rotate endpoint
# ---------------------------------------------------------------------------

HTTP_RESPONSE=$(
    curl --silent \
         --show-error \
         --fail \
         --max-time 30 \
         --request POST \
         --header "Authorization: Bearer ${JA4PROXY_API_TOKEN}" \
         --header "Content-Type: application/json" \
         --write-out "\n%{http_code}" \
         "${ROTATE_URL}" \
    2>&1
) || {
    echo "[${TIMESTAMP}] ERROR: curl failed — could not reach ${ROTATE_URL}" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Parse HTTP status and body
# ---------------------------------------------------------------------------

HTTP_STATUS=$(echo "${HTTP_RESPONSE}" | tail -n1)
RESPONSE_BODY=$(echo "${HTTP_RESPONSE}" | head -n -1)

if [ "${HTTP_STATUS}" != "200" ]; then
    echo "[${TIMESTAMP}] ERROR: token rotation failed — HTTP ${HTTP_STATUS}" >&2
    echo "[${TIMESTAMP}] Response body: ${RESPONSE_BODY}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Extract new token from JSON response
# ---------------------------------------------------------------------------

NEW_TOKEN=$(echo "${RESPONSE_BODY}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['token'])
except (KeyError, json.JSONDecodeError) as e:
    print(f'ERROR: could not parse token from response: {e}', file=sys.stderr)
    sys.exit(1)
")

if [ -z "${NEW_TOKEN}" ]; then
    echo "[${TIMESTAMP}] ERROR: new token was empty in response" >&2
    exit 1
fi

DONE_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${DONE_TIMESTAMP}] SUCCESS: token rotated for id=${JA4PROXY_TOKEN_ID}"
echo "[${DONE_TIMESTAMP}] Copy the new token from the secure response and update the SOAR platform asset configuration."
# NOTE: The new token is intentionally NOT printed to stdout to prevent exposure in logs.
# Retrieve it from your secrets manager or from the raw API response if needed.
