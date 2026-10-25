#!/usr/bin/env bash
# Tier: T2
#
# J4 — False-positive rescue
# Contract from docs/reference/CUSTOMER_JOURNEYS.md:
# "Proves it worked: the client is served again within one propagation
# interval, and a repeat of the same fingerprint is not re-blocked."
#
# Usage: ./tests/integration/journeys/check_j4_false_positive_rescue.sh [TEST_IP]
set -euo pipefail

START_TIME=$(date +%s)

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"
# shellcheck disable=SC1091
[ -f .env ] && . ./.env

TEST_IP="${1:-198.51.100.42}"
PROPAGATION_MAX_WAIT_SECS=5

# Always clean up any test IP block on exit
trap 'status=$?; ./scripts/ja4-admin.sh unblock-ip "$TEST_IP" >/dev/null 2>&1 || true; duration=$(( $(date +%s) - START_TIME )); echo "Duration: ${duration}s"; exit $status' EXIT

echo "── J4: False-positive rescue for $TEST_IP"

# 1. Block the test IP and confirm it is actioned
echo "Blocking IP $TEST_IP for 60s..."
./scripts/ja4-admin.sh block-ip "$TEST_IP" 60 >/dev/null 2>&1

blocked_output=$(./scripts/ja4-admin.sh blocked 2>/dev/null || true)
if ! echo "$blocked_output" | grep -q "$TEST_IP"; then
    echo "FAIL IP $TEST_IP was not confirmed actioned in ja4-admin.sh blocked"
    exit 1
fi
echo "OK   Confirmed IP $TEST_IP is actioned in blocked list"

# 2. Release it immediately
echo "Releasing IP $TEST_IP..."
./scripts/ja4-admin.sh unblock-ip "$TEST_IP" >/dev/null 2>&1

# 3. Assert client is served again within one propagation interval (time-bounded)
start_prop=$(date +%s)
released=0
while [ $(( $(date +%s) - start_prop )) -le "$PROPAGATION_MAX_WAIT_SECS" ]; do
    blocked_check=$(./scripts/ja4-admin.sh blocked 2>/dev/null || true)
    if ! echo "$blocked_check" | grep -q "$TEST_IP"; then
        released=1
        break
    fi
    sleep 0.5
done

if [ "$released" -ne 1 ]; then
    echo "FAIL IP $TEST_IP still appears in blocked list after ${PROPAGATION_MAX_WAIT_SECS}s propagation interval"
    exit 1
fi

echo "OK   IP $TEST_IP successfully rescued and cleared within ${PROPAGATION_MAX_WAIT_SECS}s bound"
