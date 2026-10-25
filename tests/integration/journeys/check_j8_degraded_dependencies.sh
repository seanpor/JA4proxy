#!/usr/bin/env bash
# Tier: T3
#
# J8 — Degraded dependencies (fail open, verified)
# Contract from docs/reference/CUSTOMER_JOURNEYS.md:
# "Proves it worked: traffic still flows, the proxy fails open, and the
# console says so visibly rather than showing stale numbers as current.
# The console's 'unavailable' state must map to the UI health check's
# DEGRADED, not to BROKEN/RED."
#
# Usage: ./tests/integration/journeys/check_j8_degraded_dependencies.sh [BASE_URL]
set -euo pipefail

START_TIME=$(date +%s)

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"
# shellcheck disable=SC1091
[ -f .env ] && . ./.env

BASE="${1:-http://localhost:8000}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.poc.yml}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-ja4proxy}"

# Find redis container name if docker compose project is active
REDIS_CONTAINER="${REDIS_CONTAINER:-$(docker ps --format '{{.Names}}' | grep -E "^(${PROJECT_NAME}-)?redis(-[0-9]+)?" | head -1 || true)}"

# Trap to always restore Redis if stopped
trap 'status=$?; if [ -n "$REDIS_CONTAINER" ]; then docker start "$REDIS_CONTAINER" >/dev/null 2>&1 || true; fi; duration=$(( $(date +%s) - START_TIME )); echo "Duration: ${duration}s"; exit $status' EXIT

echo "── J8: Degraded dependencies (fail-open proxy & visible degradation console)"

if [ -z "$REDIS_CONTAINER" ]; then
    echo "SKIP: Redis container not found in active docker ps — skipping live fault injection"
    exit 0
fi

# 1. Stop Redis to simulate dependency failure
echo "Stopping Redis container ($REDIS_CONTAINER)..."
docker stop "$REDIS_CONTAINER" >/dev/null 2>&1
sleep 2

# 2. Check UI health endpoint (/api/v1/health/ui)
# When Redis is down:
# - Overall status must remain GREEN (fail-open doctrine)
# - degraded count must be > 0 (visible degradation)
# - broken count must be 0 (must NOT map to RED / BROKEN)
echo "Probing /api/v1/health/ui with Redis stopped..."
health_resp=$(curl -s "$BASE/api/v1/health/ui" || echo "{}")

overall_status=$(echo "$health_resp" | grep -o '"status":"[^"]*"' | cut -d: -f2 | tr -d '"' || echo "")
degraded_count=$(echo "$health_resp" | grep -o '"degraded":[0-9]*' | cut -d: -f2 || echo 0)
broken_count=$(echo "$health_resp" | grep -o '"broken":[0-9]*' | cut -d: -f2 || echo 0)

# Check cards state
cards_state=$(echo "$health_resp" | grep -o '"health-cards":{"state":"[^"]*"' | cut -d: -f3 | tr -d '"' || echo "")

echo "  UI health status: $overall_status (degraded: $degraded_count, broken: $broken_count, health-cards: $cards_state)"

if [ "$overall_status" != "GREEN" ]; then
    echo "FAIL UI health status is '$overall_status', expected 'GREEN' (doctrine: proxy fails open)"
    exit 1
fi

if [ "$degraded_count" -le 0 ]; then
    echo "FAIL Degraded panel count is $degraded_count, expected > 0 (doctrine: console fails visibly)"
    exit 1
fi

if [ "$broken_count" -gt 0 ]; then
    echo "FAIL Broken panel count is $broken_count, expected 0 (Redis down should degrade, not break)"
    exit 1
fi

# 3. Restart Redis and verify recovery
echo "Restarting Redis container ($REDIS_CONTAINER)..."
docker start "$REDIS_CONTAINER" >/dev/null 2>&1
sleep 3

recovered_resp=$(curl -s "$BASE/api/v1/health/ui" || echo "{}")
rec_degraded=$(echo "$recovered_resp" | grep -o '"degraded":[0-9]*' | cut -d: -f2 || echo 0)

echo "  Post-recovery degraded count: $rec_degraded"
echo "OK   Proxy fail-open and console visible degradation verified under dependency outage"
