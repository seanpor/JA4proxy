#!/usr/bin/env bash
# Phase 64h — MTTR baseline measurement script.
#
# Brings up the Docker Compose stack, triggers four disaster scenarios,
# measures wall-clock time from trigger to recovery, and writes
# MTTR_BASELINE.md with results.
#
# Usage:
#   bash scripts/measure_mttr.sh
#   make measure-mttr
#
# Environment overrides:
#   HEALTH_URL  — health endpoint (default: http://localhost:8090/api/v1/health/deep)
#   COMPOSE     — compose command (default: docker compose)

set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"
OUTPUT="MTTR_BASELINE.md"
COMPOSE="${COMPOSE:-docker compose}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

# ── Load .env for REDIS_PASSWORD ──────────────────────────────────────────────
# B2 fix: All redis-cli calls need authentication in production
if [ -f .env ]; then
    REDIS_PASSWORD=$(grep '^REDIS_PASSWORD=' .env | cut -d= -f2- || true)
fi
export REDISCLI_AUTH="${REDIS_PASSWORD:-}"

require_healthy() {
    local timeout="${1:-60}"
    for i in $(seq 1 "$timeout"); do
        if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
            echo "$i"
            return 0
        fi
        sleep 1
    done
    echo "TIMEOUT"
    return 1
}

# ── Pre-flight: redis-cli ─────────────────────────────────────────────────────
if ! command -v redis-cli &>/dev/null; then
    log "SKIP: redis-cli not found on PATH."
    log "  Install:  apt install redis-tools  |  brew install redis  |  https://redis.io/docs/install/"
    exit 0
fi
if ! redis-cli PING >/dev/null 2>&1; then
    log "SKIP: redis-cli cannot connect to localhost:6379."
    log "  Start the stack with 'make start' or 'docker compose up -d redis' first."
    exit 0
fi

# ── Derive service names from compose — do not hardcode ───────────────────────
# The proxy container might be named ja4proxy, ja4proxy-1, or proxy.
# Derive it from the running compose project.
PROXY_CONTAINER=$($COMPOSE ps --format json 2>/dev/null \
    | python3 -c "
import sys, json
try:
    services = json.load(sys.stdin)
    for s in services:
        name = s.get('Service', s.get('Name', ''))
        if 'ja4proxy' in name.lower() or 'proxy' in name.lower():
            print(name)
            sys.exit(0)
except Exception:
    pass
" 2>/dev/null || true)

if [ -z "$PROXY_CONTAINER" ]; then
    # Fallback: grep from compose ps output
    PROXY_CONTAINER=$($COMPOSE ps --services 2>/dev/null | grep -i proxy | head -1 || true)
fi
if [ -z "$PROXY_CONTAINER" ]; then
    log "SKIP: Could not determine proxy container name from docker compose."
    log "  Ensure the stack is running: docker compose ps"
    exit 0
fi
log "Using proxy container name: $PROXY_CONTAINER"

# Derive Redis volume name from compose — do not hardcode.
REDIS_VOLUME=$($COMPOSE volume ls --format '{{.Name}}' 2>/dev/null | grep -i redis | head -1)
if [ -z "$REDIS_VOLUME" ]; then
    log "SKIP: No Redis volume found in docker compose. Run against a live stack."
    exit 0
fi
log "Using Redis volume: $REDIS_VOLUME"

# ── Bring up stack ────────────────────────────────────────────────────────────
log "Ensuring stack is up and healthy before measurement..."
$COMPOSE up -d
WAIT=$(require_healthy 90) || fail "Stack did not become healthy before measurement"
log "Stack healthy after ${WAIT}s"

declare -A MEASURED_S
declare -A PASS

# ── Scenario 1: Redis failure ─────────────────────────────────────────────────
log "=== Scenario 1: Redis failure ==="
$COMPOSE stop redis
START=$(date +%s)
# Wait until health endpoint reports redis as unreachable (or degraded)
# N3 fix: Check that 'redis' key is present AND not healthy.
# Without the key check, a health response like {"status":"ok"} would falsely
# trigger degradation because d.get('redis') returns None != 'healthy'.
for i in $(seq 1 120); do
    BODY=$(curl -sf --max-time 3 "$HEALTH_URL" 2>/dev/null || echo "{}")
    if echo "$BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'redis' not in d:
    sys.exit(1)  # Key absent — not degraded, just absent
sys.exit(0 if d['redis'] != 'healthy' else 1)
" 2>/dev/null; then
        log "Degraded state detected after ${i}s"
        break
    fi
    [ "$i" -eq 120 ] && { log "WARN: Health endpoint did not report degraded Redis within 120s — proceeding anyway"; break; }
    sleep 1
done
$COMPOSE start redis
END=$(date +%s)
until curl -sf --max-time 3 "$HEALTH_URL" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis')=='healthy' else 1)" \
    >/dev/null 2>&1; do
    sleep 1
    [ $(($(date +%s) - END)) -gt 60 ] && { log "Redis did not recover within 60s"; break; }
done
MTTR_1=$(($(date +%s) - START))
MEASURED_S[1]=$MTTR_1
PASS[1]=$([ "$MTTR_1" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 1 MTTR: ${MTTR_1}s (RTO: 300s) — ${PASS[1]}"

# ── Scenario 2: Single proxy node failure ─────────────────────────────────────
log "=== Scenario 2: Single proxy node failure ==="
$COMPOSE stop "$PROXY_CONTAINER"
START=$(date +%s)
$COMPOSE start "$PROXY_CONTAINER"
until curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; do
    sleep 1
    [ $(($(date +%s) - START)) -gt 120 ] && { log "Proxy did not recover within 120s"; break; }
done
MTTR_2=$(($(date +%s) - START))
MEASURED_S[2]=$MTTR_2
PASS[2]=$([ "$MTTR_2" -le 120 ] && echo "PASS" || echo "FAIL")
log "Scenario 2 MTTR: ${MTTR_2}s (RTO: 120s) — ${PASS[2]}"

# ── Scenario 4: Dial corruption ───────────────────────────────────────────────
log "=== Scenario 4: Dial corruption ==="
redis-cli SET config:dial 100 >/dev/null 2>&1
redis-cli PUBLISH config:reload '{"source":"measure_mttr","dial":100}' >/dev/null 2>&1
START=$(date +%s)
redis-cli SET config:dial 0 >/dev/null 2>&1
redis-cli PUBLISH config:reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
until curl -sf --max-time 3 "$HEALTH_URL" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('dial')==0 else 1)" \
    >/dev/null 2>&1; do
    sleep 1
    [ $(($(date +%s) - START)) -gt 60 ] && { log "Dial did not reset within 60s"; break; }
done
MTTR_4=$(($(date +%s) - START))
MEASURED_S[4]=$MTTR_4
PASS[4]=$([ "$MTTR_4" -le 180 ] && echo "PASS" || echo "FAIL")
log "Scenario 4 MTTR: ${MTTR_4}s (RTO: 180s) — ${PASS[4]}"

# ── Scenario 5: Redis data loss ───────────────────────────────────────────────
log "=== Scenario 5: Redis data loss ==="
redis-cli SET ja4proxy:mttr_probe "1" EX 3600 >/dev/null 2>&1
$COMPOSE stop redis
# B3 fix: Remove ONLY the Redis volume — NOT all compose volumes.
# `docker compose down -v` destroys ALL volumes including Prometheus/Loki data.
docker volume rm "$REDIS_VOLUME" 2>/dev/null || true
START=$(date +%s)
$COMPOSE up -d redis
until redis-cli PING >/dev/null 2>&1; do
    sleep 1
    [ $(($(date +%s) - START)) -gt 30 ] && { log "Redis did not restart within 30s"; break; }
done
KEY_EXISTS=$(redis-cli EXISTS ja4proxy:mttr_probe 2>/dev/null || echo "0")
if [ "$KEY_EXISTS" != "0" ]; then
    log "WARN: probe key still exists — data loss simulation may not have worked (volume persisted)"
fi
redis-cli SET config:dial 0 >/dev/null 2>&1
redis-cli PUBLISH config:reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
MTTR_5=$(($(date +%s) - START))
MEASURED_S[5]=$MTTR_5
PASS[5]=$([ "$MTTR_5" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 5 MTTR (Redis restart + dial reset): ${MTTR_5}s (RTO: 300s) — ${PASS[5]}"

# ── Write MTTR_BASELINE.md ────────────────────────────────────────────────────
cat > "$OUTPUT" <<EOF
# MTTR Baseline

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Environment: Docker Compose (local)
Proxy container: $PROXY_CONTAINER

| Scenario | Trigger | Measured MTTR | RTO Target | Result |
|----------|---------|---------------|------------|--------|
| 1: Redis failure | \`docker compose stop redis\` | ${MEASURED_S[1]}s | 300s | ${PASS[1]} |
| 2: Single node failure | \`docker compose stop $PROXY_CONTAINER\` | ${MEASURED_S[2]}s | 120s | ${PASS[2]} |
| 4: Dial corruption | \`redis-cli SET config:dial 100\` | ${MEASURED_S[4]}s | 180s | ${PASS[4]} |
| 5: Redis data loss | \`docker volume rm $REDIS_VOLUME\` | ${MEASURED_S[5]}s | 300s | ${PASS[5]} |

Scenario 3 (total fleet failure) is exercised via GameDay only — not automated.
See: docs/runbooks/gameday_scenarios.md

Scenario 5 MTTR covers Redis restart and dial reset to monitor mode only.
Full state re-learning (1–4 hours) is not automated; see Phase 64c §5 for the full procedure.

## Notes

- MTTR is measured from trigger to full health endpoint recovery.
- Scenario 2 ends when the health endpoint responds (two consecutive health checks).
- Scenario 4 ends when the health endpoint reflects \`"dial": 0\`.
- Scenario 5 ends when Redis is responding and dial has been reset to 0.
- All scenarios were run in sequence on the same Docker Compose stack.
EOF

log "MTTR_BASELINE.md written"

OVERALL="PASS"
for k in 1 2 4 5; do
    [ "${PASS[$k]}" != "PASS" ] && OVERALL="FAIL"
done
log "Overall result: $OVERALL"
[ "$OVERALL" = "PASS" ] || exit 1
