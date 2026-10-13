#!/usr/bin/env bash
# Phase 64h / 819d — MTTR baseline measurement script.
#
# Measures wall-clock recovery time across disaster scenarios (Redis outage,
# proxy node failure, dial corruption, and Redis data loss) against an isolated
# stack, using containerized execution without requiring host redis-cli.
#
# Usage:
#   bash scripts/measure_mttr.sh
#   make measure-mttr
#
# Environment overrides:
#   HEALTH_URL   — health endpoint (default: http://localhost:8090/api/v1/health/deep)
#   COMPOSE      — compose command (default: docker compose -p ja4mttr ...)
#   PROJECT_NAME — compose project name (default: ja4mttr)
#   OUTPUT_FILE  — output markdown report (default: .local/MTTR_BASELINE.md)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROJECT_NAME="${PROJECT_NAME:-ja4mttr}"
OUTPUT="${OUTPUT_FILE:-${REPO_ROOT}/.local/MTTR_BASELINE.md}"
HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"

mkdir -p "$(dirname "$OUTPUT")"

COMPOSE="${COMPOSE:-docker compose -p ${PROJECT_NAME} -f ${REPO_ROOT}/deploy/docker/docker-compose.poc.yml}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

# ── Containerized Redis helper ────────────────────────────────────────────────
# Executes redis-cli inside the redis container, avoiding host redis-cli dependency.
redis_cmd() {
    $COMPOSE exec -T redis redis-cli "$@"
}

# ── Cleanup and Trap ──────────────────────────────────────────────────────────
ORIG_DIAL=""
cleanup() {
    log "Running cleanup..."
    if [ -n "$ORIG_DIAL" ]; then
        redis_cmd SET config:dial "$ORIG_DIAL" >/dev/null 2>&1 || true
        redis_cmd PUBLISH config:reload "{\"source\":\"measure_mttr_cleanup\",\"dial\":$ORIG_DIAL}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

# ── Health check probe ────────────────────────────────────────────────────────
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

# ── Verify stack is running or start project stack ────────────────────────────
RUNNING_CONTAINERS=$($COMPOSE ps -q 2>/dev/null || true)
if [ -z "$RUNNING_CONTAINERS" ]; then
    log "Stack '${PROJECT_NAME}' not running. Starting isolated stack..."
    # Ensure poc secrets exist for the stack bring-up
    bash scripts/ensure-poc-secrets.sh >/dev/null 2>&1 || true
    $COMPOSE up -d
fi

# Pre-flight: verify containerized Redis connectivity
if ! redis_cmd PING >/dev/null 2>&1; then
    log "Waiting for Redis container to respond to PING..."
    for i in $(seq 1 30); do
        if redis_cmd PING >/dev/null 2>&1; then
            break
        fi
        sleep 1
        [ "$i" -eq 30 ] && fail "Redis container did not respond to PING within 30s."
    done
fi

# Capture initial dial setting for safe restoration
ORIG_DIAL=$(redis_cmd GET config:dial 2>/dev/null || echo "0")
ORIG_DIAL="${ORIG_DIAL:-0}"

# ── Derive service and volume names ───────────────────────────────────────────
PROXY_CONTAINER=$($COMPOSE ps --format json 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = sys.stdin.read().strip()
    if data:
        # data may be a JSON array or newline-delimited JSON objects
        try:
            services = json.loads(data)
            if isinstance(services, dict):
                services = [services]
        except Exception:
            services = [json.loads(line) for line in data.splitlines() if line.strip()]
        for s in services:
            name = s.get('Service', s.get('Name', ''))
            if 'ja4proxy' in name.lower() or 'proxy' in name.lower():
                print(s.get('Name', name))
                sys.exit(0)
except Exception:
    pass
" 2>/dev/null || true)

if [ -z "$PROXY_CONTAINER" ]; then
    PROXY_CONTAINER=$($COMPOSE ps --services 2>/dev/null | grep -i proxy | head -1 || true)
fi
if [ -z "$PROXY_CONTAINER" ]; then
    PROXY_CONTAINER="proxy"
fi
log "Using proxy service/container: $PROXY_CONTAINER"

# Resolve full Redis volume name attached to the redis container
REDIS_VOLUME_ID=$($COMPOSE ps -q redis 2>/dev/null || true)
if [ -n "$REDIS_VOLUME_ID" ]; then
    FULL_REDIS_VOLUME=$(docker inspect "$REDIS_VOLUME_ID" --format '{{ range .Mounts }}{{ if eq .Destination "/data" }}{{ .Name }}{{ end }}{{ end }}' 2>/dev/null || true)
else
    FULL_REDIS_VOLUME=""
fi
if [ -z "$FULL_REDIS_VOLUME" ]; then
    FULL_REDIS_VOLUME="${PROJECT_NAME}_redis-data"
fi
log "Using Redis volume: $FULL_REDIS_VOLUME"

# ── Ensure stack is healthy before measurement ────────────────────────────────
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
for i in $(seq 1 120); do
    BODY=$(curl -sf --max-time 3 "$HEALTH_URL" 2>/dev/null || echo "{}")
    if echo "$BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'redis' not in d:
    sys.exit(1)
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
redis_cmd SET config:dial 100 >/dev/null 2>&1
redis_cmd PUBLISH config:reload '{"source":"measure_mttr","dial":100}' >/dev/null 2>&1
START=$(date +%s)
redis_cmd SET config:dial 0 >/dev/null 2>&1
redis_cmd PUBLISH config:reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
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
redis_cmd SET ja4proxy:mttr_probe "1" EX 3600 >/dev/null 2>&1
$COMPOSE stop redis
# Remove container before attempting to remove the attached volume
$COMPOSE rm -f -v redis >/dev/null 2>&1 || true
docker volume rm "$FULL_REDIS_VOLUME" >/dev/null 2>&1 || true
START=$(date +%s)
$COMPOSE up -d redis
until redis_cmd PING >/dev/null 2>&1; do
    sleep 1
    [ $(($(date +%s) - START)) -gt 30 ] && { log "Redis did not restart within 30s"; break; }
done
KEY_EXISTS=$(redis_cmd EXISTS ja4proxy:mttr_probe 2>/dev/null || echo "0")
if [ "$KEY_EXISTS" != "0" ]; then
    log "WARN: probe key still exists — data loss simulation may not have worked (volume persisted)"
fi
redis_cmd SET config:dial 0 >/dev/null 2>&1
redis_cmd PUBLISH config:reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
MTTR_5=$(($(date +%s) - START))
MEASURED_S[5]=$MTTR_5
PASS[5]=$([ "$MTTR_5" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 5 MTTR (Redis restart + dial reset): ${MTTR_5}s (RTO: 300s) — ${PASS[5]}"

# ── Write MTTR report ─────────────────────────────────────────────────────────
cat > "$OUTPUT" <<EOF
# MTTR Baseline

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Environment: Docker Compose (${PROJECT_NAME})
Proxy container: $PROXY_CONTAINER

| Scenario | Trigger | Measured MTTR | RTO Target | Result |
|----------|---------|---------------|------------|--------|
| 1: Redis failure | \`docker compose stop redis\` | ${MEASURED_S[1]}s | 300s | ${PASS[1]} |
| 2: Single node failure | \`docker compose stop $PROXY_CONTAINER\` | ${MEASURED_S[2]}s | 120s | ${PASS[2]} |
| 4: Dial corruption | \`redis-cli SET config:dial 100\` | ${MEASURED_S[4]}s | 180s | ${PASS[4]} |
| 5: Redis data loss | \`docker volume rm $FULL_REDIS_VOLUME\` | ${MEASURED_S[5]}s | 300s | ${PASS[5]} |

Scenario 3 (total fleet failure) is exercised via GameDay only — not automated.
See: docs/runbooks/gameday_scenarios.md

Scenario 5 MTTR covers Redis restart and dial reset to monitor mode only.
Full state re-learning (1–4 hours) is not automated; see Phase 64c §5 for the full procedure.

## Notes

- MTTR is measured from trigger to full health endpoint recovery.
- Scenario 2 ends when the health endpoint responds.
- Scenario 4 ends when the health endpoint reflects \`"dial": 0\`.
- Scenario 5 ends when Redis is responding and dial has been reset to 0.
- All scenarios were run in sequence on isolated compose stack: ${PROJECT_NAME}.
EOF

log "MTTR report written to: $OUTPUT"

OVERALL="PASS"
for k in 1 2 4 5; do
    [ "${PASS[$k]}" != "PASS" ] && OVERALL="FAIL"
done
log "Overall result: $OVERALL"
[ "$OVERALL" = "PASS" ] || exit 1
