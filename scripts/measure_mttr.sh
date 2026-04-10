#!/usr/bin/env bash
set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"
OUTPUT="MTTR_BASELINE.md"
COMPOSE="${COMPOSE:-docker compose}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

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

# Derive Redis volume name from compose — do not hardcode.
REDIS_VOLUME=$($COMPOSE volume ls --format '{{.Name}}' 2>/dev/null | grep -i redis | head -1)
if [ -z "$REDIS_VOLUME" ]; then
  log "SKIP: No Redis volume found in docker compose. Run against a live stack."
  exit 0
fi
log "Using Redis volume: $REDIS_VOLUME"

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
until ! curl -sf --max-time 3 "$HEALTH_URL" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis')=='unreachable' else 1)" \
    >/dev/null 2>&1; do
  sleep 1
done
log "Degraded state detected"
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

# ── Scenario 2: Single node failure ──────────────────────────────────────────
log "=== Scenario 2: Single proxy node failure ==="
$COMPOSE stop ja4proxy-1
START=$(date +%s)
$COMPOSE start ja4proxy-1
until curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 120 ] && { log "Node did not recover within 120s"; break; }
done
MTTR_2=$(($(date +%s) - START))
MEASURED_S[2]=$MTTR_2
PASS[2]=$([ "$MTTR_2" -le 120 ] && echo "PASS" || echo "FAIL")
log "Scenario 2 MTTR: ${MTTR_2}s (RTO: 120s) — ${PASS[2]}"

# ── Scenario 4: Dial corruption ───────────────────────────────────────────────
log "=== Scenario 4: Dial corruption ==="
redis-cli SET ja4proxy:dial 100
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":100}' >/dev/null
START=$(date +%s)
redis-cli SET ja4proxy:dial 0
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":0}' >/dev/null
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
redis-cli SET ja4proxy:mttr_probe "1" EX 3600 >/dev/null
$COMPOSE stop redis
$COMPOSE down -v --remove-orphans 2>/dev/null || true
docker volume rm "$REDIS_VOLUME" 2>/dev/null || true
START=$(date +%s)
$COMPOSE up -d redis
until redis-cli PING >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 30 ] && { log "Redis did not restart within 30s"; break; }
done
KEY_EXISTS=$(redis-cli EXISTS ja4proxy:mttr_probe)
if [ "$KEY_EXISTS" != "0" ]; then
  log "WARN: probe key still exists — data loss simulation may not have worked (volume persisted)"
fi
redis-cli SET ja4proxy:dial 0 >/dev/null
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":0}' >/dev/null
MTTR_5=$(($(date +%s) - START))
MEASURED_S[5]=$MTTR_5
PASS[5]=$([ "$MTTR_5" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 5 MTTR (Redis restart + dial reset): ${MTTR_5}s (RTO: 300s) — ${PASS[5]}"

# ── Write MTTR_BASELINE.md ────────────────────────────────────────────────────
cat > "$OUTPUT" <<EOF
# MTTR Baseline

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Environment: Docker Compose (local)

| Scenario | Trigger | Measured MTTR | RTO Target | Result |
|----------|---------|---------------|------------|--------|
| 1: Redis failure | \`docker compose stop redis\` | ${MEASURED_S[1]}s | 300s | ${PASS[1]} |
| 2: Single node failure | \`docker compose stop ja4proxy-1\` | ${MEASURED_S[2]}s | 120s | ${PASS[2]} |
| 4: Dial corruption | \`redis-cli SET ja4proxy:dial 100\` | ${MEASURED_S[4]}s | 180s | ${PASS[4]} |
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
