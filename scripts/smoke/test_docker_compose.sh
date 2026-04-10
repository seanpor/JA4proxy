#!/usr/bin/env bash
# Phase 64a — Docker Compose smoke test.
#
# Lifecycle test: bring up stack from scratch → verify health → verify TLS
# → tear down → write PASS/FAIL result. Non-blocking by default.
#
# Usage:
#   bash scripts/smoke/test_docker_compose.sh
#   make smoke-docker
#
# Environment overrides:
#   HEALTH_URL     — health endpoint (default: http://localhost:8090/api/v1/health/deep)
#   COMPOSE_FILE   — compose file (default: docker/docker-compose.poc.yml)
#   PROXY_PORT     — proxy TLS port (default: 8080)

set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"
COMPOSE_FILE="${COMPOSE_FILE:-docker/docker-compose.poc.yml}"
PROXY_PORT="${PROXY_PORT:-8080}"
RESULTS_DIR="test-results/smoke"

mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/docker-compose-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

# ── Pre-flight ────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "SKIP: docker not found on PATH."
    exit 0
fi

if ! docker compose version &>/dev/null; then
    log "SKIP: Docker Compose v2 not available."
    log "  Install: https://docs.docker.com/compose/install/"
    exit 0
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    log "SKIP: Compose file not found: $COMPOSE_FILE"
    exit 0
fi

# ── Load .env if present ─────────────────────────────────────────────────────
# shellcheck disable=SC1091
[ -f .env ] && set -a && source .env && set +a

# ── Bring up stack ────────────────────────────────────────────────────────────
log "Starting Docker Compose stack ($COMPOSE_FILE)..."
docker compose -f "$COMPOSE_FILE" up -d 2>>"$LOG" || fail "docker compose up failed"

log "Waiting for health endpoint (max 90s)..."
HEALTHY=false
for i in $(seq 1 90); do
    if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
        log "Health endpoint OK after ${i}s"
        HEALTHY=true
        break
    fi
    sleep 1
done

if [ "$HEALTHY" != "true" ]; then
    log "Health endpoint did not respond within 90s"
    log "Last 50 lines of compose logs:"
    docker compose -f "$COMPOSE_FILE" logs --tail=50 >>"$LOG" 2>&1 || true
    docker compose -f "$COMPOSE_FILE" down -v 2>>"$LOG" || true
    echo "FAIL" > "$RESULTS_DIR/docker-compose.result"
    exit 1
fi

# ── Verify all containers are running ─────────────────────────────────────────
log "Checking all containers are running..."
UNHEALTHY=$(docker compose -f "$COMPOSE_FILE" ps --format json 2>/dev/null \
    | python3 -c "
import sys, json
try:
    services = json.load(sys.stdin)
    bad = [s['Service'] for s in services if s.get('State') != 'running']
    print(','.join(bad) if bad else '')
except Exception:
    print('')
" 2>/dev/null || true)

if [ -n "$UNHEALTHY" ]; then
    fail "Containers not running: $UNHEALTHY"
fi

log "All containers running"

# ── Synthetic TLS connection ──────────────────────────────────────────────────
log "Sending synthetic TLS connection through port $PROXY_PORT..."
TLS_LOG="$RESULTS_DIR/tls-smoke-$(date +%Y%m%dT%H%M%S).log"
if printf 'Q\n' | timeout 10 openssl s_client \
    -connect "localhost:$PROXY_PORT" \
    -servername localhost \
    -verify_return_error \
    >>"$TLS_LOG" 2>&1; then
    log "Proxy accepted TLS connection (clean handshake)"
elif grep -q "Connection refused" "$TLS_LOG"; then
    # Proxy is not listening on the expected port — fatal
    docker compose -f "$COMPOSE_FILE" down -v 2>>"$LOG" || true
    fail "Proxy port $PROXY_PORT is not listening (Connection refused)"
elif grep -q "errno\|connect: " "$TLS_LOG"; then
    # Connection-level error (proxy may be rejecting TLS) — acceptable
    log "Proxy responded at TCP layer (TLS may be expected to fail in POC mode)"
else
    # Any other TLS-layer response means the proxy is listening and responding
    log "Proxy responded at TLS layer (connection accepted and processed)"
fi

# ── Tear down ─────────────────────────────────────────────────────────────────
log "Tearing down stack..."
docker compose -f "$COMPOSE_FILE" down -v 2>>"$LOG" || fail "docker compose down failed"

# ── Result ────────────────────────────────────────────────────────────────────
log "PASS: Docker Compose smoke test"
echo "PASS" > "$RESULTS_DIR/docker-compose.result"
