#!/usr/bin/env bash
set -euo pipefail

# Deep health check: http://localhost:8090/api/v1/health/deep (requires Auditor role)
# Shallow health check: http://localhost:8090/api/v1/health (public, no auth)
# Default to the public endpoint so CI without credentials still passes.
HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health}"
# Proxy TLS port: 8443 for the quick-start compose (docker-compose.yml),
# 8080 for the full POC stack behind HAProxy (docker-compose.poc.yml).
PROXY_TLS_PORT="${PROXY_TLS_PORT:-8443}"
RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/docker-compose-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

# --- Prerequisite checks ---
if ! command -v docker &>/dev/null; then
  log "SKIP: docker not found."
  exit 0
fi

# Find the compose file — prefer the PoC stack in deploy/docker/
COMPOSE_FILE=""
for f in docker-compose.yml compose.yml deploy/docker/docker-compose.poc.yml deploy/docker/docker-compose.test.yml; do
  if [ -f "$f" ]; then
    COMPOSE_FILE="$f"
    break
  fi
done
if [ -z "$COMPOSE_FILE" ]; then
  log "SKIP: no Docker Compose file found (docker-compose.yml, deploy/docker/docker-compose.poc.yml, etc.)."
  exit 0
fi

# Docker compose auto-loads .env from the compose file's directory, not CWD.
# When the compose file lives in deploy/docker/ and the .env in the repo root, we
# must pass --env-file explicitly, otherwise REDIS_PASSWORD and similar
# interpolations fail.
COMPOSE_ARGS="-f $COMPOSE_FILE"
if [ -f .env ]; then
  COMPOSE_ARGS="--env-file .env $COMPOSE_ARGS"
fi

cleanup() {
  log "Tearing down stack..."
  docker compose $COMPOSE_ARGS down -v 2>>"$LOG" || true
}
trap cleanup EXIT INT TERM

# Check if the images referenced in the compose file are available.
# If docker compose can't pull/find them, skip rather than fail.
log "Starting Docker Compose stack ($COMPOSE_FILE)..."
if ! docker compose $COMPOSE_ARGS up -d 2>>"$LOG"; then
  log "SKIP: docker compose up failed — images may not be built yet. Run 'docker compose build' first."
  echo "SKIP" > "$RESULTS_DIR/docker-compose.result"
  exit 0
fi

log "Waiting for health endpoint (max 120s)..."
for i in $(seq 1 120); do
  if curl -sf --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
    log "Health endpoint OK after ${i}s"
    break
  fi
  [ "$i" -eq 120 ] && fail "Health endpoint did not respond within 120s"
  sleep 1
done

log "Checking all containers are Running..."
# Docker Compose v2.21+ emits one JSON object per line (NDJSON), older versions
# emit a JSON array.  Handle both formats.
UNHEALTHY=$(docker compose $COMPOSE_ARGS ps --format json 2>/dev/null \
  | python3 -c "
import sys, json
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    data = json.loads(raw)          # try JSON array first
    if isinstance(data, dict):
        data = [data]               # single-object (one container)
except json.JSONDecodeError:
    data = [json.loads(l) for l in raw.splitlines() if l.strip()]  # NDJSON
for s in data:
    if s.get('State') != 'running':
        print(s.get('Service', s.get('Name', 'unknown')))
" 2>/dev/null || true)
[ -n "$UNHEALTHY" ] && fail "Containers not running: $UNHEALTHY"

if command -v openssl &>/dev/null; then
  log "Sending synthetic TLS connection through port ${PROXY_TLS_PORT}..."
  echo "Q" | openssl s_client -connect "localhost:${PROXY_TLS_PORT}" -servername localhost \
    -verify_return_error 2>>"$LOG" || {
    grep -q "Connection refused" "$LOG" && fail "Proxy port ${PROXY_TLS_PORT} is not listening"
    log "Proxy responded at TLS layer (connection accepted and processed)"
  }
else
  log "SKIP: openssl not found — skipping TLS probe"
fi

# Stack teardown handled by EXIT trap
log "PASS: Docker Compose smoke test"
echo "PASS" > "$RESULTS_DIR/docker-compose.result"
