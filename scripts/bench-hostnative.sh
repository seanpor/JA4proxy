#!/usr/bin/env bash
# bench-hostnative.sh — end-to-end throughput benchmark with the engine running
# HOST-NATIVE (no docker-proxy in the inbound path).
#
# The published bridge port (HOST_PORT_DIRECT, default 8081) is served by
# docker-proxy, a userland TCP relay that serialises throughput to a few
# hundred CPS regardless of CPU/memory limits. Production is expected to run
# with host networking; this script reproduces that topology so the measured
# number reflects the engine, not the bridge.
#
# It brings up only Redis + the mock backend in Docker (with their CPU/mem caps
# lifted so they are not the bottleneck), runs ja4pd on the host wired to those
# two services, and drives it with `ja4p test benchmark`.
#
# Tunables (env): BENCH_WORKERS BENCH_DURATION BENCH_GOOD_RATE BENCH_BAD_RATE
#                 PROXY_PORT METRICS_PORT
# (Prefixed BENCH_* to avoid colliding with the Makefile's own WORKERS var.)
# Extra benchmark flags can be passed via ARGS. Redis + backend are left running
# afterwards for reuse; see the teardown hint printed at the end.
set -euo pipefail

cd "$(dirname "$0")/.."

WORKERS="${BENCH_WORKERS:-32}"
DURATION="${BENCH_DURATION:-30}"
GOOD_RATE="${BENCH_GOOD_RATE:-30000}"
BAD_RATE="${BENCH_BAD_RATE:-0}"
PROXY_PORT="${PROXY_PORT:-18080}"
METRICS_PORT="${METRICS_PORT:-29090}"
BACKEND_PORT="${BACKEND_PORT:-8443}"
PROJECT="${COMPOSE_PROJECT_NAME:-ja4proxy}"
COMPOSE_BASE="deploy/docker/docker-compose.poc.yml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
say() { echo -e "${GREEN}▶${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
die() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

[ -f .env ] || die ".env not found — run 'make start-poc' once to generate it."
set -a; source .env; set +a
[ -n "${REDIS_PASSWORD:-}" ] || die "REDIS_PASSWORD not set in .env"
[ -x ./bin/ja4pd ] || die "bin/ja4pd missing — run 'make go-build'"
[ -x ./bin/ja4p ]  || die "bin/ja4p missing — run 'make cli-build'"

port_busy() { ss -ltn 2>/dev/null | grep -q ":$1 "; }
port_busy "$PROXY_PORT"   && die "port $PROXY_PORT already in use — set PROXY_PORT=<free port>"
port_busy "$METRICS_PORT" && die "port $METRICS_PORT already in use — set METRICS_PORT=<free port>"

# Temp override: lift the CPU/mem caps on redis + backend so neither becomes the
# bottleneck while we push the host-native engine.
OVERRIDE="$(mktemp --suffix=.bench-hostnative.yml)"
cat > "$OVERRIDE" <<'YAML'
services:
  backend:
    deploy:
      resources:
        limits: {cpus: '8.0', memory: 4G}
  redis:
    deploy:
      resources:
        limits: {cpus: '4.0', memory: 4G}
YAML

JA4PID=""
cleanup() {
  [ -n "$JA4PID" ] && kill "$JA4PID" 2>/dev/null || true
  [ -n "$JA4PID" ] && wait "$JA4PID" 2>/dev/null || true
  rm -f "$OVERRIDE"
}
trap cleanup EXIT

dc() { docker compose -p "$PROJECT" -f "$COMPOSE_BASE" -f "$OVERRIDE" --env-file .env "$@"; }

say "Starting Redis + backend (uncapped) ..."
dc up -d redis backend >/dev/null

say "Waiting for backend health ..."
for i in $(seq 1 30); do
  if dc exec -T backend curl -ksf "https://localhost:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    break
  fi
  [ "$i" = 30 ] && die "backend did not become healthy in 30s"
  sleep 1
done

ipof() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" 2>/dev/null | awk '{print $1}'; }
REDIS_IP="$(ipof "${PROJECT}-redis-1")"
BACKEND_IP="$(ipof "${PROJECT}-backend-1")"
[ -n "$REDIS_IP" ]   || die "could not resolve redis container IP"
[ -n "$BACKEND_IP" ] || die "could not resolve backend container IP"
say "Redis @ ${REDIS_IP}:6379   Backend @ ${BACKEND_IP}:${BACKEND_PORT}"

LOG="$(mktemp --suffix=.ja4pd-hostnative.log)"
say "Launching host-native ja4pd on :${PROXY_PORT} (log: ${LOG}) ..."
PROXY_PORT="$PROXY_PORT" METRICS_PORT="$METRICS_PORT" METRICS_BIND_HOST=127.0.0.1 \
  BACKEND_HOST="$BACKEND_IP" BACKEND_PORT="$BACKEND_PORT" \
  REDIS_HOST="$REDIS_IP" REDIS_PORT=6379 REDIS_PASSWORD="$REDIS_PASSWORD" \
  CONFIG_PATH=config/proxy.yml ENVIRONMENT=development \
  ./bin/ja4pd >"$LOG" 2>&1 &
JA4PID=$!

for i in $(seq 1 15); do
  port_busy "$PROXY_PORT" && break
  if ! kill -0 "$JA4PID" 2>/dev/null; then echo "--- ja4pd log ---"; cat "$LOG"; die "ja4pd exited during startup"; fi
  [ "$i" = 15 ] && { echo "--- ja4pd log ---"; cat "$LOG"; die "ja4pd did not start listening on :${PROXY_PORT}"; }
  sleep 1
done

echo
say "Benchmarking host-native :${PROXY_PORT} (workers=${WORKERS}, ${DURATION}s, good-rate=${GOOD_RATE}) ..."
warn "Closed-loop: CPS ≈ workers ÷ latency. If CPS plateaus while latency climbs, the engine is saturated — that plateau is the real ceiling. Raise WORKERS to confirm."
echo
./bin/ja4p test benchmark \
  --host "127.0.0.1:${PROXY_PORT}" \
  --good-rate "$GOOD_RATE" --bad-rate "$BAD_RATE" \
  --workers "$WORKERS" --duration "$DURATION" ${ARGS:-}

echo
say "Done. Redis + backend left running. Tear down with:"
echo "    docker compose -p ${PROJECT} -f ${COMPOSE_BASE} --env-file .env down"
