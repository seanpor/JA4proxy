#!/bin/bash
set -euo pipefail

# Load .env if available
[ -f .env ] && set -a && source .env && set +a
REDIS_PW="${REDIS_PASSWORD:-changeme}"

# JA4proxy Performance Benchmark Runner
# Tests throughput with 1, 2, and 4 proxy instances

DURATION=${1:-30}
GOOD_RATE=${2:-5}
BAD_RATES=${3:-"50,100,200,500"}
REPORT_DIR="reports"
REPORT_FILE="${REPORT_DIR}/performance-benchmark.md"
JSON_FILE="${REPORT_DIR}/performance-benchmark.json"

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║            JA4proxy Performance Benchmark                        ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Duration:    ${DURATION}s per scenario"
echo "  Good rate:   ${GOOD_RATE}/s"
echo "  Bad rates:   ${BAD_RATES}"
echo ""

mkdir -p "$REPORT_DIR"

# Ensure services are running
if ! curl -sf http://localhost:9090/metrics > /dev/null 2>&1; then
    echo "✗ Proxy not running. Start with ./start-all.sh first."
    exit 1
fi
echo "✓ Services are running"

# Flush Redis rate counters for clean test
docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" FLUSHALL > /dev/null 2>&1 || true
echo "✓ Redis flushed"

# ─────────────────────────────────────────────────────────────────────
# TEST 1: Single proxy (current setup)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 1: Single Proxy Instance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" FLUSHALL > /dev/null 2>&1 || true
docker compose -f docker-compose.poc.yml run --rm \
    -e PYTHONUNBUFFERED=1 \
    trafficgen python3 /app/scripts/benchmark.py \
    --host proxy --port 8080 \
    --good-rate "$GOOD_RATE" \
    --bad-rates "$BAD_RATES" \
    --duration "$DURATION" \
    --proxy-counts 1 \
    --output /tmp/bench-1.md \
    --json /tmp/bench-1.json 2>&1

# Copy results out
docker compose -f docker-compose.poc.yml run --rm \
    -v "$(pwd)/$REPORT_DIR:/reports" \
    trafficgen cp /tmp/bench-1.md /tmp/bench-1.json /reports/ 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────
# TEST 2: Two proxy instances
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 2: Two Proxy Instances"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Scale proxy to 2 and update HAProxy
docker compose -f docker-compose.poc.yml up -d --scale proxy=2 --no-recreate 2>/dev/null || true

# Get the container names/IPs for the scaled proxies
sleep 3
PROXY_IPS=$(docker compose -f docker-compose.poc.yml ps -q proxy | xargs -I{} docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null | tr '\n' ' ')
echo "  Proxy IPs: $PROXY_IPS"

# Generate HAProxy config for 2 backends
cat > /tmp/haproxy-bench.cfg << 'HAEOF'
global
    log stdout format raw local0
    maxconn 4096

defaults
    log     global
    mode    tcp
    option  tcplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend tls_in
    bind *:443
    default_backend ja4proxy_backend

backend ja4proxy_backend
HAEOF

# Add proxy servers dynamically
i=1
for ip in $PROXY_IPS; do
    echo "    server proxy${i} ${ip}:8080 send-proxy-v2" >> /tmp/haproxy-bench.cfg
    i=$((i+1))
done

cat >> /tmp/haproxy-bench.cfg << 'HAEOF'

frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 5s
HAEOF

# Update HAProxy config
docker cp /tmp/haproxy-bench.cfg ja4proxy-haproxy:/usr/local/etc/haproxy/haproxy.cfg
docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy
sleep 2

docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" FLUSHALL > /dev/null 2>&1 || true

docker compose -f docker-compose.poc.yml run --rm \
    -e PYTHONUNBUFFERED=1 \
    trafficgen python3 /app/scripts/benchmark.py \
    --host proxy --port 8080 \
    --good-rate "$GOOD_RATE" \
    --bad-rates "$BAD_RATES" \
    --duration "$DURATION" \
    --proxy-counts 2 \
    --output /tmp/bench-2.md \
    --json /tmp/bench-2.json 2>&1

# ─────────────────────────────────────────────────────────────────────
# TEST 3: Four proxy instances
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 3: Four Proxy Instances"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker compose -f docker-compose.poc.yml up -d --scale proxy=4 --no-recreate 2>/dev/null || true
sleep 3

PROXY_IPS=$(docker compose -f docker-compose.poc.yml ps -q proxy | xargs -I{} docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null | tr '\n' ' ')
echo "  Proxy IPs: $PROXY_IPS"

cat > /tmp/haproxy-bench.cfg << 'HAEOF'
global
    log stdout format raw local0
    maxconn 4096

defaults
    log     global
    mode    tcp
    option  tcplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend tls_in
    bind *:443
    default_backend ja4proxy_backend

backend ja4proxy_backend
HAEOF

i=1
for ip in $PROXY_IPS; do
    echo "    server proxy${i} ${ip}:8080 send-proxy-v2" >> /tmp/haproxy-bench.cfg
    i=$((i+1))
done

cat >> /tmp/haproxy-bench.cfg << 'HAEOF'

frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 5s
HAEOF

docker cp /tmp/haproxy-bench.cfg ja4proxy-haproxy:/usr/local/etc/haproxy/haproxy.cfg
docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy
sleep 2

docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" FLUSHALL > /dev/null 2>&1 || true

docker compose -f docker-compose.poc.yml run --rm \
    -e PYTHONUNBUFFERED=1 \
    trafficgen python3 /app/scripts/benchmark.py \
    --host proxy --port 8080 \
    --good-rate "$GOOD_RATE" \
    --bad-rates "$BAD_RATES" \
    --duration "$DURATION" \
    --proxy-counts 4 \
    --output /tmp/bench-4.md \
    --json /tmp/bench-4.json 2>&1

# ─────────────────────────────────────────────────────────────────────
# Restore single proxy
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "Restoring single proxy configuration..."
docker compose -f docker-compose.poc.yml up -d --scale proxy=1 --no-recreate 2>/dev/null || true
docker cp "$(pwd)/ha-config/haproxy.cfg" ja4proxy-haproxy:/usr/local/etc/haproxy/haproxy.cfg
docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy

# ─────────────────────────────────────────────────────────────────────
# Combine results
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Benchmark Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Results in: $REPORT_DIR/"
echo ""
