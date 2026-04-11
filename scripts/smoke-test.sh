#!/bin/bash
# Quick smoke test to verify POC is working
# Tests basic connectivity without running full test suite

# No set -e: the script tracks failures via $FAILED and exits accordingly.

# Load .env if available
[ -f .env ] && set -a && source .env && set +a
REDIS_PW="${REDIS_PASSWORD:-changeme}"

# Ports match `make start` Docker stack (docker-compose.poc.yml)
PROXY_PORT="${PROXY_PORT:-8081}"
METRICS_PORT="${METRICS_PORT:-9090}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "JA4 Proxy Smoke Test"
echo "=========================================="
echo ""

FAILED=0

# Test Proxy accepts TCP connections
echo -n "Testing Proxy (port ${PROXY_PORT})... "
if timeout 5 bash -c "echo '' | nc -w2 localhost ${PROXY_PORT}" 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Proxy Health endpoint
echo -n "Testing Proxy Health... "
if curl -sf --max-time 10 "http://localhost:${METRICS_PORT}/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Proxy Metrics
echo -n "Testing Proxy Metrics... "
if curl -sf --max-time 10 "http://localhost:${METRICS_PORT}/metrics" | grep -q "ja4proxy_" 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Redis
echo -n "Testing Redis... "
if docker compose -f docker/docker-compose.poc.yml exec -T redis redis-cli -a "${REDIS_PW}" ping 2>/dev/null | grep -q PONG; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Prometheus
echo -n "Testing Prometheus... "
if curl -sf --max-time 10 http://localhost:9091/-/healthy > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠${NC} (optional)"
fi

echo ""
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All smoke tests passed!${NC}"
    echo "=========================================="
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo "=========================================="
    echo ""
    echo "Troubleshooting:"
    echo "  1. Ensure services are running: ./scripts/start-poc.sh"
    echo "  2. Check logs: docker compose -f docker/docker-compose.poc.yml logs"
    echo "  3. Check service status: docker compose -f docker/docker-compose.poc.yml ps"
    exit 1
fi
