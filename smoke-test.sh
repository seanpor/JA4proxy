#!/bin/bash
# Quick smoke test to verify POC is working
# Tests basic connectivity without running full test suite

set -e

# Load .env if available
[ -f .env ] && set -a && source .env && set +a
REDIS_PW="${REDIS_PASSWORD:-changeme}"

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

# Test Backend
echo -n "Testing Backend... "
if curl -sk https://localhost:8443/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Backend endpoints
echo -n "Testing Backend Echo... "
RESPONSE=$(curl -sk https://localhost:8443/api/echo)
if echo "$RESPONSE" | grep -q "method"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Proxy Metrics
echo -n "Testing Proxy Metrics... "
if curl -sf http://localhost:9090/metrics > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Redis
echo -n "Testing Redis... "
if docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" ping 2>/dev/null | grep -q PONG; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test Prometheus
echo -n "Testing Prometheus... "
if curl -sf http://localhost:9091/-/healthy > /dev/null 2>&1; then
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
    echo "  1. Ensure services are running: ./start-poc.sh"
    echo "  2. Check logs: docker-compose -f docker-compose.poc.yml logs"
    echo "  3. Check service status: docker-compose -f docker-compose.poc.yml ps"
    exit 1
fi
