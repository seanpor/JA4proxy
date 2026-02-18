#!/bin/bash
# POC Status Check - Verify everything is ready for demo

set -e

# Load .env if available
[ -f .env ] && set -a && source .env && set +a
REDIS_PW="${REDIS_PASSWORD:-changeme}"

echo "╔════════════════════════════════════════════════════╗"
echo "║   JA4proxy POC Status Check                       ║"
echo "║   Verifying all components for demo               ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1"
        ERRORS=$((ERRORS + 1))
    fi
}

# 1. Check Docker containers
echo "========================================
1. Docker Containers
========================================"
docker compose -f docker-compose.poc.yml ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}" | head -10
echo ""

# 2. Check services are responding
echo "========================================
2. Service Health Checks
========================================"

curl -sf http://localhost:8080/health > /dev/null 2>&1
check "Proxy health endpoint (localhost:8080/health)"

curl -sf http://localhost:9090/metrics > /dev/null 2>&1
check "Proxy metrics endpoint (localhost:9090/metrics)"

curl -sf http://localhost:8081/health > /dev/null 2>&1
check "Backend health endpoint (localhost:8081/health)"

redis-cli -h localhost -p 6379 -a "${REDIS_PW}" ping > /dev/null 2>&1
check "Redis connection (localhost:6379)"

curl -sf http://localhost:9091/-/ready > /dev/null 2>&1
check "Prometheus endpoint (localhost:9091)"

echo ""

# 3. Check test execution
echo "========================================
3. Test Suite Status
========================================"
echo "Running integration tests..."
./run-tests.sh > /tmp/test-output.log 2>&1
check "Integration tests pass"
echo ""

# 4. Check documentation
echo "========================================
4. Documentation
========================================"

[ -f README.md ]
check "README.md exists"

[ -f POC_QUICKSTART.md ]
check "POC_QUICKSTART.md exists"

[ -f POC_SECURITY_SUMMARY.txt ]
check "POC_SECURITY_SUMMARY.txt exists"

[ -d docs ]
check "docs/ directory exists"

[ -f docs/guides/ALERTS_SETUP.md ]
check "Alerts setup guide exists"

[ -f docs/guides/GRAFANA_DASHBOARD.md ]
check "Grafana dashboard guide exists"

echo ""

# 5. Check scripts
echo "========================================
5. Demo Scripts
========================================"

[ -x start-poc.sh ]
check "start-poc.sh is executable"

[ -x test-ja4-blocking.sh ]
check "test-ja4-blocking.sh is executable"

[ -x smoke-test.sh ]
check "smoke-test.sh is executable"

[ -x run-tests.sh ]
check "run-tests.sh is executable"

echo ""

# 6. Check configuration
echo "========================================
6. Configuration Files
========================================"

[ -f config/config.yaml ]
check "config/config.yaml exists"

[ -f docker-compose.poc.yml ]
check "docker-compose.poc.yml exists"

[ -f monitoring/prometheus/prometheus.yml ]
check "Prometheus config exists"

[ -f monitoring/prometheus/alerts.yml ]
check "Alert rules exist"

echo ""

# 7. Test JA4 fingerprint blocking
echo "========================================
7. JA4 Blocking Functionality
========================================"

# Add a test fingerprint to blacklist
redis-cli -h localhost -p 6379 -a "${REDIS_PW}" SADD ja4:blacklist "test_fingerprint_demo" > /dev/null 2>&1
check "Can add fingerprints to blacklist"

# Check if it's there
redis-cli -h localhost -p 6379 -a "${REDIS_PW}" SISMEMBER ja4:blacklist "test_fingerprint_demo" > /dev/null 2>&1
check "Can query blacklist"

# Clean up
redis-cli -h localhost -p 6379 -a "${REDIS_PW}" SREM ja4:blacklist "test_fingerprint_demo" > /dev/null 2>&1

echo ""

# 8. Check metrics are being collected
echo "========================================
8. Metrics Collection
========================================"

METRICS=$(curl -s http://localhost:9090/metrics | grep "^ja4_" | wc -l)
if [ "$METRICS" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} JA4 metrics are being collected ($METRICS metrics)"
else
    echo -e "${YELLOW}⚠${NC} No JA4 metrics found yet (this is OK if just started)"
fi

echo ""

# Final summary
echo "========================================
Summary
========================================"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ POC is ready for demo!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review POC_QUICKSTART.md for demo flow"
    echo "  2. Run ./test-ja4-blocking.sh to demonstrate blocking"
    echo "  3. Open http://localhost:9091 for Prometheus UI"
    echo "  4. Check metrics at http://localhost:9090/metrics"
    exit 0
else
    echo -e "${RED}✗ Found $ERRORS issue(s) that need attention${NC}"
    echo ""
    echo "Review the output above and fix any failing checks"
    exit 1
fi
