#!/bin/bash
# Quick status check for JA4proxy POC and monitoring stack

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================"
echo " JA4proxy POC Status"
echo "========================================"
echo ""

# Check services
echo -e "${CYAN}Services Status:${NC}"
echo "----------------"

check_service() {
    local name=$1
    local port=$2
    if curl -sf "http://localhost:$port" > /dev/null 2>&1 || curl -sf "http://localhost:$port/health" > /dev/null 2>&1 || curl -sf "http://localhost:$port/api/health" > /dev/null 2>&1; then
        echo -e "  ✓ $name (port $port)"
    else
        echo -e "  ${RED}✗${NC} $name (port $port) - not responding"
    fi
}

check_service "Backend" "8081"
check_service "Proxy Metrics" "9090"
check_service "Prometheus" "9091"
check_service "Grafana" "3001"

echo ""

# Check Redis
echo -e "${CYAN}Redis Data:${NC}"
echo "------------"
if docker exec ja4proxy-redis redis-cli -a changeme ping 2>/dev/null | grep -q PONG; then
    echo -e "  ✓ Redis is running"
    WHITELIST=$(docker exec ja4proxy-redis redis-cli -a changeme SCARD ja4:whitelist 2>/dev/null)
    BLACKLIST=$(docker exec ja4proxy-redis redis-cli -a changeme SCARD ja4:blacklist 2>/dev/null)
    BLOCKS=$(docker exec ja4proxy-redis redis-cli -a changeme KEYS 'ja4:block:*' 2>/dev/null | wc -l)
    BANS=$(docker exec ja4proxy-redis redis-cli -a changeme KEYS 'ja4:ban:*' 2>/dev/null | wc -l)
    
    echo "  - Whitelist entries: $WHITELIST"
    echo "  - Blacklist entries: $BLACKLIST"
    echo "  - Active blocks: $BLOCKS"
    echo "  - Active bans: $BANS"
else
    echo -e "  ${RED}✗${NC} Redis is not running"
fi

echo ""

# Check Prometheus metrics
echo -e "${CYAN}Prometheus Metrics:${NC}"
echo "-------------------"
TOTAL_REQUESTS=$(curl -s 'http://localhost:9091/api/v1/query?query=ja4_requests_total' | jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0")
echo "  - Total requests processed: $TOTAL_REQUESTS"

if [ "$TOTAL_REQUESTS" = "0" ]; then
    echo -e "  ${YELLOW}⚠${NC}  No traffic has been sent through the proxy yet"
    echo "     The proxy requires TLS connections to generate JA4 fingerprints"
fi

echo ""

# Access information
echo "========================================"
echo " Access Information"
echo "========================================"
echo ""
echo -e "${GREEN}Grafana Dashboard:${NC}"
echo "  URL: http://localhost:3001"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo -e "${GREEN}Prometheus:${NC}"
echo "  URL: http://localhost:9091"
echo ""
echo -e "${GREEN}Proxy Metrics:${NC}"
echo "  URL: http://localhost:9090/metrics"
echo ""
echo -e "${GREEN}Backend (for testing):${NC}"
echo "  URL: http://localhost:8081"
echo ""

# Helpful hints
echo "========================================"
echo " Quick Actions"
echo "========================================"
echo ""
echo "1. Populate demo data:"
echo "   ./scripts/populate-grafana-demo-data.sh"
echo ""
echo "2. View all containers:"
echo "   docker compose -f docker-compose.poc.yml ps"
echo ""
echo "3. View logs:"
echo "   docker compose -f docker-compose.poc.yml logs -f proxy"
echo ""
echo "4. Run tests:"
echo "   ./run-tests.sh"
echo ""

# Current limitations
if [ "$TOTAL_REQUESTS" = "0" ]; then
    echo "========================================"
    echo " Note"
    echo "========================================"
    echo ""
    echo -e "${YELLOW}The Grafana dashboard will show limited data until${NC}"
    echo -e "${YELLOW}TLS traffic is sent through the proxy (port 8080).${NC}"
    echo ""
    echo "The proxy analyzes TLS handshakes to generate JA4"
    echo "fingerprints. Plain HTTP requests won't generate"
    echo "fingerprints or request metrics."
    echo ""
    echo "Redis-based security data (blocks, bans, lists) is"
    echo "populated and visible in the dashboard."
    echo ""
fi
