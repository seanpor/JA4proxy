#!/bin/bash
# TLS Traffic Generator - Performance Testing Script for JA4proxy
#
# Generates real TLS connections through the proxy to test JA4 fingerprinting
# and security blocking. Good clients use browser-like TLS, bad clients use
# tool/malware-like TLS configurations.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
DURATION=${1:-60}
GOOD_PERCENT=${2:-15}
WORKERS=${3:-50}
TARGET_HOST="localhost"
TARGET_PORT="8080"  # Direct to proxy (use 443 if HAProxy is running)

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          JA4proxy TLS Traffic Generator                           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
echo -e "${BLUE}▶ Checking services...${NC}"

if ! docker compose -f docker-compose.poc.yml ps 2>/dev/null | grep -q "ja4proxy.*Up"; then
    echo -e "${RED}✗ JA4proxy services are not running${NC}"
    echo -e "${YELLOW}  Start with: ./start-poc.sh or ./start-all.sh${NC}"
    exit 1
fi

# Check if HAProxy is running — if so, target port 443
if docker compose -f docker-compose.poc.yml ps 2>/dev/null | grep -q "haproxy.*Up"; then
    # Check if port 443 is reachable
    if timeout 2 bash -c "echo | openssl s_client -connect ${TARGET_HOST}:443 2>/dev/null" | grep -q "CONNECTED"; then
        TARGET_PORT="443"
        echo -e "${GREEN}✓ HAProxy detected — targeting TLS port ${TARGET_PORT}${NC}"
    fi
fi

# For non-TLS fallback, check proxy directly
if [ "$TARGET_PORT" = "8080" ]; then
    # Try a raw TCP connection to the proxy
    if timeout 2 bash -c "</dev/tcp/${TARGET_HOST}/${TARGET_PORT}" 2>/dev/null; then
        echo -e "${GREEN}✓ Proxy accessible at ${TARGET_HOST}:${TARGET_PORT}${NC}"
    else
        echo -e "${RED}✗ Proxy not accessible at ${TARGET_HOST}:${TARGET_PORT}${NC}"
        echo -e "${YELLOW}  Make sure the POC stack is running: ./start-poc.sh${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ Services are running${NC}"
echo ""

# Make the Python script executable
chmod +x scripts/tls-traffic-generator.py

echo -e "${BLUE}Configuration:${NC}"
echo -e "  Duration:        ${DURATION}s"
echo -e "  Good Traffic:    ${GOOD_PERCENT}%"
echo -e "  Bad Traffic:     $((100 - GOOD_PERCENT))%"
echo -e "  Workers:         ${WORKERS}"
echo -e "  Target:          ${TARGET_HOST}:${TARGET_PORT}"
echo ""

echo -e "${YELLOW}Monitor in real-time:${NC}"
echo -e "  Metrics:     curl http://localhost:9090/metrics | grep ja4_"
echo -e "  Grafana:     http://localhost:3001 (admin/admin)"
echo -e "  Prometheus:  http://localhost:9091"
echo -e "  Logs:        docker compose -f docker-compose.poc.yml logs -f proxy"
echo ""

echo -e "${GREEN}▶ Starting TLS traffic generation...${NC}"
echo ""

# Run the traffic generator
python3 scripts/tls-traffic-generator.py \
    --target-host "${TARGET_HOST}" \
    --target-port "${TARGET_PORT}" \
    --duration "${DURATION}" \
    --good-percent "${GOOD_PERCENT}" \
    --workers "${WORKERS}"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Traffic generation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Show quick metrics summary
echo -e "${BLUE}Quick Metrics Summary:${NC}"
echo ""

if curl -s http://localhost:9090/metrics > /tmp/ja4_metrics.txt 2>/dev/null; then
    echo -e "${CYAN}Total Requests:${NC}"
    grep "^ja4_requests_total" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"
    
    echo ""
    echo -e "${CYAN}Blocked Requests:${NC}"
    grep "^ja4_blocked_requests_total" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"
    
    rm -f /tmp/ja4_metrics.txt
else
    echo -e "${YELLOW}  Metrics endpoint not accessible${NC}"
fi

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. View metrics: ${CYAN}curl http://localhost:9090/metrics | grep ja4_${NC}"
echo -e "  2. Grafana:      ${CYAN}http://localhost:3001${NC}"
echo -e "  3. Run again:    ${CYAN}./generate-tls-traffic.sh <duration> <good%> <workers>${NC}"
echo ""
