#!/bin/bash
# TLS Traffic Generator - Performance Testing Script for JA4proxy
#
# This script generates realistic mixed traffic with good and bad actors
# to stress test the JA4proxy system

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
BACKEND_HOST="localhost"
BACKEND_PORT="8081"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          JA4proxy Performance Test - Traffic Generator            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
echo -e "${BLUE}▶ Checking services...${NC}"

if ! docker compose -f docker-compose.poc.yml ps 2>/dev/null | grep -q "ja4proxy.*Up"; then
    echo -e "${RED}✗ JA4proxy services are not running${NC}"
    echo -e "${YELLOW}  Start with: ./start-poc.sh${NC}"
    exit 1
fi

# Check backend is accessible
if ! curl -s -f "http://${BACKEND_HOST}:${BACKEND_PORT}/api/health" > /dev/null 2>&1; then
    echo -e "${RED}✗ Backend not accessible at ${BACKEND_HOST}:${BACKEND_PORT}${NC}"
    echo -e "${YELLOW}  Make sure the POC stack is running${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Services are running${NC}"
echo ""

# Install Python dependencies if needed
if ! python3 -c "import requests" 2>/dev/null; then
    echo -e "${YELLOW}▶ Installing Python dependencies...${NC}"
    pip3 install requests 2>&1 | grep -v "already satisfied" || true
    echo -e "${GREEN}✓ Dependencies installed${NC}"
    echo ""
fi

# Make the Python script executable
chmod +x scripts/tls-traffic-generator.py

echo -e "${BLUE}Configuration:${NC}"
echo -e "  Duration:        ${DURATION}s"
echo -e "  Good Traffic:    ${GOOD_PERCENT}%"
echo -e "  Bad Traffic:     $((100 - GOOD_PERCENT))%"
echo -e "  Workers:         ${WORKERS}"
echo -e "  Backend:         ${BACKEND_HOST}:${BACKEND_PORT}"
echo ""

echo -e "${YELLOW}Tip: Monitor in real-time:${NC}"
echo -e "  Metrics:     curl http://localhost:9090/metrics | grep ja4_"
echo -e "  Grafana:     http://localhost:3001 (admin/admin)"
echo -e "  Prometheus:  http://localhost:9091"
echo -e "  Logs:        docker compose -f docker-compose.poc.yml logs -f proxy"
echo ""

echo -e "${GREEN}▶ Starting traffic generation...${NC}"
echo ""

# Run the traffic generator
python3 scripts/tls-traffic-generator.py \
    --backend-host "${BACKEND_HOST}" \
    --backend-port "${BACKEND_PORT}" \
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
    grep "^ja4_blocks_total" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"
    
    echo ""
    echo -e "${CYAN}Active Bans:${NC}"
    grep "^ja4_bans_active" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"
    
    rm -f /tmp/ja4_metrics.txt
else
    echo -e "${YELLOW}  Metrics endpoint not accessible${NC}"
fi

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. View detailed metrics: ${CYAN}curl http://localhost:9090/metrics | grep ja4_${NC}"
echo -e "  2. Check Grafana dashboards: ${CYAN}http://localhost:3001${NC}"
echo -e "  3. Query Prometheus: ${CYAN}http://localhost:9091${NC}"
echo -e "  4. Run again with different settings:"
echo -e "     ${CYAN}./generate-tls-traffic.sh <duration> <good_percent> <workers>${NC}"
echo -e "     Example: ${CYAN}./generate-tls-traffic.sh 300 10 100${NC} (5min, 10% good, 100 workers)"
echo ""
