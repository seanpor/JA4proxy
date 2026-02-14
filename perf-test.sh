#!/bin/bash
# Performance testing script for JA4 Proxy

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "JA4 Proxy Performance Tests"
echo "=========================================="
echo ""

# Check if services are running
if ! docker compose -f docker-compose.poc.yml ps | grep -q "Up"; then
    echo -e "${RED}Error: Services are not running${NC}"
    echo "Start services first with: ./start-poc.sh"
    exit 1
fi

# Default values
USERS=${1:-10}
SPAWN_RATE=${2:-2}
DURATION=${3:-30}
MODE=${4:-headless}

echo "Configuration:"
echo "  Users: $USERS"
echo "  Spawn rate: $SPAWN_RATE users/sec"
echo "  Duration: ${DURATION}s"
echo "  Mode: $MODE"
echo ""

# Create reports directory
mkdir -p performance/reports

if [ "$MODE" = "web" ]; then
    echo -e "${BLUE}Starting Locust web interface...${NC}"
    echo "Open http://localhost:8089 in your browser"
    echo "Press Ctrl+C to stop"
    echo ""
    
    docker compose -f docker-compose.poc.yml run --rm \
        -p 8089:8089 \
        test \
        locust \
        -f /app/performance/locustfile.py \
        --host=http://backend:80 \
        --web-host=0.0.0.0 \
        --web-port=8089
else
    echo -e "${BLUE}Running headless performance test...${NC}"
    echo ""
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    REPORT_FILE="performance/reports/perf_${TIMESTAMP}.html"
    
    docker compose -f docker-compose.poc.yml run --rm \
        test \
        locust \
        -f /app/performance/locustfile.py \
        --host=http://backend:80 \
        --users=$USERS \
        --spawn-rate=$SPAWN_RATE \
        --run-time=${DURATION}s \
        --headless \
        --html=/app/$REPORT_FILE \
        --csv=/app/performance/reports/perf_${TIMESTAMP}
    
    echo ""
    echo "=========================================="
    echo -e "${GREEN}✓ Performance test complete!${NC}"
    echo ""
    echo "Reports generated:"
    echo "  - HTML: ./$REPORT_FILE"
    echo "  - CSV: ./performance/reports/perf_${TIMESTAMP}_stats.csv"
    echo "=========================================="
fi
