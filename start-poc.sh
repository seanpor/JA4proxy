#!/bin/bash
# JA4 Proxy POC Startup Script
# Starts all services and verifies they are working

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "JA4 Proxy POC Environment"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker-compose is not installed${NC}"
    exit 1
fi

echo -e "${BLUE}Starting services...${NC}"

# Workaround for Docker iptables issue - try to clean up first
docker network prune -f > /dev/null 2>&1 || true

# Try to start services with --remove-orphans to avoid warnings
if ! docker compose -f docker-compose.poc.yml up -d --remove-orphans redis backend proxy 2>&1; then
    echo ""
    echo -e "${RED}Failed to start services. This may be a Docker networking issue.${NC}"
    echo ""
    echo "Try these fixes:"
    echo "  1. Restart Docker daemon: sudo systemctl restart docker"
    echo "  2. Or: sudo service docker restart"
    echo "  3. Then run this script again"
    echo ""
    echo "If the problem persists, check Docker logs:"
    echo "  sudo journalctl -u docker -n 50"
    exit 1
fi

echo ""
echo "Waiting for services to be ready..."
sleep 5

# Check Redis
echo -n "Checking Redis... "
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker exec ja4proxy-redis redis-cli -a changeme ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 1
done
if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Check Backend
echo -n "Checking Backend... "
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:8081/api/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 1
done
if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Check Proxy
echo -n "Checking Proxy... "
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:9090/metrics > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 1
done
if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}✗ Failed${NC}"
    docker compose -f docker-compose.poc.yml logs proxy
    exit 1
fi



echo ""
echo "=========================================="
echo -e "${GREEN}✓ POC services are running!${NC}"
echo "=========================================="
echo ""
echo "Service URLs:"
echo "  Proxy:       http://localhost:8080"
echo "  Metrics:     http://localhost:9090/metrics"
echo "  Backend:     http://localhost:8081"
echo ""
echo "Test the proxy:"
echo "  curl -x http://localhost:8080 http://backend/api/health"
echo "  curl http://localhost:9090/metrics"
echo ""
echo "Run tests:"
echo "  ./run-tests.sh"
echo ""
echo "View logs:"
echo "  docker compose -f docker-compose.poc.yml logs -f"
echo ""
echo "Start monitoring (Prometheus/Grafana):"
echo "  ./start-monitoring.sh"
echo "  or"
echo "  ./start-all.sh  # Starts both POC and monitoring"
echo ""
echo "Stop services:"
echo "  docker compose -f docker-compose.poc.yml down"
echo "=========================================="
