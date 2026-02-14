#!/bin/bash
# Test runner script for JA4 Proxy POC
# Runs all tests in Docker containers

set -e

echo "=========================================="
echo "JA4 Proxy Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if services are running
echo "Checking if services are running..."
if ! docker ps | grep -q ja4proxy-redis; then
    echo -e "${YELLOW}Services not running. Starting services...${NC}"
    docker-compose -f docker-compose.poc.yml up -d redis backend proxy
    echo "Waiting for services to be ready..."
    sleep 10
fi

# Wait for proxy to be healthy
echo "Waiting for proxy to be healthy..."
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:9090/metrics > /dev/null 2>&1; then
        echo -e "${GREEN}Proxy is healthy!${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo -n "."
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Proxy failed to become healthy${NC}"
    docker-compose -f docker-compose.poc.yml logs proxy
    exit 1
fi

echo ""
echo "Running tests..."
echo "=========================================="

# Create reports directory if it doesn't exist
mkdir -p reports

# Run tests
docker-compose -f docker-compose.poc.yml run --rm test

TEST_EXIT_CODE=$?

echo ""
echo "=========================================="
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Test reports available in ./reports/"
    echo "  - Coverage report: ./reports/coverage/index.html"
    echo "  - JUnit report: ./reports/junit.xml"
else
    echo -e "${RED}✗ Tests failed with exit code $TEST_EXIT_CODE${NC}"
fi
echo "=========================================="

exit $TEST_EXIT_CODE
