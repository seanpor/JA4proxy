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
    docker compose -f docker-compose.poc.yml up -d redis backend proxy
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
    docker compose -f docker-compose.poc.yml logs proxy
    exit 1
fi

echo ""
echo "Running tests..."
echo "=========================================="

# Create reports directory if it doesn't exist
mkdir -p reports

# Run all tests with parallel execution and comprehensive output
echo "Running all tests with parallel execution..."
echo "=========================================="

# Create a timestamp for this test run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="test_results_${TIMESTAMP}.txt"
JUNIT_FILE="reports/junit_${TIMESTAMP}.xml"

# Run tests with parallel execution if available
echo "Starting test execution..."

# Check if pytest-xdist is available for parallel execution
echo "Checking for parallel test support..."
if docker compose -f docker-compose.poc.yml run --rm test pytest --version 2>/dev/null | grep -q xdist; then
    echo "✓ pytest-xdist available, using parallel execution (-n 4)"
    PARALLEL_FLAG="-n 4"
else
    echo "⚠ pytest-xdist not available, running tests sequentially"
    PARALLEL_FLAG=""
fi

# Use timeout to prevent hanging
echo "Running tests with timeout (600 seconds)..."
timeout 600 docker compose -f docker-compose.poc.yml run --rm test pytest /app/tests/ \
    -v --tb=short \
    $PARALLEL_FLAG \
    --junitxml="${JUNIT_FILE}" \
    -W ignore::pytest.PytestUnraisableExceptionWarning \
    -W ignore::RuntimeWarning \
    -W ignore::DeprecationWarning \
    -W ignore::InsecureRequestWarning \
    --disable-warnings \
    -p no:warnings \
    2>&1 | tee "${RESULTS_FILE}"

TIMEOUT_EXIT_CODE=$?
if [ $TIMEOUT_EXIT_CODE -eq 124 ]; then
    echo -e "${RED}✗ Tests timed out after 600 seconds${NC}"
    TEST_EXIT_CODE=124
fi

TEST_EXIT_CODE=$?

echo ""
echo "=========================================="
echo "TEST RUN SUMMARY"
echo "=========================================="

# Parse test results to extract key metrics
if [ -f "${RESULTS_FILE}" ]; then
    echo "Detailed results saved to: ${RESULTS_FILE}"
    echo "JUnit XML report saved to: ${JUNIT_FILE}"
    
    # Extract test statistics
    PASSED=$(grep -oP '\d+ passed' "${RESULTS_FILE}" | grep -oP '\d+')
    FAILED=$(grep -oP '\d+ failed' "${RESULTS_FILE}" | grep -oP '\d+')
    SKIPPED=$(grep -oP '\d+ skipped' "${RESULTS_FILE}" | grep -oP '\d+')
    WARNINGS=$(grep -oP '\d+ warnings' "${RESULTS_FILE}" | grep -oP '\d+')
    DURATION=$(grep -oP '\d+m\d+\.\d+s' "${RESULTS_FILE}" | tail -1)
    
    echo ""
    echo "Test Statistics:"
    echo "  ✓ Passed: ${PASSED:-0}"
    echo "  ✗ Failed: ${FAILED:-0}"
    echo "  ⊘ Skipped: ${SKIPPED:-0}"
    echo "  ⚠ Warnings: ${WARNINGS:-0}"
    echo "  ⏱ Duration: ${DURATION:-unknown}"
    echo ""
fi

if [ $TEST_EXIT_CODE -eq 0 ]; then
    # Check if there were any skipped tests
    SKIPPED_COUNT=$(grep -oP '\d+ skipped' "${RESULTS_FILE}" | grep -oP '\d+' || echo "0")
    
    if [ "$SKIPPED_COUNT" -eq "0" ]; then
        echo -e "${GREEN}✓ OVERALL RESULT: ALL TESTS PASSED WITH ZERO SKIPPED${NC}"
    else
        echo -e "${YELLOW}⚠ OVERALL RESULT: ALL TESTS PASSED BUT $SKIPPED_COUNT TESTS WERE SKIPPED${NC}"
        echo ""
        echo "Skipped tests (check ${RESULTS_FILE} for details):"
        grep -A 1 -B 1 "SKIPPED" "${RESULTS_FILE}"
    fi
    echo ""
    echo "Artifacts available:"
    echo "  📄 Test output: ${RESULTS_FILE}"
    echo "  📊 JUnit report: ${JUNIT_FILE}"
    echo "  🌐 Coverage report: ./reports/coverage/index.html"
elif [ $TEST_EXIT_CODE -eq 124 ]; then
    echo -e "${RED}✗ OVERALL RESULT: TESTS TIMED OUT${NC}"
    echo ""
    echo "Tests exceeded 600 second timeout"
    echo "Check ${RESULTS_FILE} for partial results"
else
    echo -e "${RED}✗ OVERALL RESULT: TESTS FAILED (exit code $TEST_EXIT_CODE)${NC}"
    echo ""
    echo "Check ${RESULTS_FILE} for detailed failure information"
fi
echo "=========================================="

exit $TEST_EXIT_CODE
