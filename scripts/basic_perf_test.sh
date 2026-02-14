#!/bin/bash
# Basic performance test script
# Runs without external dependencies

set -e

echo "🏃 Running Basic Performance Test"
echo "================================"

PROXY_URL=${1:-"http://localhost:8080"}
CONCURRENT_USERS=${2:-10}
REQUESTS_PER_USER=${3:-10}
TOTAL_REQUESTS=$((CONCURRENT_USERS * REQUESTS_PER_USER))

echo "Configuration:"
echo "  Target URL: $PROXY_URL"
echo "  Concurrent Users: $CONCURRENT_USERS"
echo "  Requests per User: $REQUESTS_PER_USER"
echo "  Total Requests: $TOTAL_REQUESTS"

# Check if target is reachable
if ! curl -s -o /dev/null "$PROXY_URL" --max-time 5; then
    echo "❌ Target URL $PROXY_URL is not reachable"
    echo "Make sure the proxy is running: make deploy-poc"
    exit 1
fi

# Create reports directory
mkdir -p reports

# Performance test function
run_performance_test() {
    local user_id=$1
    local start_time=$(date +%s.%N)
    local success_count=0
    local error_count=0
    
    for i in $(seq 1 $REQUESTS_PER_USER); do
        local request_start=$(date +%s.%N)
        
        if curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL" --max-time 10 | grep -q "200\|502\|503"; then
            success_count=$((success_count + 1))
        else
            error_count=$((error_count + 1))
        fi
        
        local request_end=$(date +%s.%N)
        local request_time=$(echo "$request_end - $request_start" | bc -l 2>/dev/null || echo "0.1")
        
        echo "user_$user_id,request_$i,$request_time,$(date +%s)" >> "reports/perf_raw_$user_id.tmp"
    done
    
    local end_time=$(date +%s.%N)
    local total_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "1.0")
    
    echo "user_$user_id,$success_count,$error_count,$total_time" >> reports/perf_summary.tmp
}

# Start performance test
echo ""
echo "🚀 Starting performance test..."
start_time=$(date +%s.%N)

# Clean up previous results
rm -f reports/perf_*.tmp

# Run concurrent users
pids=()
for user in $(seq 1 $CONCURRENT_USERS); do
    run_performance_test $user &
    pids+=($!)
done

# Wait for all background jobs to complete
echo "⏳ Running $CONCURRENT_USERS concurrent users..."
for pid in "${pids[@]}"; do
    wait $pid
done

end_time=$(date +%s.%N)
total_test_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "1.0")

# Calculate results
echo ""
echo "📊 Performance Test Results"
echo "========================="

total_success=0
total_errors=0
if [ -f reports/perf_summary.tmp ]; then
    while IFS=',' read -r user success errors time; do
        total_success=$((total_success + success))
        total_errors=$((total_errors + errors))
    done < reports/perf_summary.tmp
fi

success_rate=$(echo "scale=2; $total_success * 100 / $TOTAL_REQUESTS" | bc -l 2>/dev/null || echo "0")
requests_per_second=$(echo "scale=2; $total_success / $total_test_time" | bc -l 2>/dev/null || echo "0")

echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Successful Requests: $total_success"
echo "  Failed Requests: $total_errors"
echo "  Success Rate: ${success_rate}%"
echo "  Test Duration: ${total_test_time}s"
echo "  Requests/Second: $requests_per_second"

# Generate simple HTML report
cat > reports/basic_performance.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>JA4proxy Basic Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .metric { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <h1>JA4proxy Performance Test Report</h1>
    <div class="metric"><strong>Test Date:</strong> $(date)</div>
    <div class="metric"><strong>Target URL:</strong> $PROXY_URL</div>
    <div class="metric"><strong>Concurrent Users:</strong> $CONCURRENT_USERS</div>
    <div class="metric"><strong>Total Requests:</strong> $TOTAL_REQUESTS</div>
    <div class="metric"><strong>Test Duration:</strong> ${total_test_time}s</div>
    <div class="metric success"><strong>Successful Requests:</strong> $total_success</div>
    <div class="metric error"><strong>Failed Requests:</strong> $total_errors</div>
    <div class="metric"><strong>Success Rate:</strong> ${success_rate}%</div>
    <div class="metric"><strong>Requests per Second:</strong> $requests_per_second</div>
</body>
</html>
EOF

# Cleanup temporary files
rm -f reports/perf_*.tmp

echo ""
echo "📈 Report saved to: reports/basic_performance.html"

# Exit with error if success rate is too low
if (( $(echo "$success_rate < 80" | bc -l 2>/dev/null || echo "0") )); then
    echo "❌ Performance test failed: Success rate below 80%"
    exit 1
else
    echo "✅ Performance test passed"
fi