#!/bin/bash

# Generate realistic test traffic for JA4proxy to populate Grafana dashboard

set -e

PROXY_URL="http://localhost:8080"
BACKEND_URL="https://localhost:8443"

echo "========================================="
echo "Generating Test Traffic for JA4proxy"
echo "========================================="
echo ""

# Function to make requests
make_request() {
    local url=$1
    local description=$2
    echo "▶ $description"
    curl -s -w "  Status: %{http_code}, Time: %{time_total}s\n" \
         -o /dev/null \
         "$url" 2>/dev/null || echo "  Failed"
}

echo "1. Normal Traffic (should pass through)"
echo "----------------------------------------"
for i in {1..10}; do
    make_request "$PROXY_URL/health" "Request $i to /health"
    sleep 0.2
done

echo ""
echo "2. Various Endpoints"
echo "----------------------------------------"
make_request "$PROXY_URL/" "Homepage"
make_request "$PROXY_URL/echo?message=test" "Echo endpoint"
make_request "$PROXY_URL/delay/1" "Delay endpoint"
make_request "$PROXY_URL/status/200" "Status 200"
make_request "$PROXY_URL/status/404" "Status 404"

echo ""
echo "3. POST Requests"
echo "----------------------------------------"
curl -s -X POST -w "  Status: %{http_code}\n" \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}' \
     -o /dev/null \
     "$PROXY_URL/echo" 2>/dev/null || echo "  Failed"

echo ""
echo "4. Rapid Requests (may trigger rate limiting)"
echo "----------------------------------------"
echo "Sending 20 rapid requests..."
for i in {1..20}; do
    curl -s -o /dev/null "$PROXY_URL/health" &
done
wait
echo "  Completed"

echo ""
echo "5. Checking Metrics"
echo "----------------------------------------"
echo "Total requests:"
curl -s http://localhost:9090/metrics | grep "ja4_requests_total" | grep -v "#"

echo ""
echo "Blocked requests:"
curl -s http://localhost:9090/metrics | grep "ja4_blocks_total" | grep -v "#"

echo ""
echo "Active connections:"
curl -s http://localhost:9090/metrics | grep "ja4_active_connections" | grep -v "#"

echo ""
echo "========================================="
echo "Traffic generation complete!"
echo "========================================="
echo ""
echo "Check Grafana at: http://localhost:3001 (admin / see .env)"
echo "Check Prometheus at: http://localhost:9091"
echo "Check metrics at: http://localhost:9090/metrics"
