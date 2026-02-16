#!/bin/bash

# Start complete JA4proxy with monitoring

set -e

echo "========================================"
echo "JA4proxy Complete Stack Startup"
echo "========================================"
echo

# Start POC environment first
echo "▶ Starting POC environment..."
./start-poc.sh

echo
echo "▶ Waiting for POC services to stabilize..."
sleep 5

# Start monitoring stack
echo "▶ Starting monitoring stack..."
./start-monitoring.sh

echo
echo "========================================"
echo "✓ Complete stack is running!"
echo "========================================"
echo
echo "Services:"
echo "  Proxy:         http://localhost:8443"
echo "  Backend:       http://localhost:8080"
echo "  Metrics:       http://localhost:9090/metrics"
echo "  Prometheus:    http://localhost:9091"
echo "  Alertmanager:  http://localhost:9093"
echo "  Grafana:       http://localhost:3001"
echo "                 (admin/admin)"
echo
echo "Next steps:"
echo "  1. Open Grafana: http://localhost:3001"
echo "  2. Run tests: ./test-ja4-blocking.sh"
echo "  3. Generate traffic: ./generate-tls-traffic.sh"
echo
