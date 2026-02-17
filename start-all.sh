#!/bin/bash

# Start complete JA4proxy with monitoring

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "JA4proxy Complete Stack Startup"
echo "========================================"
echo

# Check if POC services are already running
POC_RUNNING=false
if docker ps --format '{{.Names}}' | grep -q "ja4proxy$"; then
    echo -e "${YELLOW}▶ POC services already running, skipping...${NC}"
    POC_RUNNING=true
else
    # Start POC environment first
    echo "▶ Starting POC environment..."
    ./start-poc.sh
    
    echo
    echo "▶ Waiting for POC services to stabilize..."
    sleep 5
fi

# Check if monitoring services are already running
MONITORING_RUNNING=false
if docker ps --format '{{.Names}}' | grep -q "ja4proxy-grafana"; then
    echo -e "${YELLOW}▶ Monitoring services already running, skipping...${NC}"
    MONITORING_RUNNING=true
else
    # Start monitoring stack
    echo
    echo "▶ Starting monitoring stack..."
    ./start-monitoring.sh
fi

echo
echo "========================================"
echo -e "${GREEN}✓ Complete stack is running!${NC}"
echo "========================================"
echo
echo "Services:"
echo "  HAProxy (LB):  https://localhost:443 (TLS passthrough)"
echo "  HAProxy Stats: http://localhost:8404/stats"
echo "  Proxy:         http://localhost:8080"
echo "  Backend:       https://localhost:8443"
echo "  Tarpit:        http://localhost:8888"
echo "  Metrics:       http://localhost:9090/metrics"
echo "  Prometheus:    http://localhost:9091"
echo "  Loki:          http://localhost:3100 (centralized logs)"
echo "  Alertmanager:  http://localhost:9093"
echo "  Grafana:       http://localhost:3001"
echo "                 (admin/admin)"
echo
echo "Next steps:"
echo "  1. Open Grafana: http://localhost:3001"
echo "  2. Generate traffic: ./generate-tls-traffic.sh 60 15 20"
echo "  3. Watch the dashboard show blocked vs allowed traffic"
echo
echo "View logs:"
echo "  docker compose -f docker-compose.poc.yml logs -f proxy"
echo "  docker compose -f docker-compose.monitoring.yml logs -f"
echo
echo "Stop all services:"
echo "  docker compose -f docker-compose.poc.yml down"
echo "  docker compose -f docker-compose.monitoring.yml down"
echo
