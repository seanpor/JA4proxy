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

# Load lane port map from .env (managed by scripts/lane-env.sh)
[ -f .env ] && { set -a; source .env; set +a; }

# Check if POC services are already running
POC_RUNNING=false
if docker compose -f deploy/docker/docker-compose.poc.yml ps --format '{{.Status}}' | grep -q "Up"; then
    echo -e "${YELLOW}▶ POC services already running, skipping...${NC}"
    POC_RUNNING=true
else
    # Start POC environment first
    echo "▶ Starting POC environment..."
    ./scripts/start-poc.sh
    
    echo
    echo "▶ Waiting for POC services to stabilize..."
    sleep 5
fi

# Check if monitoring services are already running.
# NB: docker compose ps for the monitoring file shares the COMPOSE_PROJECT_NAME
# with the POC file, so it would report the POC containers (which ARE up) and
# wrongly skip the monitoring stack. Gate on the actual lane-prefixed monitoring
# container, not on the project-scoped ps output.
GRAFANA_CT="ja4proxy-lane${JA4_LANE:-1}-grafana-1"
MONITORING_RUNNING=false
if [ -n "$(docker ps --filter "name=^/${GRAFANA_CT}$" --filter 'status=running' --format '{{.Names}}')" ]; then
    echo -e "${YELLOW}▶ Monitoring services already running, skipping...${NC}"
    MONITORING_RUNNING=true
else
    # Start monitoring stack
    echo
    echo "▶ Starting monitoring stack..."
    ./scripts/start-monitoring.sh
fi

echo
echo "========================================"
echo -e "${GREEN}✓ Complete stack is running!${NC}"
echo "========================================"
echo
echo "Services:"
echo "  Proxy (direct):  http://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_DIRECT:-8081}"
echo "  Proxy /metrics:  http://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_METRICS:-9090}/metrics"
echo "  Backend:         https://${BACKEND_HOST:-backend}:${BACKEND_PORT:-8443} (network-only)"
echo "  Prometheus:      http://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_PROMETHEUS:-9091}"
echo "  Alertmanager:    http://localhost:9093"
echo "  Grafana:         https://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}"
echo "                   (admin / see .env)"
echo "  Management API:  http://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_MANAGEMENT:-8090}"
echo
echo "Next steps:"
echo "  1. Open Grafana: https://${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}"
echo "  2. Generate traffic: ./scripts/generate-tls-traffic.sh 60 15 20"
echo "  3. Watch the dashboard show blocked vs allowed traffic"
echo
echo "View logs:"
echo "  docker compose -f deploy/docker/docker-compose.poc.yml logs -f proxy"
echo "  docker compose -f deploy/docker/docker-compose.monitoring.yml logs -f"
echo
echo "Stop all services:"
echo "  ./scripts/stop-all.sh          # graceful stop (keep Redis data)"
echo "  ./scripts/stop-all.sh --clean  # wipe everything (fresh slate)"
echo "  make stop                       # same as ./scripts/stop-all.sh"
echo
