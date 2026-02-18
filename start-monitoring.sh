#!/bin/bash
# Quick start script for JA4proxy monitoring stack

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}JA4proxy Monitoring Stack Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if POC is running
if ! docker ps | grep -q "ja4proxy"; then
    echo -e "${YELLOW}⚠ JA4proxy POC not running. Starting...${NC}"
    ./start-poc.sh
    sleep 10
fi

# Source .env if it exists (for password display)
[ -f .env ] && { set -a; source .env; set +a; }

# Start monitoring stack
echo -e "${GREEN}▶ Starting monitoring stack...${NC}"
docker compose -f docker-compose.monitoring.yml up -d

# Wait for services
echo -e "${GREEN}▶ Waiting for services to be ready...${NC}"
sleep 15

# Ensure Grafana admin password matches .env (handles pre-existing volume)
if [ -n "${GRAFANA_PASSWORD}" ] && [ "${GRAFANA_PASSWORD}" != "admin" ]; then
    docker exec ja4proxy-grafana grafana-cli admin reset-admin-password "${GRAFANA_PASSWORD}" > /dev/null 2>&1 || true
fi

# Check Prometheus
if curl -sf http://localhost:9091/-/healthy > /dev/null; then
    echo -e "${GREEN}✓ Prometheus is healthy${NC}"
else
    echo -e "${YELLOW}⚠ Prometheus not responding yet...${NC}"
fi

# Check Alertmanager
if curl -sf http://localhost:9093/-/healthy > /dev/null; then
    echo -e "${GREEN}✓ Alertmanager is healthy${NC}"
else
    echo -e "${YELLOW}⚠ Alertmanager not responding yet...${NC}"
fi

# Check Grafana
if curl -sf http://localhost:3001/api/health > /dev/null; then
    echo -e "${GREEN}✓ Grafana is healthy${NC}"
else
    echo -e "${YELLOW}⚠ Grafana not responding yet...${NC}"
fi

# Check Loki (via docker exec since it has no host port)
if docker exec ja4proxy-loki wget -q --spider http://localhost:3100/ready 2>/dev/null; then
    echo -e "${GREEN}✓ Loki is healthy${NC}"
else
    echo -e "${YELLOW}⚠ Loki not responding yet...${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Monitoring stack is running!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Access the services:"
echo ""
echo "  Prometheus:    http://localhost:9091"
echo "  Alertmanager:  http://localhost:9093"
echo "  Grafana:       http://localhost:3001"
echo "                 (admin / ${GRAFANA_PASSWORD:-admin})"
echo ""
echo "Next steps:"
echo ""
echo "  1. Open Grafana: open http://localhost:3001"
echo "  2. Dashboard is auto-imported: 'JA4 Proxy Security Dashboard'"
echo "  3. Test alerts: ./test-ja4-blocking.sh"
echo "  4. View alerts: open http://localhost:9093"
echo ""
echo "Documentation: docs/MONITORING_SETUP.md"
echo ""
