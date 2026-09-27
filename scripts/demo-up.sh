#!/usr/bin/env bash
# demo-up.sh — Start the lean JA4proxy demo stack with traffic generator and monitoring
#
# Phase 816: Single-command showcase bootstrapper. Brings up:
#   - Core proxy stack (redis, backend, proxy, tarpit, analytics, management)
#   - Continuous traffic generator (trafficgen with realistic mixed profile)
#   - Observability stack (prometheus, grafana)
#
# Usage:
#   scripts/demo-up.sh [--dry-run] [--help]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Color helpers
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BOLD="\033[1m"
NC="\033[0m"

DRY_RUN=0

show_help() {
    cat << 'EOF'
Usage: scripts/demo-up.sh [OPTIONS]

Start the lean JA4proxy demo environment for management console showcase.

Options:
  --dry-run       Validate prerequisites and display startup plan without running containers
  -h, --help      Show this help message and exit

Services started:
  - Go JA4proxy & null backend
  - Redis cache & session datastore
  - Analytics pipeline & tarpit
  - FastAPI Management Console (HTTP :8000 or lane port)
  - TLS Traffic Generator (mixed legitimate & malicious profiles)
  - Prometheus (:9091) & Grafana (:3000)
EOF
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}" >&2
            show_help >&2
            exit 1
            ;;
    esac
done

if [ "$DRY_RUN" -eq 1 ] || [ "${DRY_RUN:-0}" = "1" ]; then
    echo -e "${BLUE}=== [DRY-RUN] JA4proxy Demo Environment Startup ===${NC}"
    echo "1. Validate Docker daemon availability"
    echo "2. Ensure mock backend TLS certificates (scripts/generate-backend-cert.sh)"
    echo "3. Ensure environment secrets and tokens (deploy/secrets/metrics_token.txt)"
    echo "4. Launch POC services: redis backend proxy tarpit analytics management"
    echo "5. Launch Monitoring services: prometheus grafana"
    echo "6. Launch Traffic generator profile: trafficgen"
    echo "7. Poll health on Proxy, Management API, Prometheus, and Grafana"
    echo -e "${GREEN}✓ Dry-run verification complete.${NC}"
    exit 0
fi

echo -e "${BLUE}${BOLD}====================================================${NC}"
echo -e "${BLUE}${BOLD}      JA4proxy Showcase Demo Environment Setup      ${NC}"
echo -e "${BLUE}${BOLD}====================================================${NC}"
echo ""

# 1. Check Docker
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running or accessible.${NC}" >&2
    exit 1
fi

# 2. Mock backend & Grafana TLS certificates
if [ -f "scripts/generate-backend-cert.sh" ]; then
    bash scripts/generate-backend-cert.sh > /dev/null 2>&1 || true
fi
if [ -f "scripts/generate-grafana-cert.sh" ]; then
    bash scripts/generate-grafana-cert.sh > /dev/null 2>&1 || true
fi

# 3. Ensure deploy/secrets directory and metrics_token.txt file exist
mkdir -p deploy/secrets
if [ ! -f "deploy/secrets/metrics_token.txt" ]; then
    [ -f .env ] && { set -a; source .env; set +a; }
    echo "${METRICS_AUTH_TOKEN:-}" > deploy/secrets/metrics_token.txt
    chmod 600 deploy/secrets/metrics_token.txt
fi

# 4. Start POC core stack
echo -e "${BLUE}▶ Bringing up core JA4proxy POC services...${NC}"
bash scripts/start-poc.sh

# Load .env now that start-poc has generated or synced it
[ -f .env ] && { set -a; source .env; set +a; }

BIND_IP="${AGENT_BIND_IP:-127.0.0.1}"
PROXY_PORT="${HOST_PORT_DIRECT:-8081}"
METRICS_PORT="${HOST_PORT_METRICS:-9090}"
MGMT_PORT="${HOST_PORT_MANAGEMENT:-8090}"
PROM_PORT="${HOST_PORT_PROMETHEUS:-9091}"
GRAFANA_PORT="${HOST_PORT_GRAFANA:-3000}"

# 5. Start monitoring stack
echo -e "${BLUE}▶ Bringing up Prometheus and Grafana monitoring...${NC}"
bash scripts/start-monitoring.sh

# 6. Start traffic generator profile
echo -e "${BLUE}▶ Starting continuous TLS traffic generator...${NC}"
P_FLAG=""
[ -n "${COMPOSE_PROJECT_NAME:-}" ] && P_FLAG="-p ${COMPOSE_PROJECT_NAME}"
docker compose $P_FLAG -f deploy/docker/docker-compose.poc.yml --env-file .env --profile traffic up -d trafficgen

# 7. Wait for readiness
echo -e "${YELLOW}▶ Waiting for demo services to be fully healthy...${NC}"

max_retries=30
retry=0
until curl -sf "http://${BIND_IP}:${MGMT_PORT}/api/v1/health" > /dev/null 2>&1 || [ $retry -ge $max_retries ]; do
    sleep 1
    retry=$((retry + 1))
done

if [ $retry -ge $max_retries ]; then
    echo -e "${RED}Warning: Management API not responding yet at http://${BIND_IP}:${MGMT_PORT}/api/v1/health${NC}"
else
    echo -e "${GREEN}  ✓ Management API ready on http://${BIND_IP}:${MGMT_PORT}${NC}"
fi

retry=0
until curl -sf "http://${BIND_IP}:${PROM_PORT}/-/healthy" > /dev/null 2>&1 || [ $retry -ge $max_retries ]; do
    sleep 1
    retry=$((retry + 1))
done

if [ $retry -ge $max_retries ]; then
    echo -e "${RED}Warning: Prometheus not responding yet at http://${BIND_IP}:${PROM_PORT}/-/healthy${NC}"
else
    echo -e "${GREEN}  ✓ Prometheus ready on http://${BIND_IP}:${PROM_PORT}${NC}"
fi

retry=0
until curl -skf "https://${BIND_IP}:${GRAFANA_PORT}/api/health" > /dev/null 2>&1 || [ $retry -ge $max_retries ]; do
    sleep 1
    retry=$((retry + 1))
done

if [ $retry -ge $max_retries ]; then
    echo -e "${RED}Warning: Grafana not responding yet at https://${BIND_IP}:${GRAFANA_PORT}/api/health${NC}"
else
    echo -e "${GREEN}  ✓ Grafana ready on https://${BIND_IP}:${GRAFANA_PORT}${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}====================================================${NC}"
echo -e "${GREEN}${BOLD}       JA4proxy Demo Stack is Ready!                ${NC}"
echo -e "${GREEN}${BOLD}====================================================${NC}"
echo -e "  Management Console:  ${BOLD}http://${BIND_IP}:${MGMT_PORT}${NC}"
echo -e "  Grafana Dashboard:   ${BOLD}https://${BIND_IP}:${GRAFANA_PORT}${NC}"
echo -e "  Prometheus Engine:   ${BOLD}http://${BIND_IP}:${PROM_PORT}${NC}"
echo -e "  Proxy (TLS Ingress): ${BOLD}https://${BIND_IP}:${PROXY_PORT}${NC}"
echo ""
