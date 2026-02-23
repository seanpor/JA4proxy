#!/usr/bin/env bash
# stop-all.sh — Stop all JA4proxy stacks (POC + monitoring)
#
# Usage:
#   ./stop-all.sh           # Graceful stop (keep volumes/data)
#   ./stop-all.sh --clean   # Stop AND remove all volumes (fresh slate)

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

CLEAN=false
for arg in "$@"; do
    [ "$arg" = "--clean" ] && CLEAN=true
done

echo "========================================"
echo "JA4proxy — Stopping all services"
[ "$CLEAN" = true ] && echo "  (--clean: volumes will be removed)"
echo "========================================"
echo

# Stop monitoring stack
if docker compose -f docker-compose.monitoring.yml ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping monitoring stack (Prometheus/Grafana/Loki)...${NC}"
    if [ "$CLEAN" = true ]; then
        docker compose -f docker-compose.monitoring.yml down -v --remove-orphans
    else
        docker compose -f docker-compose.monitoring.yml down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ Monitoring stopped${NC}"
else
    echo -e "${YELLOW}  ▷ Monitoring stack not running — skipping${NC}"
fi

# Stop POC stack
if docker compose -f docker-compose.poc.yml ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping POC stack (proxy/HAProxy/Redis/backend)...${NC}"
    if [ "$CLEAN" = true ]; then
        docker compose -f docker-compose.poc.yml down -v --remove-orphans
    else
        docker compose -f docker-compose.poc.yml down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ POC stack stopped${NC}"
else
    echo -e "${YELLOW}  ▷ POC stack not running — skipping${NC}"
fi

echo
echo "========================================"
echo -e "${GREEN}✓ All services stopped.${NC}"
if [ "$CLEAN" = true ]; then
    echo "  Volumes removed. Next start will be a fresh deployment."
else
    echo "  Redis data preserved. Use --clean to also wipe volumes."
fi
echo
echo "To start again:"
echo "  ./start-all.sh          # POC + monitoring"
echo "  ./start-poc.sh          # POC only"
echo "========================================"
