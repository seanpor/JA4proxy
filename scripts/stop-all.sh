#!/usr/bin/env bash
# stop-all.sh — Stop all JA4proxy stacks (POC + monitoring)

set -euo pipefail

GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; CYAN="\033[0;36m"; NC="\033[0m"

CLEAN=false
for arg in "$@"; do
    [ "$arg" = "--clean" ] && CLEAN=true
done

echo "========================================"
echo "JA4proxy — Stopping all services"
[ "$CLEAN" = true ] && echo "  (--clean: volumes will be removed)"
echo "========================================"
echo

# ── Environment context ───────────────────────────────────────────────────────
_AGENT=$(cat .current-agent 2>/dev/null || true)
if [[ -n "$_AGENT" && -f ".env.$_AGENT" ]]; then
    echo -e "${CYAN}  (active agent: $_AGENT)${NC}"
    P_NAME="ja4_${_AGENT}"
    E_FILE=".env.${_AGENT}"
elif [ -f .env ]; then
    # Parse project name from .env
    P_NAME=$(grep "^COMPOSE_PROJECT_NAME=" .env | cut -d= -f2-)
    [ -z "$P_NAME" ] && P_NAME="ja4proxy"
    E_FILE=".env"
else
    P_NAME="ja4proxy"
    E_FILE=""
fi

FLAGS="-p $P_NAME"
[ -n "$E_FILE" ] && FLAGS="$FLAGS --env-file $E_FILE"

# Stop monitoring stack
if docker compose $FLAGS -f deploy/docker/docker-compose.monitoring.yml ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping monitoring stack...${NC}"
    if [ "$CLEAN" = true ]; then
        docker compose $FLAGS -f deploy/docker/docker-compose.monitoring.yml down -v --remove-orphans
    else
        docker compose $FLAGS -f deploy/docker/docker-compose.monitoring.yml down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ Monitoring stopped${NC}"
else
    echo -e "${YELLOW}  ▷ Monitoring stack not running — skipping${NC}"
fi

# Stop POC stack
if docker compose $FLAGS -f deploy/docker/docker-compose.poc.yml ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping POC stack...${NC}"
    if [ "$CLEAN" = true ]; then
        docker compose $FLAGS -f deploy/docker/docker-compose.poc.yml down -v --remove-orphans
    else
        docker compose $FLAGS -f deploy/docker/docker-compose.poc.yml down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ POC stack stopped${NC}"
    [[ -n "$_AGENT" ]] && rm -f .current-agent && echo -e "${GREEN}  ✓ Cleared .current-agent${NC}"
else
    echo -e "${YELLOW}  ▷ POC stack not running — skipping${NC}"
fi

echo
echo "========================================"
echo -e "${GREEN}✓ All services stopped.${NC}"
echo "========================================"
