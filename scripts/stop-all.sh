#!/usr/bin/env bash
# stop-all.sh — Stop all JA4proxy stacks (POC + monitoring)
#
# Usage:
#   ./stop-all.sh           # Graceful stop (keep volumes/data)
#   ./stop-all.sh --clean   # Stop AND remove all volumes (fresh slate)

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

CLEAN=false
for arg in "$@"; do
    [ "$arg" = "--clean" ] && CLEAN=true
done

echo "========================================"
echo "JA4proxy — Stopping all services"
[ "$CLEAN" = true ] && echo "  (--clean: volumes will be removed)"
echo "========================================"
echo

# ── Agent context: if .current-agent is set, target that stack ────────────────
_AGENT=$(cat .current-agent 2>/dev/null || true)
if [[ -n "$_AGENT" && -f ".env.$_AGENT" ]]; then
    echo -e "${CYAN}  (active agent: $_AGENT)${NC}"
    POC_FLAGS="--project-name ja4_${_AGENT} --env-file .env.${_AGENT}"
elif [ -f .env ]; then
    # docker-compose.poc.yml references ${REDIS_PASSWORD:?} — interpolation
    # fails if .env isn't passed explicitly (compose's auto-load is relative
    # to the compose file directory, not CWD), and `ps -q` returns nothing
    # even when the stack is running.
    POC_FLAGS="--env-file .env"
else
    POC_FLAGS=""
fi

# Stop monitoring stack
if docker compose $POC_FLAGS -f docker/docker-compose.monitoring.yml ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping monitoring stack (Prometheus/Grafana/Loki)...${NC}"
    if [ "$CLEAN" = true ]; then
        docker compose $POC_FLAGS -f docker/docker-compose.monitoring.yml down -v --remove-orphans
    else
        docker compose $POC_FLAGS -f docker/docker-compose.monitoring.yml down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ Monitoring stopped${NC}"
else
    echo -e "${YELLOW}  ▷ Monitoring stack not running — skipping${NC}"
fi

# Stop POC stack (agent-aware)
# shellcheck disable=SC2086
if docker compose -f docker/docker-compose.poc.yml $POC_FLAGS ps -q 2>/dev/null | grep -q .; then
    echo -e "${BLUE}▶ Stopping POC stack (proxy/HAProxy/Redis/backend)...${NC}"
    if [ "$CLEAN" = true ]; then
        # shellcheck disable=SC2086
        docker compose -f docker/docker-compose.poc.yml $POC_FLAGS down -v --remove-orphans
    else
        # shellcheck disable=SC2086
        docker compose -f docker/docker-compose.poc.yml $POC_FLAGS down --remove-orphans
    fi
    echo -e "${GREEN}  ✓ POC stack stopped${NC}"
    [[ -n "$_AGENT" ]] && rm -f .current-agent && echo -e "${GREEN}  ✓ Cleared .current-agent${NC}"
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
echo "  ./scripts/start-all.sh          # POC + monitoring"
echo "  ./scripts/start-poc.sh          # POC only"
echo "========================================"
