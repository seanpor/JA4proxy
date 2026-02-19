#!/bin/bash
# TLS Traffic Generator - Performance Testing Script for JA4proxy
#
# Generates real TLS connections through the proxy to test JA4 fingerprinting
# and security blocking. Runs inside a Docker container on the same network
# as the proxy. Good clients use browser-like TLS, bad clients use
# tool/malware-like TLS configurations.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
DURATION=${1:-60}
GOOD_PERCENT=${2:-15}
WORKERS=${3:-50}

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          JA4proxy TLS Traffic Generator                           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
echo -e "${BLUE}▶ Checking services...${NC}"

if ! docker compose -f docker-compose.poc.yml ps 2>/dev/null | grep -q "ja4proxy.*Up"; then
    echo -e "${RED}✗ JA4proxy services are not running${NC}"
    echo -e "${YELLOW}  Start with: ./start-poc.sh or ./start-all.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Services are running${NC}"
echo ""

# Clear stale rate-tracking, bans, and audit keys from previous runs
# (preserves whitelist/blacklist configuration)
echo -e "${BLUE}▶ Clearing stale security state from previous runs...${NC}"
REDIS_PASS=$(grep '^REDIS_PASSWORD=' .env 2>/dev/null | cut -d= -f2)
if [ -n "$REDIS_PASS" ]; then
    # Delete enforcement, audit, rate, banned, and blocked keys (keep ja4:whitelist/blacklist)
    docker exec ja4proxy-redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
        EVAL "local count=0; for _,k in ipairs(redis.call('keys','enforcement:*')) do redis.call('del',k); count=count+1 end; for _,k in ipairs(redis.call('keys','audit:*')) do redis.call('del',k); count=count+1 end; for _,k in ipairs(redis.call('keys','rate:*')) do redis.call('del',k); count=count+1 end; for _,k in ipairs(redis.call('keys','banned:*')) do redis.call('del',k); count=count+1 end; for _,k in ipairs(redis.call('keys','blocked:*')) do redis.call('del',k); count=count+1 end; return count" 0 \
        2>/dev/null && echo -e "${GREEN}✓ Cleared stale keys${NC}" || echo -e "${YELLOW}⚠ Could not clear Redis (non-fatal)${NC}"
else
    echo -e "${YELLOW}⚠ No REDIS_PASSWORD in .env, skipping Redis cleanup${NC}"
fi
echo ""

echo -e "${BLUE}Configuration:${NC}"
echo -e "  Duration:        ${DURATION}s"
echo -e "  Good Traffic:    ${GOOD_PERCENT}%"
echo -e "  Bad Traffic:     $((100 - GOOD_PERCENT))%"
echo -e "  Workers:         ${WORKERS}"
echo -e "  Target:          proxy:8080 (Docker network)"
echo ""

echo -e "${YELLOW}Monitor in real-time:${NC}"
echo -e "  Grafana:     http://localhost:3001 (admin / see .env)"
echo -e "  Prometheus:  http://localhost:9091"
echo -e "  Logs:        docker compose -f docker-compose.poc.yml logs -f proxy"
echo ""

echo -e "${GREEN}▶ Starting TLS traffic generation (containerized)...${NC}"
echo ""

# Run traffic generator in a container on the ja4proxy network
docker compose -f docker-compose.poc.yml run --rm \
    -e PYTHONUNBUFFERED=1 \
    trafficgen \
    --target-host proxy --target-port 8080 \
    --duration "${DURATION}" \
    --good-percent "${GOOD_PERCENT}" \
    --workers "${WORKERS}"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Traffic generation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Show quick metrics summary
echo -e "${BLUE}Quick Metrics Summary:${NC}"
echo ""

if curl -s http://localhost:9090/metrics > /tmp/ja4_metrics.txt 2>/dev/null; then
    echo -e "${CYAN}Total Requests:${NC}"
    grep "^ja4_requests_total" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"

    echo ""
    echo -e "${CYAN}Blocked Requests:${NC}"
    grep "^ja4_blocked_requests_total" /tmp/ja4_metrics.txt | grep -v "#" || echo "  No data yet"

    rm -f /tmp/ja4_metrics.txt
else
    echo -e "${YELLOW}  Metrics endpoint not accessible${NC}"
fi

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. View metrics: ${CYAN}curl http://localhost:9090/metrics | grep ja4_${NC}"
echo -e "  2. Grafana:      ${CYAN}http://localhost:3001${NC} (metrics + logs)"
echo -e "  3. Run again:    ${CYAN}./generate-tls-traffic.sh <duration> <good%> <workers>${NC}"
echo ""
