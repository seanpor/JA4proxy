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

# Lane port map (managed by scripts/lane-env.sh); metrics + Grafana are lane-offset.
[ -f .env ] && { set -a; source .env; set +a; }

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          JA4proxy TLS Traffic Generator                           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
echo -e "${BLUE}▶ Checking services...${NC}"

if ! docker compose -f deploy/docker/docker-compose.poc.yml ps 2>/dev/null | grep -q "ja4proxy.*Up"; then
    echo -e "${RED}✗ JA4proxy services are not running${NC}"
    echo -e "${YELLOW}  Start with: ./scripts/start-poc.sh or ./scripts/start-all.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Services are running${NC}"
echo ""

# Clear stale rate-tracking, bans, and audit keys from previous runs
# (preserves whitelist/blacklist configuration)
echo -e "${BLUE}▶ Clearing stale security state from previous runs...${NC}"
REDIS_PASS=$(grep '^REDIS_PASSWORD=' .env 2>/dev/null | cut -d= -f2)
if [ -n "$REDIS_PASS" ]; then
    # Delete transient security state (keep ja4:whitelist/blacklist)
    docker exec ja4proxy-redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
        EVAL "local n=0; for _,p in ipairs({'enforcement:*','audit:*','rate:*','banned:*','blocked:*','repeat_block:*'}) do for _,k in ipairs(redis.call('keys',p)) do redis.call('del',k); n=n+1 end end; return n" 0 \
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
echo -e "  Grafana:     https://localhost:${HOST_PORT_GRAFANA:-3000} (admin / see .env)"
echo -e "  Prometheus:  http://localhost:${HOST_PORT_PROMETHEUS:-9091}"
echo -e "  Logs:        docker compose -f deploy/docker/docker-compose.poc.yml logs -f proxy"
echo ""

echo -e "${GREEN}▶ Starting TLS traffic generation (containerized)...${NC}"
echo ""

# Run traffic generator in a container on the ja4proxy network
docker compose -f deploy/docker/docker-compose.poc.yml run --rm \
    -e PYTHONUNBUFFERED=1 \
    -e HOST_PORT_GRAFANA="${HOST_PORT_GRAFANA:-3001}" \
    -e HOST_PORT_PROMETHEUS="${HOST_PORT_PROMETHEUS:-9091}" \
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

# Show quick metrics summary (aggregated — avoids per-TTL label explosion)
echo -e "${BLUE}Quick Metrics Summary:${NC}"
echo ""

# The proxy's /metrics endpoint requires a Bearer token when scraped
# non-loopback and serves the ja4proxy_* metric family (JA4PROXY-2026-0008).
METRICS_URL="http://localhost:${HOST_PORT_METRICS:-9090}/metrics"
if curl -sf -H "Authorization: Bearer ${METRICS_AUTH_TOKEN:-}" "${METRICS_URL}" > /tmp/ja4_metrics.txt 2>/dev/null; then
    echo -e "${CYAN}Requests by fingerprint + action:${NC}"
    grep "^ja4proxy_connections_total" /tmp/ja4_metrics.txt | grep -v "#" \
        | awk -F'"' '
            {
                name=""; action=""
                for(i=2;i<=NF;i+=2){
                    if($(i-1)~"fingerprint_name=") name=$i
                    if($(i-1)~"action=") action=$i
                }
                val=$NF; gsub(/^[^0-9.]+/,"",val)
                key=sprintf("  %-30s %-10s", name, action)
                total[key]+=val
            }
            END{ for(k in total) printf "%s %g\n", k, total[k] }
        ' | sort || echo "  No data yet"

    echo ""

    # Sum all blocked counts into a single total (reason label varies per TTL)
    total_blocked=$(grep "^ja4proxy_blocked_requests_total" /tmp/ja4_metrics.txt | grep -v "#" \
        | awk '{val=$NF; gsub(/^[^0-9.]+/,"",val); sum+=val} END{printf "%.0f", sum}')
    # Break down by attack_type label only
    echo -e "${CYAN}Blocked requests by action type:${NC}"
    grep "^ja4proxy_blocked_requests_total" /tmp/ja4_metrics.txt | grep -v "#" \
        | awk -F'"' '
            {
                atype=""
                for(i=1;i<=NF;i++){
                    if($(i-1)~"attack_type=") atype=$i
                }
                val=$NF; gsub(/^[^0-9.]+/,"",val)
                total[atype]+=val
            }
            END{ for(k in total) printf "  %-12s %s\n", k, total[k] }
        ' | sort || echo "  No data yet"
    echo "  ─────────────────────"
    echo "  Total blocked  ${total_blocked}"

    rm -f /tmp/ja4_metrics.txt
else
    echo -e "${YELLOW}  Metrics endpoint not accessible (${METRICS_URL})${NC}"
fi

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
# The inner quotes must be ESCAPED: this whole string is already double-quoted,
# so bare " characters closed and reopened the outer quoting instead of being
# printed. The suggested command came out as
#   curl -s -H Authorization: Bearer <token> <url>
# which bash splits into separate args -- curl sees "-H Authorization:" (an
# empty header, which DELETES the header) and the rest as URLs, so the request
# went out unauthenticated and returned 401. Copy-pasting the tool's own
# suggestion could never work.
echo -e "  1. View metrics: ${CYAN}curl -s -H \"Authorization: Bearer ${METRICS_AUTH_TOKEN:-}\" ${METRICS_URL} | grep ja4proxy_${NC}"
echo -e "  2. Grafana:      ${CYAN}https://localhost:${HOST_PORT_GRAFANA:-3000}${NC} (metrics + logs)"
echo -e "  3. Run again:    ${CYAN}./scripts/generate-tls-traffic.sh <duration> <good%> <workers>${NC}"
echo ""
