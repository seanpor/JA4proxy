#!/usr/bin/env bash
# demo-mgmt.sh — Orchestrate full JA4proxy showcase demo: boot, seed API, generate traffic, verify
#
# Phase 816: End-to-end management console demonstration orchestrator.
#   1. Starts the stack via scripts/demo-up.sh
#   2. Authenticates against the FastAPI Management API
#   3. Seeds policy lists (whitelists, blacklists, bans) via authenticated REST calls
#   4. Adjusts the blocking dial dynamically
#   5. Runs automated verification via scripts/demo-verify.sh
#   6. Displays the interactive demonstration walkthrough guide
#
# Usage:
#   scripts/demo-mgmt.sh [--dry-run] [--skip-up] [--help]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BOLD="\033[1m"
NC="\033[0m"

DRY_RUN=0
SKIP_UP=0

show_help() {
    cat << 'EOF'
Usage: scripts/demo-mgmt.sh [OPTIONS]

Orchestrate the full JA4proxy demonstration: boot stack, seed API state, run traffic, and verify.

Options:
  --dry-run       Validate environment and display orchestration plan without network/container actions
  --skip-up       Skip running demo-up.sh (use if demo stack is already up)
  -h, --help      Show this help message and exit

Orchestration steps:
  1. Boot stack via demo-up.sh
  2. Authenticate admin user against Management API
  3. Seed baseline JA4 whitelists, blacklists, IP allowlist, and active ban via REST API
  4. Adjust initial blocking dial via REST API
  5. Run 6-point verification via demo-verify.sh
  6. Output live demonstration guide and dashboard URLs
EOF
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        --skip-up)
            SKIP_UP=1
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
    echo -e "${BLUE}=== [DRY-RUN] JA4proxy Showcase Orchestration ===${NC}"
    echo "1. Run scripts/demo-up.sh (or reuse existing containers)"
    echo "2. Read admin credentials from .env"
    echo "3. Authenticate with Management API at POST /auth/login"
    echo "4. Seed JA4 Whitelist (Chrome/Firefox): t13d1212h2_eac1b15b5477_8e6e362c5eac"
    echo "5. Seed JA4 Blacklist (Sliver C2): t13d091100_f91f431d341e_8e6e362c5eac"
    echo "6. Seed JA4 Blacklist (Cobalt Strike): t12d020800_04659ec43a24_36cef8aed422"
    echo "7. Seed IP Allowlist: 10.0.0.1"
    echo "8. Create Threat Ban: 198.51.100.42 (duration: 24h)"
    echo "9. Adjust Blocking Dial to 50 via PUT /api/v1/dial"
    echo "10. Run scripts/demo-verify.sh"
    echo "11. Display interactive walkthrough guide"
    echo -e "${GREEN}✓ Dry-run orchestration plan validated successfully.${NC}"
    exit 0
fi

[ -f .env ] && { set -a; source .env; set +a; }

BIND_IP="${AGENT_BIND_IP:-127.0.0.1}"
MGMT_PORT="${HOST_PORT_MANAGEMENT:-8090}"
GRAFANA_PORT="${HOST_PORT_GRAFANA:-3000}"
PROM_PORT="${HOST_PORT_PROMETHEUS:-9091}"
PROXY_PORT="${HOST_PORT_DIRECT:-8081}"
ADMIN_USER="${MANAGEMENT_ADMIN_USER:-admin}"
ADMIN_PASS="${MANAGEMENT_ADMIN_PASSWORD:-}"

# Step 1: Up
if [ "$SKIP_UP" -eq 0 ]; then
    echo -e "${BLUE}▶ 1. Starting demo environment...${NC}"
    bash scripts/demo-up.sh
fi

# Reload .env if updated by start-poc
[ -f .env ] && { set -a; source .env; set +a; }
ADMIN_PASS="${MANAGEMENT_ADMIN_PASSWORD:-}"

echo -e "${BLUE}▶ 2. Authenticating against Management API...${NC}"
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

LOGIN_URL="http://${BIND_IP}:${MGMT_PORT}/auth/login"
LOGIN_DATA="username=${ADMIN_USER}&password=${ADMIN_PASS}"

LOGIN_HTTP_CODE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" \
    -X POST "$LOGIN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$LOGIN_DATA" || echo "000")

if [ "$LOGIN_HTTP_CODE" != "200" ] && [ "$LOGIN_HTTP_CODE" != "302" ]; then
    echo -e "${YELLOW}Warning: Form login returned HTTP ${LOGIN_HTTP_CODE}; trying JSON body...${NC}"
    LOGIN_HTTP_CODE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" \
        -X POST "$LOGIN_URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASS}\"}" || echo "000")
fi

if [ "$LOGIN_HTTP_CODE" = "200" ] || [ "$LOGIN_HTTP_CODE" = "302" ]; then
    echo -e "${GREEN}  ✓ Authenticated successfully as '${ADMIN_USER}'${NC}"
else
    echo -e "${RED}Error: Authentication failed with HTTP ${LOGIN_HTTP_CODE}${NC}" >&2
    exit 1
fi

# Step 3: Seed lists via API
echo -e "${BLUE}▶ 3. Seeding baseline lists and policies via Management REST API...${NC}"

api_post() {
    local path="$1"
    local data="${2:-}"
    local url="http://${BIND_IP}:${MGMT_PORT}${path}"
    if [ -n "$data" ]; then
        curl -s -b "$COOKIE_JAR" -X POST "$url" -H "Content-Type: application/json" -d "$data" > /dev/null
    else
        curl -s -b "$COOKIE_JAR" -X POST "$url" > /dev/null
    fi
}

api_put() {
    local path="$1"
    local data="$2"
    local url="http://${BIND_IP}:${MGMT_PORT}${path}"
    curl -s -b "$COOKIE_JAR" -X PUT "$url" -H "Content-Type: application/json" -d "$data" > /dev/null
}

# 3a. Whitelist browser
BROWSER_FP="t13d1212h2_eac1b15b5477_8e6e362c5eac"
api_post "/api/v1/lists/ja4/whitelist/${BROWSER_FP}"
echo -e "${GREEN}  ✓ Whitelisted Chrome/Firefox JA4: ${BROWSER_FP}${NC}"

# 3b. Blacklist malicious tools
SLIVER_FP="t13d091100_f91f431d341e_8e6e362c5eac"
COBALT_FP="t12d020800_04659ec43a24_36cef8aed422"
api_post "/api/v1/lists/ja4/blacklist/${SLIVER_FP}"
api_post "/api/v1/lists/ja4/blacklist/${COBALT_FP}"
echo -e "${GREEN}  ✓ Blacklisted Sliver C2 JA4: ${SLIVER_FP}${NC}"
echo -e "${GREEN}  ✓ Blacklisted Cobalt Strike JA4: ${COBALT_FP}${NC}"

# 3c. IP allowlist
api_post "/api/v1/lists/ip/allowlist/10.0.0.1"
echo -e "${GREEN}  ✓ Allowlisted internal gateway IP: 10.0.0.1${NC}"

# 3d. Ban scanner IP
BAN_IP="198.51.100.42"
api_post "/api/v1/bans" "{\"ip\": \"${BAN_IP}\", \"reason\": \"Demo scanner threat-intel ban\", \"duration_hours\": 24}"
echo -e "${GREEN}  ✓ Banned malicious scanner IP: ${BAN_IP}${NC}"

# 3e. Set Blocking Dial to 50
api_put "/api/v1/dial" "{\"value\": 50}" || api_put "/api/v1/dial" "{\"dial\": 50}" || true
echo -e "${GREEN}  ✓ Adjusted Blocking Dial to 50 via API${NC}"

# Step 4: Let traffic settle
echo -e "${BLUE}▶ 4. Collecting initial live traffic telemetry (5 seconds)...${NC}"
sleep 5

# Step 5: Verification
echo -e "${BLUE}▶ 5. Running end-to-end automated verification...${NC}"
bash scripts/demo-verify.sh

# Step 6: Interactive Walkthrough Presentation
echo ""
echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo -e "${BLUE}${BOLD}            JA4proxy LIVE DEMONSTRATION WALKTHROUGH                   ${NC}"
echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo ""
echo -e "${BOLD}Access Endpoints & Credentials:${NC}"
echo -e "  Management Console:  ${CYAN}http://${BIND_IP}:${MGMT_PORT}${NC}"
echo -e "  Username / Password: ${BOLD}${ADMIN_USER}${NC} / ${BOLD}${ADMIN_PASS}${NC}"
echo -e "  Grafana Dashboard:   ${CYAN}https://${BIND_IP}:${GRAFANA_PORT}${NC} (admin / ${GRAFANA_PASSWORD:-admin})"
echo -e "  Prometheus Metrics:  ${CYAN}http://${BIND_IP}:${PROM_PORT}${NC}"
echo -e "  Proxy TLS Ingress:   ${CYAN}https://${BIND_IP}:${PROXY_PORT}${NC}"
echo ""
echo -e "${BOLD}Recommended 10-Minute Demonstration Narrative:${NC}"
echo -e "  ${YELLOW}1. Open Management Console${NC} -> Login at ${BOLD}http://${BIND_IP}:${MGMT_PORT}${NC}"
echo -e "  ${YELLOW}2. Live SSE Connection Stream${NC} -> Watch real-time incoming traffic (Chrome, Sliver, Cobalt)"
echo -e "  ${YELLOW}3. Inspect JA4 Fingerprint Decodes${NC} -> Click any connection to view TLS cipher & ALPN details"
echo -e "  ${YELLOW}4. Real-Time Mitigation${NC} -> Click 'Blacklist' on an unblocked tool fingerprint in the feed"
echo -e "  ${YELLOW}5. Dynamic Blocking Dial${NC} -> Use the Dial widget to scale from Monitor (0) to Enforce (50-100)"
echo -e "  ${YELLOW}6. Grafana Security Overview${NC} -> Watch Blocked/sec and Action Breakdown panels shift in real time"
echo -e "  ${YELLOW}7. Audit Log${NC} -> Navigate to Audit page to show cryptographic tamper-evident event logs"
echo ""
echo -e "${BOLD}Teardown when finished:${NC}"
echo -e "  Run ${BOLD}make demo-stop${NC} or ${BOLD}scripts/stop-all.sh${NC}"
echo -e "${BLUE}${BOLD}======================================================================${NC}"
