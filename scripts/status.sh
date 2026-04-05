#!/usr/bin/env bash
# status.sh — Unified JA4proxy health status
#
# Shows at a glance: container states, service health, active credentials,
# current backend config, and live security state.
#
# Usage:  ./status.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ENV_FILE="${ENV_FILE:-.env}"

ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}·${NC}  $*"; }

ERRORS=0

# ── Load .env ──────────────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
    set -a; source "$ENV_FILE"; set +a
fi
REDIS_PASS="${REDIS_PASSWORD:-changeme}"
GRAFANA_PASS="${GRAFANA_PASSWORD:-admin}"
BACKEND_HOST="${BACKEND_HOST:-backend}"
BACKEND_PORT="${BACKEND_PORT:-443}"

redis_cmd() {
    docker compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning "$@" 2>/dev/null
}

echo
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  JA4proxy — Status Overview$(date +'  %Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"

# ── 1. Configuration ───────────────────────────────────────────────────────────
echo
echo -e "${BOLD}▸ Configuration${NC}"
info "Backend:  ${BACKEND_HOST}:${BACKEND_PORT}"
if [ "${REDIS_PASSWORD:-changeme}" = "changeme" ]; then
    warn "Redis password is default 'changeme' — run ./scripts/start-poc.sh to auto-generate"
else
    info "Redis:    password set ($(echo "${REDIS_PASSWORD}" | wc -c | tr -d ' ')+ chars)"
fi
if [ "${GRAFANA_PASSWORD:-admin}" = "admin" ]; then
    warn "Grafana password is default 'admin' — run ./scripts/start-poc.sh to auto-generate"
else
    info "Grafana:  password set"
fi

# ── 2. Docker containers ───────────────────────────────────────────────────────
echo
echo -e "${BOLD}▸ Docker Containers${NC}"

check_service() {
    local svc="$1" label="$2"
    local status
    status=$(docker compose -f docker-compose.poc.yml ps "$svc" --format '{{.Status}}' 2>/dev/null || true)
    
    if [ -n "$status" ]; then
        if echo "$status" | grep -qi "Up"; then
            ok "${label} (${status})"
        else
            fail "${label} — STOPPED (${status})"
        fi
    else
        # Try monitoring compose if not in POC
        status=$(docker compose -f docker/docker-compose.monitoring.yml ps "$svc" --format '{{.Status}}' 2>/dev/null || true)
        if [ -n "$status" ]; then
             if echo "$status" | grep -qi "Up"; then
                ok "${label} (${status})"
            else
                fail "${label} — STOPPED (${status})"
            fi
        else
            warn "${label} — not deployed"
        fi
    fi
}

check_service haproxy     "HAProxy         :443 / :8404"
check_service proxy       "JA4 Proxy       :8080 / metrics :9090"
check_service redis       "Redis           (internal)"
check_service backend     "Mock Backend    :8443"
check_service tarpit      "Tarpit          :8888"
check_service prometheus  "Prometheus    :9091"
check_service grafana     "Grafana          :3001"
check_service loki        "Loki             (internal)"
# Management UI might be in a different file or service name
# check_service management-ui "Management UI    :8001"

# ── 3. Service health ──────────────────────────────────────────────────────────
echo
echo -e "${BOLD}▸ Service Health${NC}"

http_check() {
    local label="$1" url="$2" extra="${3:-}"
    if curl -sf --max-time 3 $extra "$url" > /dev/null 2>&1; then
        ok "$label  ($url)"
    else
        fail "$label  ($url) — not reachable"
    fi
}

http_check "Proxy metrics"   "http://localhost:9090/metrics"
http_check "Backend TLS"     "https://localhost:8443/api/health" "-k"
http_check "HAProxy stats"   "http://localhost:8404/stats"
http_check "Prometheus"      "http://localhost:9091/-/ready"
http_check "Grafana"         "http://localhost:3001/api/health"
http_check "Management UI"  "http://localhost:8001/health"

# Redis
if docker compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning ping > /dev/null 2>&1; then
    ok "Redis  (docker network — authenticated)"
else
    fail "Redis  — not reachable or auth failed"
fi

# ── 4. Security state ──────────────────────────────────────────────────────────
echo
echo -e "${BOLD}▸ Live Security State${NC}"

if docker compose -f docker-compose.poc.yml ps redis --format '{{.Status}}' 2>/dev/null | grep -qi "Up"; then
    BL_COUNT=$(redis_cmd SCARD ja4:blacklist 2>/dev/null || echo "?")
    WL_COUNT=$(redis_cmd SCARD ja4:whitelist 2>/dev/null || echo "?")
    SAFE_CC=$(redis_cmd SCARD geoip:safe_countries 2>/dev/null || echo "?")
    DYN_CC=$(redis_cmd SCARD geoip:dynamic_blacklist 2>/dev/null || echo "?")
    CIDRS=$(redis_cmd SCARD geoip:blocked_cidrs 2>/dev/null || echo "?")
    BANS=$(redis_cmd KEYS 'banned:*' 2>/dev/null | wc -l | tr -d ' ')
    BLOCKS=$(redis_cmd KEYS 'blocked:*' 2>/dev/null | wc -l | tr -d ' ')
    PENDING=$(redis_cmd HLEN ja4:pending 2>/dev/null || echo "0")

    info "JA4 blacklist:   ${BL_COUNT} fingerprints"
    info "JA4 whitelist:   ${WL_COUNT} fingerprints"
    info "Safe countries:  ${SAFE_CC} (protected from auto-block)"
    info "Blocked countries (dynamic): ${DYN_CC}"
    info "Blocked CIDRs:   ${CIDRS}"
    info "Active bans:     ${BANS}"
    info "Active blocks:   ${BLOCKS}"
    [ "${PENDING:-0}" -gt 0 ] && warn "Pending ja4db fingerprints awaiting approval: ${PENDING}  →  make list-pending"
else
    warn "Redis not running — cannot retrieve security state"
fi

# ── 5. Access summary ──────────────────────────────────────────────────────────
echo
echo -e "${BOLD}▸ Access URLs${NC}"
echo -e "  HAProxy (TLS entry):  ${CYAN}https://localhost:443${NC}"
echo -e "  HAProxy stats:        ${CYAN}http://localhost:8404/stats${NC}"
echo -e "  Proxy metrics:        ${CYAN}http://localhost:9090/metrics${NC}"
echo -e "  Prometheus:           ${CYAN}http://localhost:9091${NC}"
echo -e "  Grafana:              ${CYAN}http://localhost:3001${NC}  (admin / ${GRAFANA_PASS})"
UI_PASS=$(grep UI_PASSWORD .env 2>/dev/null | cut -d= -f2 || echo "see .env")
echo -e "  Management UI:        ${CYAN}http://localhost:8001${NC}  (admin / ${UI_PASS})"
echo

# ── 6. Summary ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}▸ Summary${NC}"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All checks passed.${NC}"
else
    echo -e "  ${RED}${BOLD}${ERRORS} issue(s) found.${NC} Check output above."
fi
echo
echo -e "  Quick commands:"
echo -e "    ${CYAN}./scripts/ja4-admin.sh status${NC}     — live attack snapshot"
echo -e "    ${CYAN}./scripts/ja4-admin.sh top 10${NC}     — top fingerprints by traffic"
echo -e "    ${CYAN}make flush-redis${NC}                  — clear bans/blocks (keep lists)"
echo
