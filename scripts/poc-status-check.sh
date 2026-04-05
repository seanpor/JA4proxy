#!/usr/bin/env bash
# poc-status-check.sh — Quick POC readiness check
#
# Verifies the core POC stack is up and all components are reachable.
# For a full health dashboard (including security state), use: ./status.sh

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Load .env for credentials
if [ -f .env ]; then
    set -a; source .env; set +a
fi
REDIS_PASS="${REDIS_PASSWORD:-changeme}"

ERRORS=0

pass() { echo -e "  ${GREEN}✓${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

echo ""
echo "JA4proxy — POC Readiness Check"
echo "────────────────────────────────────────"

# ── Containers ─────────────────────────────────────────────────────────────────
echo ""
echo "Containers:"
for svc in haproxy proxy redis backend tarpit; do
    if docker compose -f docker-compose.poc.yml ps "$svc" --format '{{.Status}}' 2>/dev/null | grep -qi "Up"; then
        STATUS=$(docker compose -f docker-compose.poc.yml ps "$svc" --format '{{.Status}}' 2>/dev/null)
        pass "$svc  ($STATUS)"
    else
        fail "$svc  — not running"
    fi
done

# ── Service health ──────────────────────────────────────────────────────────────
echo ""
echo "Service health:"

curl -sf --max-time 3 http://localhost:9090/metrics > /dev/null 2>&1 \
    && pass "Proxy metrics       http://localhost:9090/metrics" \
    || fail "Proxy metrics       http://localhost:9090/metrics — not reachable"

curl -sfk --max-time 3 https://localhost:8443/api/health > /dev/null 2>&1 \
    && pass "Backend (TLS)       https://localhost:8443/api/health" \
    || fail "Backend (TLS)       https://localhost:8443/api/health — not reachable"

curl -sf --max-time 3 http://localhost:8404/stats > /dev/null 2>&1 \
    && pass "HAProxy stats       http://localhost:8404/stats" \
    || fail "HAProxy stats       http://localhost:8404/stats — not reachable"

docker compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning ping > /dev/null 2>&1 \
    && pass "Redis               authenticated connection OK" \
    || fail "Redis               — not reachable or wrong password"

# ── JA4 blacklist ───────────────────────────────────────────────────────────────
echo ""
echo "Security state:"

BL=$(docker compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning SCARD ja4:blacklist 2>/dev/null || echo 0)
WL=$(docker compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning SCARD ja4:whitelist 2>/dev/null || echo 0)
if [ "${BL:-0}" -gt 0 ]; then
    pass "JA4 blacklist:  $BL fingerprints loaded"
else
    warn "JA4 blacklist is empty — check config/proxy.yml blacklist section"
fi
pass "JA4 whitelist:  $WL fingerprints loaded"

# ── JA4 metrics ─────────────────────────────────────────────────────────────────
METRICS=$(curl -s --max-time 3 http://localhost:9090/metrics 2>/dev/null | grep -c "^ja4_" || true)
if [ "${METRICS:-0}" -gt 0 ]; then
    pass "JA4 metrics:    $METRICS metric series active"
else
    warn "No JA4 metrics yet — send some traffic first: ./scripts/generate-tls-traffic.sh 10 15 5"
fi

# ── Config files ────────────────────────────────────────────────────────────────
echo ""
echo "Configuration:"
[ -f config/proxy.yml ]        && pass "config/proxy.yml" || fail "config/proxy.yml — missing"
[ -f docker-compose.poc.yml ]  && pass "docker-compose.poc.yml" || fail "docker-compose.poc.yml — missing"
[ -f .env ]                    && pass ".env (credentials file)" || warn ".env missing — run ./scripts/start-poc.sh to auto-generate"

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${GREEN}POC stack is ready.${NC}"
    echo ""
    echo "  Next steps:"
    echo "    Generate traffic:  ./scripts/generate-tls-traffic.sh 60 15 20"
    echo "    Watch the proxy:   make logs"
    echo "    Security status:   ./scripts/ja4-admin.sh status"
    echo "    Full dashboard:    ./scripts/status.sh"
else
    echo -e "  ${RED}${ERRORS} issue(s) found.${NC}"
    echo ""
    echo "  If services are not running:  ./scripts/start-poc.sh"
    echo "  View startup logs:            make logs"
fi
echo ""
