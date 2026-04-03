#!/usr/bin/env bash
# scripts/check-isolation.sh — Verify multi-agent Docker isolation
#
# Runs a series of checks from the host and from inside containers to confirm
# that network zones, port surface, Docker socket access, and cross-agent
# isolation are all correctly enforced.
#
# Usage:
#   ./scripts/check-isolation.sh                  # uses .current-agent
#   ./scripts/check-isolation.sh --agent claude   # explicit agent
#
# Requires: at least one agent stack running (make agent-up NAME=<agent>)
# Exit code: 0 = all checks pass, 1 = one or more checks failed

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}✓ PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗ FAIL${NC}  $*"; ((FAIL++)); }
info() { echo -e "  ${YELLOW}→${NC}      $*"; }
section() { echo ""; echo -e "${BOLD}$*${NC}"; }

# ── Resolve agent ──────────────────────────────────────────────────────────────

AGENT=""
if [[ "${1:-}" == "--agent" ]]; then
    AGENT="${2:?--agent requires a name (gemini|claude|ollama|mistral)}"
elif [[ -f ".current-agent" ]]; then
    AGENT="$(cat .current-agent)"
fi

if [[ -z "$AGENT" ]]; then
    # Try to detect from running ja4_* containers
    AGENT=$(docker compose ls 2>/dev/null | grep '^ja4_' | head -1 | awk '{print $1}' | sed 's/^ja4_//' || true)
fi

if [[ -z "$AGENT" ]]; then
    echo -e "${RED}✗ No running ja4_* agent found.${NC}"
    echo "  Start one with:  make agent-up NAME=<agent>"
    echo "  Or specify:      ./scripts/check-isolation.sh --agent <agent>"
    exit 1
fi

ENV_FILE=".env.${AGENT}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo -e "${RED}✗ No $ENV_FILE found.${NC}"
    exit 1
fi

BIND_IP=$(grep '^AGENT_BIND_IP=' "$ENV_FILE" | cut -d= -f2)
PROJECT="ja4_${AGENT}"

PROXY_CONTAINER="${PROJECT}-proxy-1"
REDIS_CONTAINER="${PROJECT}-redis-1"
BACKEND_CONTAINER="${PROJECT}-backend-1"
HAPROXY_CONTAINER="${PROJECT}-haproxy-1"
ANALYTICS_CONTAINER="${PROJECT}-analytics-1"

echo -e "${BOLD}══ JA4proxy Isolation Audit ══${NC}"
echo -e "  Agent:   ${AGENT}"
echo -e "  IP:      ${BIND_IP}"
echo -e "  Project: ${PROJECT}"

# ── Section 1: Host Port Surface ──────────────────────────────────────────────
section "1. Host Port Surface (${BIND_IP})"

OPEN_PORTS=$(ss -tlnp 2>/dev/null | grep "$BIND_IP" | awk '{print $4}' | awk -F: '{print $NF}' | sort -n || true)

for port in 443 8080 8404 9090; do
    if echo "$OPEN_PORTS" | grep -qx "${port}"; then
        pass "Port ${BIND_IP}:${port} open (expected)"
    else
        fail "Port ${BIND_IP}:${port} NOT open (expected)"
    fi
done

UNEXPECTED=$(echo "$OPEN_PORTS" | grep -vxE '(443|8080|8404|9090)' || true)
if [[ -z "$UNEXPECTED" ]]; then
    pass "No unexpected ports on ${BIND_IP}"
else
    fail "Unexpected ports on ${BIND_IP}: $(echo "$UNEXPECTED" | tr '\n' ' ')"
fi

if ss -tlnp 2>/dev/null | grep -q ':6379 '; then
    fail "Redis port 6379 exposed on host (should be internal only)"
else
    pass "Redis port 6379 not exposed to host"
fi

if ss -tlnp 2>/dev/null | grep -q ':8443 '; then
    fail "Backend port 8443 exposed on host (should be internal only)"
else
    pass "Backend port 8443 not exposed to host"
fi

# ── Section 2: Docker Socket ──────────────────────────────────────────────────
section "2. Docker Socket Access"

if docker exec "$PROXY_CONTAINER" test -S /var/run/docker.sock 2>/dev/null; then
    fail "Docker socket accessible inside proxy container"
else
    pass "Docker socket NOT accessible inside proxy container"
fi

if docker exec "$REDIS_CONTAINER" test -S /var/run/docker.sock 2>/dev/null; then
    fail "Docker socket accessible inside redis container"
else
    pass "Docker socket NOT accessible inside redis container"
fi

# ── Section 3: Network Zone Isolation ────────────────────────────────────────
section "3. Network Zone Isolation"

# data_net: Redis must not reach internet (internal: true)
info "Redis → internet (expect: unreachable)..."
if docker exec "$REDIS_CONTAINER" ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    fail "Redis can reach internet (data_net should have internal: true)"
else
    pass "Redis cannot reach internet (data_net isolated)"
fi

# origin_net: Backend must not reach internet (internal: true)
info "Backend → internet (expect: unreachable)..."
if docker exec "$BACKEND_CONTAINER" ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    fail "Backend can reach internet (origin_net should have internal: true)"
else
    pass "Backend cannot reach internet (origin_net isolated)"
fi

# HAProxy must not reach Redis (no shared network)
info "HAProxy → Redis (expect: no route)..."
if docker exec "$HAPROXY_CONTAINER" nc -z -w2 redis 6379 >/dev/null 2>&1; then
    fail "HAProxy can reach Redis directly (they share no network)"
else
    pass "HAProxy cannot reach Redis (zone boundary confirmed)"
fi

# Analytics must not reach Backend (no shared network)
info "Analytics → Backend (expect: no route)..."
if docker exec "$ANALYTICS_CONTAINER" nc -z -w2 backend 443 >/dev/null 2>&1; then
    fail "Analytics can reach Backend directly (they share no network)"
else
    pass "Analytics cannot reach Backend (zone boundary confirmed)"
fi

# Proxy must reach Redis (data_net)
info "Proxy → Redis (expect: reachable)..."
if docker exec "$PROXY_CONTAINER" nc -z -w2 redis 6379 >/dev/null 2>&1; then
    pass "Proxy can reach Redis (data_net working)"
else
    fail "Proxy CANNOT reach Redis (data_net broken)"
fi

# Proxy must reach Backend (origin_net)
info "Proxy → Backend (expect: reachable)..."
if docker exec "$PROXY_CONTAINER" nc -z -w2 backend 443 >/dev/null 2>&1; then
    pass "Proxy can reach Backend (origin_net working)"
else
    fail "Proxy CANNOT reach Backend (origin_net broken)"
fi

# ── Section 4: IPC Namespace Isolation ───────────────────────────────────────
section "4. IPC Namespace (/dev/shm)"

PROXY_SHM=$(docker exec "$PROXY_CONTAINER" stat -c '%i' /dev/shm 2>/dev/null || echo "unknown")
REDIS_SHM=$(docker exec "$REDIS_CONTAINER" stat -c '%i' /dev/shm 2>/dev/null || echo "unknown2")

if [[ "$PROXY_SHM" != "$REDIS_SHM" ]]; then
    pass "/dev/shm inode differs between proxy and redis (independent)"
else
    fail "/dev/shm appears shared between proxy and redis (inode: ${PROXY_SHM})"
fi

# ── Section 5: Cross-Agent Isolation ─────────────────────────────────────────
section "5. Cross-Agent Isolation"

OTHER_AGENTS="gemini claude ollama mistral"
CHECKED=0

for other in $OTHER_AGENTS; do
    [[ "$other" == "$AGENT" ]] && continue
    OTHER_ENV=".env.${other}"
    [[ -f "$OTHER_ENV" ]] || continue
    CHECKED=$((CHECKED + 1))
    OTHER_IP=$(grep '^AGENT_BIND_IP=' "$OTHER_ENV" | cut -d= -f2)
    info "Proxy → ${other} (${OTHER_IP}:443, expect: unreachable from container)..."
    if docker exec "$PROXY_CONTAINER" nc -z -w2 "$OTHER_IP" 443 >/dev/null 2>&1; then
        fail "Proxy container can reach ${other} agent at ${OTHER_IP}:443"
    else
        pass "Proxy container cannot reach ${other} at ${OTHER_IP}:443"
    fi
done

if [[ "$CHECKED" -eq 0 ]]; then
    info "No other agent .env files found — cross-agent check skipped"
    info "Start another agent with 'make agent-up NAME=<other>' to test cross-agent isolation"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══ Results ══${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  Checks run: ${TOTAL}  |  ${GREEN}PASS: ${PASS}${NC}  |  ${RED}FAIL: ${FAIL}${NC}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}✗ Isolation audit FAILED — ${FAIL} check(s) need attention.${NC}"
    exit 1
else
    echo -e "${GREEN}✓ All isolation checks passed.${NC}"
    exit 0
fi
