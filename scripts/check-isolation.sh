#!/usr/bin/env bash
# scripts/check-isolation.sh — Verify multi-agent Docker isolation
#
# Runs checks from the host and inside containers to confirm network zones,
# port surface, Docker socket access, and cross-agent isolation are enforced.
#
# Usage:
#   ./scripts/check-isolation.sh                  # uses .current-agent
#   ./scripts/check-isolation.sh --agent claude   # explicit agent
#
# Requirements: at least one agent stack running (make agent-up NAME=<agent>)
# Exit code: 0 = all checks pass, 1 = one or more checks failed

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}✓ PASS${NC}  $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗ FAIL${NC}  $*"; FAIL=$((FAIL + 1)); }
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
    AGENT=$(docker compose ls 2>/dev/null | grep '^ja4_' | head -1 | awk '{print $1}' | sed 's/^ja4_//' || true)
fi

if [[ -z "$AGENT" ]]; then
    echo -e "${RED}✗ No running ja4_* agent found.${NC}"
    echo "  Start one with:  make agent-up NAME=<agent>"
    echo "  Or specify:      ./scripts/check-isolation.sh --agent <agent>"
    exit 1
fi

ENV_FILE=".env.${AGENT}"
[[ -f "$ENV_FILE" ]] || { echo -e "${RED}✗ No $ENV_FILE found.${NC}"; exit 1; }

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

# ── Helper: Python TCP connect test inside a container ────────────────────────
# Usage: py_connect <container> <host> <port> <timeout>
# Returns 0 if connected, 1 if not
py_connect() {
    local ctr="$1" host="$2" port="$3" timeout="${4:-2}"
    docker exec "$ctr" python3 -c "
import socket, sys
s = socket.socket()
s.settimeout($timeout)
try:
    s.connect(('$host', $port))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null
}

# ── Helper: check if two containers share a Docker network (host-side) ────────
containers_share_network() {
    local c1="$1" c2="$2"
    local nets1 nets2
    nets1=$(docker inspect "$c1" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
    nets2=$(docker inspect "$c2" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
    for net in $nets1; do
        if echo "$nets2" | grep -qw "$net"; then
            return 0
        fi
    done
    return 1
}

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

for ctr in "$PROXY_CONTAINER" "$REDIS_CONTAINER"; do
    if docker exec "$ctr" test -S /var/run/docker.sock 2>/dev/null; then
        fail "Docker socket accessible inside ${ctr}"
    else
        pass "Docker socket NOT accessible inside ${ctr}"
    fi
done

# ── Section 3: Network Zone Isolation ────────────────────────────────────────
section "3. Network Zone Isolation"

# ja4proxy-data: Redis must not reach internet (internal: true)
info "Redis → internet port 443 (expect: blocked)..."
if py_connect "$REDIS_CONTAINER" "8.8.8.8" 443 3; then
    fail "Redis can reach internet (ja4proxy-data should have internal: true)"
else
    pass "Redis cannot reach internet (ja4proxy-data isolated)"
fi

# ja4proxy-origin: Backend must not reach internet (internal: true)
info "Backend → internet port 443 (expect: blocked)..."
if py_connect "$BACKEND_CONTAINER" "8.8.8.8" 443 3; then
    fail "Backend can reach internet (ja4proxy-origin should have internal: true)"
else
    pass "Backend cannot reach internet (ja4proxy-origin isolated)"
fi

# HAProxy must not share a network with Redis (checked via Docker network inspection)
info "HAProxy ↔ Redis: shared network check (expect: none)..."
if containers_share_network "$HAPROXY_CONTAINER" "$REDIS_CONTAINER"; then
    fail "HAProxy and Redis share a Docker network (expected: no shared network)"
else
    pass "HAProxy and Redis share no Docker network"
fi

# Analytics must not share a network with Backend
info "Analytics ↔ Backend: shared network check (expect: none)..."
if containers_share_network "$ANALYTICS_CONTAINER" "$BACKEND_CONTAINER"; then
    fail "Analytics and Backend share a Docker network (expected: no shared network)"
else
    pass "Analytics and Backend share no Docker network"
fi

# Proxy must reach Redis (ja4proxy-data)
info "Proxy → Redis port 6379 (expect: reachable)..."
if py_connect "$PROXY_CONTAINER" "redis" 6379 3; then
    pass "Proxy can reach Redis (ja4proxy-data working)"
else
    fail "Proxy CANNOT reach Redis (ja4proxy-data broken)"
fi

# Proxy must reach Backend (ja4proxy-origin)
info "Proxy → Backend port 443 (expect: reachable)..."
if py_connect "$PROXY_CONTAINER" "backend" 443 3; then
    pass "Proxy can reach Backend (ja4proxy-origin working)"
else
    fail "Proxy CANNOT reach Backend (ja4proxy-origin broken)"
fi

# ── Section 4: IPC Namespace ──────────────────────────────────────────────────
section "4. IPC Namespace"

# Check IPC mode via docker inspect — "private" or "" means each container has
# its own IPC namespace. "host" or "container:<name>" means sharing.
for ctr in "$PROXY_CONTAINER" "$REDIS_CONTAINER" "$BACKEND_CONTAINER" "$ANALYTICS_CONTAINER"; do
    IPC_MODE=$(docker inspect "$ctr" --format '{{.HostConfig.IpcMode}}' 2>/dev/null || echo "unknown")
    if [[ "$IPC_MODE" == "host" || "$IPC_MODE" == container:* ]]; then
        fail "${ctr} has shared IPC mode: ${IPC_MODE}"
    else
        pass "${ctr} has private IPC namespace (mode: '${IPC_MODE:-private}')"
    fi
done

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
    if py_connect "$PROXY_CONTAINER" "$OTHER_IP" 443 3; then
        fail "Proxy container can reach ${other} agent at ${OTHER_IP}:443"
    else
        pass "Proxy container cannot reach ${other} at ${OTHER_IP}:443"
    fi
done

if [[ "$CHECKED" -eq 0 ]]; then
    info "No other agent .env files found — cross-agent check skipped"
    info "Start another agent with 'make agent-up NAME=<other>' to test"
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
