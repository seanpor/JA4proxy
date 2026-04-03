# PHASE 75 — Docker Isolation: Security Audit & Validation

## Status: OPEN

---

## Goal

Perform a final security audit of the multi-agent environment, ensuring no lateral
movement, resource leaks, or egress violations. Produce an automated script that
any operator can run to verify isolation health.

---

## 75a. `scripts/check-isolation.sh`

This script verifies the isolation model from outside the containers (host-level checks)
and from inside selected containers (cross-zone checks via `docker exec`).

**Requirements:**
- Takes an optional `--agent <name>` argument (defaults to first running `ja4_*` project)
- Prints PASS/FAIL per check with colour
- Exits 0 if all checks pass, 1 if any fail
- Requires at least one agent stack to be running

```bash
#!/usr/bin/env bash
# scripts/check-isolation.sh — Verify multi-agent Docker isolation
#
# Usage: ./scripts/check-isolation.sh [--agent <name>]
#
# Requires: at least one agent stack running (make agent-up NAME=...)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}✓ PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗ FAIL${NC}  $1"; ((FAIL++)); }
info() { echo -e "  ${YELLOW}→${NC}      $1"; }

AGENT="${2:-}"
if [[ "${1:-}" == "--agent" ]]; then
    AGENT="$2"
fi

# Derive agent name from first running ja4_* project if not specified
if [[ -z "$AGENT" ]]; then
    AGENT=$(docker compose ls --filter name=ja4_ --format json 2>/dev/null \
        | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['Name'].replace('ja4_',''))" 2>/dev/null || true)
fi
[[ -n "$AGENT" ]] || { echo "No running ja4_* agent found. Start one with: make agent-up NAME=<agent>"; exit 1; }

ENV_FILE=".env.${AGENT}"
[[ -f "$ENV_FILE" ]] || { echo "No $ENV_FILE found."; exit 1; }
BIND_IP=$(grep '^AGENT_BIND_IP=' "$ENV_FILE" | cut -d= -f2)
PROJECT="ja4_${AGENT}"

echo -e "${BOLD}══ JA4proxy Isolation Audit — agent: ${AGENT} (${BIND_IP}) ══${NC}"
echo ""

# ── Section 1: Host Port Surface ──────────────────────────────────────────────
echo -e "${BOLD}1. Host Port Surface${NC}"

# Only expected ports should be open on BIND_IP
OPEN_PORTS=$(ss -tlnp | grep "$BIND_IP" | awk '{print $4}' | awk -F: '{print $NF}' | sort -n)
EXPECTED_PORTS="443 8080 8404 9090"

for port in $EXPECTED_PORTS; do
    if echo "$OPEN_PORTS" | grep -q "^${port}$"; then
        pass "Port ${BIND_IP}:${port} is open (expected)"
    else
        fail "Port ${BIND_IP}:${port} is NOT open (expected to be open)"
    fi
done

# No other ports should be open on BIND_IP
UNEXPECTED=$(echo "$OPEN_PORTS" | grep -vE '^(443|8080|8404|9090)$' || true)
if [[ -z "$UNEXPECTED" ]]; then
    pass "No unexpected ports open on ${BIND_IP}"
else
    fail "Unexpected ports open on ${BIND_IP}: $UNEXPECTED"
fi

# Redis must NOT be exposed on host
if ss -tlnp | grep -q ':6379'; then
    fail "Redis port 6379 is exposed on host (should be internal only)"
else
    pass "Redis port 6379 not exposed to host"
fi

# Backend must NOT be exposed on host  
if ss -tlnp | grep -q ':8443'; then
    fail "Backend port 8443 is exposed on host (should be internal only)"
else
    pass "Backend port 8443 not exposed to host"
fi

echo ""

# ── Section 2: Docker Socket ─────────────────────────────────────────────────
echo -e "${BOLD}2. Docker Socket Access${NC}"

PROXY_CONTAINER="${PROJECT}-proxy-1"
if docker exec "$PROXY_CONTAINER" test -S /var/run/docker.sock 2>/dev/null; then
    fail "Docker socket is accessible inside proxy container"
else
    pass "Docker socket NOT accessible inside proxy container"
fi

echo ""

# ── Section 3: Network Zone Isolation ────────────────────────────────────────
echo -e "${BOLD}3. Network Zone Isolation${NC}"

REDIS_CONTAINER="${PROJECT}-redis-1"
BACKEND_CONTAINER="${PROJECT}-backend-1"
ANALYTICS_CONTAINER="${PROJECT}-analytics-1"

# Redis on data_net (internal: true) — must not reach internet
info "Testing Redis egress (expect: 100% packet loss to 8.8.8.8)..."
if docker exec "$REDIS_CONTAINER" ping -c 2 -W 2 8.8.8.8 > /dev/null 2>&1; then
    fail "Redis can reach internet (data_net should be internal: true)"
else
    pass "Redis cannot reach internet (data_net is isolated)"
fi

# Backend on origin_net (internal: true) — must not reach internet
info "Testing backend egress (expect: 100% packet loss to 8.8.8.8)..."
if docker exec "$BACKEND_CONTAINER" ping -c 2 -W 2 8.8.8.8 > /dev/null 2>&1; then
    fail "Backend can reach internet (origin_net should be internal: true)"
else
    pass "Backend cannot reach internet (origin_net is isolated)"
fi

# HAProxy must not reach Redis directly (no shared network)
HAPROXY_CONTAINER="${PROJECT}-haproxy-1"
info "Testing HAProxy → Redis isolation (expect: no route)..."
if docker exec "$HAPROXY_CONTAINER" nc -z -w2 redis 6379 2>/dev/null; then
    fail "HAProxy can reach Redis directly (they should have no shared network)"
else
    pass "HAProxy cannot reach Redis (network isolation confirmed)"
fi

# Analytics must not reach Backend directly (no shared network)
info "Testing Analytics → Backend isolation (expect: no route)..."
if docker exec "$ANALYTICS_CONTAINER" nc -z -w2 backend 443 2>/dev/null; then
    fail "Analytics can reach Backend directly (they should have no shared network)"
else
    pass "Analytics cannot reach Backend (network isolation confirmed)"
fi

echo ""

# ── Section 4: Shared Memory / IPC ───────────────────────────────────────────
echo -e "${BOLD}4. IPC Namespace Isolation${NC}"

# /dev/shm should be container-private (not shared with host or other containers)
PROXY_SHM=$(docker exec "$PROXY_CONTAINER" df /dev/shm 2>/dev/null | tail -1 | awk '{print $1}')
REDIS_SHM=$(docker exec "$REDIS_CONTAINER" df /dev/shm 2>/dev/null | tail -1 | awk '{print $1}')
if [[ "$PROXY_SHM" != "$REDIS_SHM" ]] || [[ -z "$PROXY_SHM" ]]; then
    pass "/dev/shm is independent per container"
else
    fail "/dev/shm appears shared between proxy and redis"
fi

echo ""

# ── Section 5: Cross-Agent Isolation ─────────────────────────────────────────
echo -e "${BOLD}5. Cross-Agent Isolation${NC}"

# From inside a container, 127.0.0.x are the container's own loopback — not host.
# Therefore no other agent's bind IP should be reachable from inside.
OTHER_AGENTS="gemini claude ollama mistral"
for other in $OTHER_AGENTS; do
    [[ "$other" == "$AGENT" ]] && continue
    OTHER_ENV=".env.${other}"
    [[ -f "$OTHER_ENV" ]] || continue
    OTHER_IP=$(grep '^AGENT_BIND_IP=' "$OTHER_ENV" | cut -d= -f2)
    info "Testing: can proxy reach ${other}'s IP (${OTHER_IP}) from inside container?..."
    if docker exec "$PROXY_CONTAINER" nc -z -w2 "$OTHER_IP" 443 2>/dev/null; then
        fail "Proxy container can reach ${other} agent at ${OTHER_IP}:443"
    else
        pass "Proxy container cannot reach ${other} agent at ${OTHER_IP}:443"
    fi
done

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}══ Results ══${NC}"
echo -e "  ${GREEN}PASS: ${PASS}${NC}  |  ${RED}FAIL: ${FAIL}${NC}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}✗ Isolation audit FAILED — ${FAIL} check(s) need attention.${NC}"
    exit 1
else
    echo -e "${GREEN}✓ All isolation checks passed.${NC}"
    exit 0
fi
```

---

## 75b. Egress Violation Audit (Manual)

The script above automates the egress checks. For a manual one-liner:

```bash
# Verify Redis cannot reach internet
docker exec ja4_gemini-redis-1 ping -c 3 8.8.8.8
# Expected: 100% packet loss (network unreachable)

# Verify Backend cannot reach internet
docker exec ja4_gemini-backend-1 ping -c 3 8.8.8.8
# Expected: 100% packet loss
```

---

## 75c. Final Documentation

`docs/architecture/ISOLATION_MODEL.md` already exists and covers the model correctly.
After implementing phases 71–74, update the "Implementation for Agents" section to
reflect the `make agent-up` workflow and the actual (not planned) port table.

---

## Acceptance Criteria

- [ ] `scripts/check-isolation.sh` exists and is executable (`chmod +x`).
- [ ] `./scripts/check-isolation.sh --agent gemini` exits 0 with all PASS.
- [ ] `ping 8.8.8.8` from Redis container results in 0% success.
- [ ] `ping 8.8.8.8` from Backend container results in 0% success.
- [ ] HAProxy container cannot reach Redis container.
- [ ] Analytics container cannot reach Backend container.
- [ ] Docker socket is not accessible inside any container.
- [ ] `docs/architecture/ISOLATION_MODEL.md` updated to reflect implemented state.

---

## Files to Modify

| File | Change |
|------|--------|
| `scripts/check-isolation.sh` | New file — full script above |
| `docs/architecture/ISOLATION_MODEL.md` | Update "Implementation for Agents" section |
| `README.md` | Add multi-agent section referencing `make agent-up` |
| `CHANGELOG.md` | Phase 75 entry |
