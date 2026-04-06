#!/usr/bin/env bash
# scripts/agent-env.sh — Generate isolated .env file for a named agent
#
# Usage: ./scripts/agent-env.sh <agent_name> [-f]
#   agent_name: any name — well-known names get fixed IPs/CPUs,
#               custom names get auto-assigned IPs from 127.0.0.20+
#   -f: overwrite existing .env.<agent_name>
#
# Well-known agents (fixed IP + CPU partition on i9-9900K):
#   gemini  → 127.0.0.10, cpus 0-3
#   claude  → 127.0.0.11, cpus 4-7
#   ollama  → 127.0.0.12, cpus 8-11
#   mistral → 127.0.0.13, cpus 12-15
#
# Custom agents (e.g. claude0, claude1, myagent):
#   IP auto-assigned from 127.0.0.20 upward — checks both .env.* files and
#   currently-bound host ports (via ss) to avoid collisions even if env files
#   were deleted or two agents are started in parallel.
#   cpuset unrestricted (0-15) — pin manually if needed
#
# After generating, start the stack with:
#   make agent-up NAME=<name>

set -euo pipefail

AGENT="${1:-}"
FORCE="${2:-}"

usage() {
    echo "Usage: $0 <agent_name> [-f]"
    echo "  agent_name: any identifier (gemini|claude|ollama|mistral get fixed IPs)"
    echo "  -f: overwrite existing .env.<agent_name>"
    exit 1
}

[[ -n "$AGENT" ]] || usage

OUTFILE=".env.${AGENT}"
LOCKFILE="/tmp/ja4proxy-agent-env.lock"

# ── Fast-path: fail before acquiring any lock ─────────────────────────────────

if [[ -f "$OUTFILE" && "$FORCE" != "-f" ]]; then
    echo "✗ $OUTFILE already exists. Use -f to overwrite." >&2
    exit 1
fi

# ── Resolve IP and CPU set ────────────────────────────────────────────────────

case "$AGENT" in
  gemini)  IP="127.0.0.10"; CPUS="0-3"   ;;
  claude)  IP="127.0.0.11"; CPUS="4-7"   ;;
  ollama)  IP="127.0.0.12"; CPUS="8-11"  ;;
  mistral) IP="127.0.0.13"; CPUS="12-15" ;;
  *)
    CPUS="0-15"
    echo "  Note: custom agent — assigning IP from pool, cpuset unrestricted (0-15)" >&2
    echo "  To pin CPUs, edit AGENT_CPU_SET in .env.${AGENT} after generation." >&2
    echo "" >&2

    # Acquire an exclusive lock so two simultaneous agent-up calls cannot race
    # to pick the same IP.  The lock is held until this script exits (fd 9 closes).
    exec 9>"$LOCKFILE"
    flock -x 9

    # Re-check inside the lock — a concurrent caller may have just written a file
    if [[ -f "$OUTFILE" && "$FORCE" != "-f" ]]; then
        echo "✗ $OUTFILE already exists. Use -f to overwrite." >&2
        exit 1
    fi

    # Assign the lowest free IP in 127.0.0.20-254.
    # Sources checked:
    #   1. Existing .env.* files (handles env files that outlive their stacks)
    #   2. Host-bound loopback ports via `ss` (handles running stacks whose env
    #      files were deleted, and the race window before any file is written)
    IP=$(python3 - <<'PYEOF'
import glob, re, subprocess, sys
used = set()

# Source 1 — env files
for f in glob.glob('.env.*'):
    try:
        m = re.search(r'^AGENT_BIND_IP=(\S+)', open(f).read(), re.MULTILINE)
        if m:
            used.add(m.group(1))
    except OSError:
        pass

# Source 2 — host-bound loopback IPs (ss -tlnp)
try:
    out = subprocess.check_output(['ss', '-tlnp'], text=True, timeout=5)
    for line in out.splitlines():
        m = re.search(r'127\.0\.0\.(\d+):', line)
        if m:
            used.add(f'127.0.0.{m.group(1)}')
except Exception:
    pass  # ss unavailable — fall back to env-file scan only

for i in range(20, 255):
    candidate = f'127.0.0.{i}'
    if candidate not in used:
        print(candidate)
        sys.exit(0)
print('ERROR: no free IPs in 127.0.0.20-254', file=sys.stderr)
sys.exit(1)
PYEOF
    )
    echo "  Assigned IP: ${IP}" >&2
    ;;
esac

# ── Write env file ────────────────────────────────────────────────────────────
# For well-known agents the existence check already happened above.
# For custom agents this write is still inside the flock (fd 9 is still open).

cat > "$OUTFILE" <<EOF
# ── Agent identity ───────────────────────────────────────────────────────────
COMPOSE_PROJECT_NAME=ja4_${AGENT}
AGENT_BIND_IP=${IP}
AGENT_CPU_SET=${CPUS}

# ── Host port assignments ────────────────────────────────────────────────────
HOST_PORT_INGRESS=443
HOST_PORT_ANALYTICS=8080
HOST_PORT_ADMIN_API=8091
HOST_PORT_MANAGEMENT=8090

# ── Secrets (auto-generated) ─────────────────────────────────────────────────
REDIS_PASSWORD=$(openssl rand -hex 32)
GRAFANA_PASSWORD=$(openssl rand -hex 16)

# ── Backend ──────────────────────────────────────────────────────────────────
BACKEND_HOST=backend
BACKEND_PORT=443

# ── Environment ──────────────────────────────────────────────────────────────
ENVIRONMENT=development
LOG_LEVEL=INFO
EOF

chmod 600 "$OUTFILE"
echo "✓ Created $OUTFILE (agent=${AGENT}, ip=${IP}, cpus=${CPUS})"
echo ""
echo "  Start:  make agent-up NAME=${AGENT}"
echo "  Admin:  ./scripts/ja4-admin.sh --agent ${AGENT} status"
echo "  Stop:   make agent-down NAME=${AGENT}"
