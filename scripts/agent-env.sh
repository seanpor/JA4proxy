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
#   IP auto-assigned from 127.0.0.20 upward (first not in use by any .env.*)
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

# ── Resolve IP and CPU set ────────────────────────────────────────────────────

case "$AGENT" in
  gemini)  IP="127.0.0.10"; CPUS="0-3"   ;;
  claude)  IP="127.0.0.11"; CPUS="4-7"   ;;
  ollama)  IP="127.0.0.12"; CPUS="8-11"  ;;
  mistral) IP="127.0.0.13"; CPUS="12-15" ;;
  *)
    # Auto-assign: find the lowest IP in 127.0.0.20-254 not already in a .env.* file
    IP=$(python3 - <<'PYEOF'
import glob, re, sys
used = set()
for f in glob.glob('.env.*'):
    try:
        m = re.search(r'^AGENT_BIND_IP=(\S+)', open(f).read(), re.MULTILINE)
        if m:
            used.add(m.group(1))
    except OSError:
        pass
for i in range(20, 255):
    candidate = f'127.0.0.{i}'
    if candidate not in used:
        print(candidate)
        sys.exit(0)
print('ERROR: no free IPs in 127.0.0.20-254', file=sys.stderr)
sys.exit(1)
PYEOF
    )
    CPUS="0-15"
    echo "  Note: custom agent — assigned IP ${IP}, cpuset unrestricted (0-15)" >&2
    echo "  To pin CPUs, edit AGENT_CPU_SET in .env.${AGENT} after generation." >&2
    echo "" >&2
    ;;
esac

# ── Write env file ────────────────────────────────────────────────────────────

OUTFILE=".env.${AGENT}"

if [[ -f "$OUTFILE" && "$FORCE" != "-f" ]]; then
    echo "✗ $OUTFILE already exists. Use -f to overwrite." >&2
    exit 1
fi

cat > "$OUTFILE" <<EOF
# ── Agent identity ───────────────────────────────────────────────────────────
COMPOSE_PROJECT_NAME=ja4_${AGENT}
AGENT_BIND_IP=${IP}
AGENT_CPU_SET=${CPUS}

# ── Host port assignments ────────────────────────────────────────────────────
HOST_PORT_INGRESS=443
HOST_PORT_ANALYTICS=8080

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
