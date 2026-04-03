#!/usr/bin/env bash
# scripts/agent-env.sh — Generate isolated .env file for a named agent
#
# Usage: ./scripts/agent-env.sh <agent_name> [-f]
#   agent_name: gemini | claude | ollama | mistral
#   -f: overwrite existing .env.<agent_name>
#
# After generating, start the stack with:
#   docker compose --project-name ja4_<name> --env-file .env.<name> up -d
#
# Or use the Makefile shortcut:
#   make agent-up NAME=<name>

set -euo pipefail

AGENT="${1:-}"
FORCE="${2:-}"

usage() {
    echo "Usage: $0 <agent_name> [-f]"
    echo "  agent_name: gemini | claude | ollama | mistral"
    echo "  -f: overwrite existing .env.<agent_name>"
    exit 1
}

[[ -n "$AGENT" ]] || usage

case "$AGENT" in
  gemini)  IP="127.0.0.10"; CPUS="0-3"   ;;
  claude)  IP="127.0.0.11"; CPUS="4-7"   ;;
  ollama)  IP="127.0.0.12"; CPUS="8-11"  ;;
  mistral) IP="127.0.0.13"; CPUS="12-15" ;;
  *) echo "Unknown agent: $AGENT"; usage ;;
esac

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
echo "  Start:  docker compose --project-name ja4_${AGENT} --env-file $OUTFILE up -d"
echo "  Admin:  ./scripts/ja4-admin.sh --agent ${AGENT} status"
echo "  Stop:   docker compose --project-name ja4_${AGENT} --env-file $OUTFILE down"
echo "  Or use: make agent-up NAME=${AGENT}"
