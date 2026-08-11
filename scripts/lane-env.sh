#!/usr/bin/env bash
# lane-env.sh — assign this git worktree a collision-free "lane" of host ports
# and a unique compose project name, persisted into .env (phase-310 / phase-161).
#
# Each lane gets its own docker network/containers/volumes (via the unique
# COMPOSE_PROJECT_NAME), so INTERNAL service ports never collide. Only the few
# HOST-PUBLISHED ports we actually reach from outside are lane-offset:
#   port = base + lane*100   (lane 0 = the historical defaults)
#
# Flags (phase-161):
#   --list       — JSON output of all detected lanes on the host
#   --preview N  — show port map for lane N without allocating
#
# Idempotent: once .env pins JA4_LANE, this is a no-op (stable across restarts).
# Run `JA4_LANE_REASSIGN=1 scripts/lane-env.sh` to force re-derivation.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"
ENV_FILE=".env"
LANE_COUNT=40

# Published ports we expose per lane: VAR=base
declare -A BASE=(
  [HOST_PORT_DIRECT]=8081      # proxy listener / load-test target
  [HOST_PORT_METRICS]=9090     # proxy /metrics
  [HOST_PORT_GRAFANA]=3000     # Grafana UI
  [HOST_PORT_MANAGEMENT]=8090  # Management API
  [HOST_PORT_PROMETHEUS]=9091  # Prometheus UI
  # phase-800: alertmanager was missing here while
  # docker-compose.monitoring.yml published
  # "${AGENT_BIND_IP}:${HOST_PORT_ALERTMANAGER:-9093}:9093". With no lane value
  # set, every lane fell back to the same default 9093 and collided on the host
  # — one of two reasons the monitoring stack could not run in two lanes at
  # once (the other being hardcoded container_name: entries in that compose).
  [HOST_PORT_ALERTMANAGER]=9093 # Alertmanager UI
)
MANAGED_KEYS=(JA4_LANE COMPOSE_PROJECT_NAME "${!BASE[@]}")

# --- flags (phase-161) --------------------------------------------------------
if [ "${1:-}" = "--list" ]; then
  echo '{'
  echo '  "lanes": ['
  first=true
  for f in .env*; do
    [ -f "$f" ] || continue
    lane=$(grep -E '^JA4_LANE=' "$f" 2>/dev/null | tail -1 | cut -d= -f2 || true)
    [ -n "$lane" ] || continue
    name=$(grep -E '^JA4_LANE_NAME=' "$f" 2>/dev/null | tail -1 | cut -d= -f2 || echo "lane-$lane")
    proj=$(grep -E '^COMPOSE_PROJECT_NAME=' "$f" 2>/dev/null | tail -1 | cut -d= -f2 || echo "ja4proxy-lane$lane")
    $first || echo ','
    first=false
    printf '    {"number":%s,"name":"%s","path":"%s","project":"%s"}' "$lane" "$name" "$(realpath "$f")" "$proj"
  done
  echo
  echo '  ]'
  echo '}'
  exit 0
fi

if [ "${1:-}" = "--preview" ]; then
  lane="${2:-0}"
  echo "Lane $lane port preview:"
  for v in "${!BASE[@]}"; do
    printf "  %s=%d\n" "$v" $(( BASE[$v] + lane*100 ))
  done
  exit 0
fi

port_free() { ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
lane_ports_free() { local L=$1 v; for v in "${!BASE[@]}"; do port_free $(( BASE[$v] + L*100 )) || return 1; done; }

# --- determine the lane -------------------------------------------------------
existing_lane=""
[ -f "$ENV_FILE" ] && existing_lane=$(grep -E '^JA4_LANE=' "$ENV_FILE" | tail -1 | cut -d= -f2 || true)

if [ -n "$existing_lane" ] && [ "${JA4_LANE_REASSIGN:-0}" != "1" ]; then
  LANE="$existing_lane"                       # already pinned — stable, no probing
else
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  start=$(( $(printf '%s' "$root" | cksum | cut -d' ' -f1) % LANE_COUNT ))
  LANE=""
  for i in $(seq 0 $((LANE_COUNT-1))); do
    cand=$(( (start + i) % LANE_COUNT ))
    if lane_ports_free "$cand"; then LANE="$cand"; break; fi
  done
  [ -n "$LANE" ] || { echo "lane-env: all $LANE_COUNT lanes' ports are busy" >&2; exit 1; }
fi

# --- compute the map ----------------------------------------------------------
PROJECT="ja4proxy-lane${LANE}"
declare -A PORT
for v in "${!BASE[@]}"; do PORT[$v]=$(( BASE[$v] + LANE*100 )); done

# --- upsert into .env (preserve everything else, e.g. secrets) ----------------
[ -f "$ENV_FILE" ] || { umask 077; : > "$ENV_FILE"; }
tmp="$(mktemp)"
# drop the keys we manage, keep the rest verbatim
grep -vE "^($(IFS='|'; echo "${MANAGED_KEYS[*]}"))=" "$ENV_FILE" > "$tmp" || true
{
  echo "# --- lane allocation (phase-310, managed by scripts/lane-env.sh) ---"
  echo "JA4_LANE=${LANE}"
  echo "COMPOSE_PROJECT_NAME=${PROJECT}"
  for v in HOST_PORT_DIRECT HOST_PORT_METRICS HOST_PORT_GRAFANA HOST_PORT_MANAGEMENT HOST_PORT_PROMETHEUS; do
    echo "${v}=${PORT[$v]}"
  done
} >> "$tmp"
chmod 600 "$tmp"; mv "$tmp" "$ENV_FILE"

# --- report -------------------------------------------------------------------
BIND="${AGENT_BIND_IP:-127.0.0.1}"
cat <<EOF
Lane ${LANE}  (project ${PROJECT})
  proxy (direct)  ${BIND}:${PORT[HOST_PORT_DIRECT]}
  proxy /metrics  ${BIND}:${PORT[HOST_PORT_METRICS]}
  Grafana         http://${BIND}:${PORT[HOST_PORT_GRAFANA]}
  Management API  http://${BIND}:${PORT[HOST_PORT_MANAGEMENT]}
  Prometheus      http://${BIND}:${PORT[HOST_PORT_PROMETHEUS]}
EOF
