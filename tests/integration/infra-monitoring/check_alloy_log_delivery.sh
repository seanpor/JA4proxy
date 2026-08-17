#!/usr/bin/env bash
# Phase 825 — prove logs actually ARRIVE in Loki through Alloy.
#
# WHY THIS EXISTS, AND WHY IT ASSERTS ARRIVAL
#
# Promtail is configured in YAML; Alloy uses River. The migration rewrote the
# scrape/relabel/pipeline rules that decide which logs reach Loki and how they
# are labelled. A silent translation error stops log delivery — and AN EMPTY
# LOKI IS INDISTINGUISHABLE FROM A QUIET SYSTEM. Nothing alerts on it.
#
# That is not hypothetical. Phase 825 found that prod's promtail mounted a
# config whose docker_sd_configs pointed at `docker-socket-proxy`, a service
# that does not exist in docker-compose.prod.yml — so PROD HAD BEEN SHIPPING NO
# LOGS AT ALL, undetected, for as long as that config had been in place.
#
# So "the alloy container is Up" proves nothing, and neither does "Loki
# responds". This script emits a unique marker line from a real container and
# asserts it comes back out of Loki WITH ITS LABELS INTACT.
#
# Requires: the monitoring stack and the stack whose logs are being shipped.
#   docker compose -f deploy/docker/docker-compose.monitoring.yml up -d

set -euo pipefail

LOKI_HOST="${LOKI_HOST:-localhost}"
LOKI_PORT="${LOKI_PORT:-3100}"
LOKI_URL="http://${LOKI_HOST}:${LOKI_PORT}"
ALLOY_URL="${ALLOY_URL:-http://localhost:12345}"
TIMEOUT="${ALLOY_DELIVERY_TIMEOUT:-90}"

MARKER="ALLOY-DELIVERY-PROBE-$(date +%s)-$$"
FAIL=0

echo "=== Phase 825: Alloy → Loki delivery check ==="

# 1. Alloy is running and its config loaded without error.
if ! curl -sf "${ALLOY_URL}/-/ready" >/dev/null 2>&1; then
    echo "FAIL: Alloy is not ready at ${ALLOY_URL}"
    echo "      docker compose -f deploy/docker/docker-compose.monitoring.yml up -d alloy"
    exit 1
fi
echo "OK  Alloy ready"

# 2. Loki is reachable.
if ! curl -sf "${LOKI_URL}/ready" >/dev/null 2>&1; then
    echo "FAIL: Loki is not reachable at ${LOKI_URL}"
    exit 1
fi
echo "OK  Loki reachable"

# 3. Emit a marker from a container Alloy is supposed to be watching. The
#    discovery filter matches any container whose name contains "ja4proxy".
TARGET="$(docker ps --format '{{.Names}}' | grep -m1 'ja4proxy' || true)"
if [[ -z "$TARGET" ]]; then
    echo "FAIL: no running container matching 'ja4proxy' — nothing for Alloy to discover."
    echo "      Bring up the POC stack first."
    exit 1
fi
echo "OK  emitting marker from container: ${TARGET}"
# Write to the container's stdout so it lands in the Docker log Alloy reads.
docker exec "$TARGET" sh -c "echo '$(date '+%Y-%m-%d %H:%M:%S,000') - probe - INFO - ${MARKER}' > /proc/1/fd/1" 2>/dev/null \
    || { echo "WARN: could not write to ${TARGET}'s stdout; trying logger"; \
         docker exec "$TARGET" sh -c "echo '${MARKER}'" >/dev/null 2>&1 || true; }

# 4. THE ACTUAL TEST — does it come back out of Loki?
echo "    waiting up to ${TIMEOUT}s for the marker to appear in Loki..."
found=""
deadline=$(( $(date +%s) + TIMEOUT ))
while [[ $(date +%s) -lt $deadline ]]; do
    resp=$(curl -sf -G "${LOKI_URL}/loki/api/v1/query_range" \
        --data-urlencode "query={container=~\".+\"} |= \`${MARKER}\`" \
        --data-urlencode "limit=5" 2>/dev/null || echo "")
    if [[ -n "$resp" ]] && echo "$resp" | grep -q "$MARKER"; then
        found="$resp"
        break
    fi
    sleep 3
done

if [[ -z "$found" ]]; then
    echo "FAIL: the marker never arrived in Loki within ${TIMEOUT}s."
    echo "      The log pipeline is broken. Check:"
    echo "        docker logs \$(docker ps -qf name=alloy)"
    echo "        curl ${ALLOY_URL}/metrics | grep loki_write"
    echo "      An empty Loki looks exactly like a quiet system — this is why"
    echo "      the check asserts arrival rather than container health."
    exit 1
fi
echo "OK  marker delivered to Loki"

# 5. Labels must survive the YAML → River translation. Dashboards and saved
#    queries depend on this contract; a line arriving unlabelled is still a
#    regression.
for label in container service; do
    if echo "$found" | python3 -c "
import json,sys
d=json.load(sys.stdin)
labels=set()
for s in d.get('data',{}).get('result',[]):
    labels.update(s.get('stream',{}))
sys.exit(0 if '${label}' in labels else 1)
" 2>/dev/null; then
        echo "OK  label '${label}' present"
    else
        echo "FAIL: label '${label}' missing — the relabel rules did not survive"
        echo "      translation to River. Dashboards keyed on it will break."
        FAIL=1
    fi
done

# 6. Promtail must be gone; two shippers would double-deliver.
if docker ps --format '{{.Image}}' | grep -q 'grafana/promtail'; then
    echo "FAIL: a grafana/promtail container is still running alongside Alloy."
    FAIL=1
else
    echo "OK  no promtail container running"
fi

[[ "$FAIL" -eq 0 ]] || { echo "=== Alloy delivery check FAILED ==="; exit 1; }
echo "=== Alloy delivery check passed ==="
