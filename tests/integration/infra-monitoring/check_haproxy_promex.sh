#!/usr/bin/env bash
# Phase 820 integration check — HAProxy native Prometheus exporter
#
# Requires: monitoring stack running
#   docker compose -f deploy/docker/docker-compose.monitoring.yml up -d
#
# Replaces the Phase 87 check against prom/haproxy-exporter, which Phase 820
# deleted in favour of HAProxy 2.8's built-in exporter (USE_PROMEX=1).
#
# This check does more than confirm the target is up. Phase 820 found that all
# four HAProxy alert rules had NEVER been able to fire: they filter on `proxy=`,
# which is the native exporter's label, while the sidecar only ever emitted
# `frontend=`/`backend=`. Nothing detected that for months because the old check
# only asserted `haproxy_up=1`. So this script asserts that every metric the
# alerts and dashboards actually depend on returns a non-empty result — i.e.
# that the rules can match real series.

set -euo pipefail

PROM_HOST="${PROMETHEUS_HOST:-localhost}"
PROM_PORT="${PROMETHEUS_PORT:-9091}"
PROM_URL="http://${PROM_HOST}:${PROM_PORT}"

# Backend/frontend names from config/haproxy.cfg — the label VALUES the alert
# rules select on. If these are renamed there, the alerts go dead again.
BACKEND="ja4proxy_workers"
FRONTEND="tls_in"

echo "=== Phase 820: HAProxy native promex check ==="
echo "Prometheus: ${PROM_URL}"

query_count() {
    curl -sf "${PROM_URL}/api/v1/query" --data-urlencode "query=$1" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    print(len(json.load(sys.stdin).get('data', {}).get('result', [])))
except Exception:
    print(0)
" 2>/dev/null || echo "0"
}

# 1. Prometheus reachable
if ! curl -sf "${PROM_URL}/-/healthy" > /dev/null 2>&1; then
    echo "FAIL: Prometheus is not reachable at ${PROM_URL}"
    echo "      docker compose -f deploy/docker/docker-compose.monitoring.yml up -d"
    exit 1
fi
echo "OK  Prometheus reachable"

# 2. The haproxy scrape job has a healthy target (now haproxy:8404, not the sidecar)
TARGETS=$(curl -sf "${PROM_URL}/api/v1/targets" 2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
haproxy = [t for t in data.get('data', {}).get('activeTargets', [])
           if t.get('labels', {}).get('job') == 'haproxy']
healthy = [t for t in haproxy if t.get('health') == 'up']
print(f'{len(healthy)}/{len(haproxy)}')
" 2>/dev/null || echo "0/0")

if [[ "$TARGETS" == "0/0" ]]; then
    echo "FAIL: No 'haproxy' scrape target in Prometheus. Check prometheus.yml."
    exit 1
fi
if [[ "${TARGETS%%/*}" -eq 0 ]]; then
    echo "FAIL: 'haproxy' target present but unhealthy (${TARGETS})."
    echo "      Is haproxy:8404/metrics serving? Needs 'http-request use-service"
    echo "      prometheus-exporter' in config/haproxy.cfg."
    exit 1
fi
echo "OK  haproxy scrape target healthy: ${TARGETS}"

# 3. THE REAL CHECK — every selector the alerts and dashboards depend on must
#    return series. A zero here means a rule is silently dead.
FAIL=0
declare -a CHECKS=(
    "haproxy_backend_current_queue{proxy=\"${BACKEND}\"}|HAProxyBackendQueueing"
    "haproxy_server_status{proxy=\"${BACKEND}\",state=\"UP\"}|HAProxyBackendDown"
    "haproxy_server_connection_errors_total{proxy=\"${BACKEND}\"}|HAProxyConnectionErrorRate"
    "haproxy_frontend_current_sessions{proxy=\"${FRONTEND}\"}|HAProxySessionLimitApproaching"
    "haproxy_frontend_limit_sessions{proxy=\"${FRONTEND}\"}|HAProxySessionLimitApproaching"
    "haproxy_frontend_connections_total{proxy=\"${FRONTEND}\"}|infrastructure dashboard"
)

for entry in "${CHECKS[@]}"; do
    expr="${entry%%|*}"
    consumer="${entry##*|}"
    n=$(query_count "$expr")
    if [[ "$n" -eq 0 ]]; then
        echo "FAIL: no series for ${expr}"
        echo "      -> ${consumer} cannot fire/render. Check the proxy= label value"
        echo "         matches a frontend/backend name in config/haproxy.cfg."
        FAIL=1
    else
        echo "OK  ${consumer}: ${n} series for ${expr}"
    fi
done

# 4. haproxy_server_status must be the multi-state form. If a future HAProxy
#    emits a single series, the state="UP" selector silently stops matching.
STATES=$(query_count "count by (state) (haproxy_server_status{proxy=\"${BACKEND}\"})")
if [[ "$STATES" -lt 2 ]]; then
    echo "FAIL: haproxy_server_status has ${STATES} state(s); expected the"
    echo "      multi-state form (UP/DOWN/MAINT/DRAIN/NOLB)."
    FAIL=1
else
    echo "OK  haproxy_server_status is multi-state (${STATES} states)"
fi

# 5. The retired sidecar must be gone.
if [[ "$(query_count 'haproxy_up')" -ne 0 ]]; then
    echo "FAIL: haproxy_up is present — that metric is emitted only by the"
    echo "      retired prom/haproxy-exporter sidecar. Is it still running?"
    FAIL=1
else
    echo "OK  prom/haproxy-exporter is gone (no haproxy_up series)"
fi

# 6. HAProxy alert rules loaded
ALERTS=$(curl -sf "${PROM_URL}/api/v1/rules?type=alert" 2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
print(len([r for g in groups for r in g.get('rules', [])
           if r.get('type') == 'alerting' and 'haproxy' in r.get('name', '').lower()]))
" 2>/dev/null || echo "0")

if [[ "$ALERTS" -eq 0 ]]; then
    echo "FAIL: No HAProxy alert rules loaded in Prometheus."
    FAIL=1
else
    echo "OK  HAProxy alert rules loaded (${ALERTS} rules)"
fi

[[ "$FAIL" -eq 0 ]] || { echo "=== HAProxy promex check FAILED ==="; exit 1; }
echo "=== HAProxy promex check passed ==="
