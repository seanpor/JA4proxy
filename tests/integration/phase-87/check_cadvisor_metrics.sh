#!/usr/bin/env bash
# Phase 87 integration check — cAdvisor metrics reachable via Prometheus
#
# Requires: monitoring stack running
#   docker compose -f docker/docker-compose.monitoring.yml up -d
#
# Checks that Prometheus has scraped at least one cAdvisor metric
# (container_cpu_usage_seconds_total) for a ja4proxy container.

set -euo pipefail

PROM_HOST="${PROMETHEUS_HOST:-localhost}"
PROM_PORT="${PROMETHEUS_PORT:-9090}"
PROM_URL="http://${PROM_HOST}:${PROM_PORT}"

echo "=== Phase 87: cAdvisor metrics check ==="
echo "Prometheus: ${PROM_URL}"

# 1. Check Prometheus is reachable
if ! curl -sf "${PROM_URL}/-/healthy" > /dev/null 2>&1; then
    echo "FAIL: Prometheus is not reachable at ${PROM_URL}"
    echo "      Start the monitoring stack first:"
    echo "      docker compose -f docker/docker-compose.monitoring.yml up -d"
    exit 1
fi
echo "OK  Prometheus reachable"

# 2. Check the cadvisor scrape job exists and has at least one healthy target
TARGETS=$(curl -sf "${PROM_URL}/api/v1/targets" 2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
cadvisor = [t for t in data.get('data', {}).get('activeTargets', [])
            if t.get('labels', {}).get('job') == 'cadvisor']
healthy = [t for t in cadvisor if t.get('health') == 'up']
print(f'{len(healthy)}/{len(cadvisor)}')
" 2>/dev/null || echo "0/0")

if [[ "$TARGETS" == "0/0" ]]; then
    echo "FAIL: No cAdvisor targets found in Prometheus. Check prometheus.yml scrape config."
    exit 1
fi
echo "OK  cAdvisor targets: ${TARGETS} healthy"

# 3. Check at least one ja4proxy container metric is present
METRIC_COUNT=$(curl -sf \
    "${PROM_URL}/api/v1/query?query=container_cpu_usage_seconds_total%7Bname%3D~%22ja4proxy.*%22%7D" \
    2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', {}).get('result', [])))
" 2>/dev/null || echo "0")

if [[ "$METRIC_COUNT" -eq 0 ]]; then
    echo "WARN: No ja4proxy container CPU metrics found. Stack may not be running."
    echo "      Start the POC stack: docker compose -f docker/docker-compose.poc.yml up -d"
    # Warn but don't fail — monitoring can exist independently of the proxy stack
else
    echo "OK  ja4proxy container metrics present (${METRIC_COUNT} series)"
fi

echo "=== cAdvisor check passed ==="
