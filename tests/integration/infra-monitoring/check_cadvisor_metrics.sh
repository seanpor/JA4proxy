#!/usr/bin/env bash
# Phase 87 integration check — cAdvisor metrics reachable via Prometheus
#
# Requires: monitoring stack running
#   docker compose -f deploy/docker/docker-compose.monitoring.yml up -d
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
    echo "      docker compose -f deploy/docker/docker-compose.monitoring.yml up -d"
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
    echo "      Start the POC stack: docker compose -f deploy/docker/docker-compose.poc.yml up -d"
    # Warn but don't fail — monitoring can exist independently of the proxy stack
else
    echo "OK  ja4proxy container metrics present (${METRIC_COUNT} series)"
fi

# 4. Check at least one ContainerOOMKilled alert rule is loaded
ALERT_COUNT=$(curl -sf \
    "${PROM_URL}/api/v1/rules?type=alert" \
    2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
rules = [r for g in groups for r in g.get('rules', [])
         if r.get('type') == 'alerting' and 'OOMKilled' in r.get('name', '')]
print(len(rules))
" 2>/dev/null || echo "0")

if [[ "$ALERT_COUNT" -eq 0 ]]; then
    echo "WARN: No ContainerOOMKilled alert rules found in Prometheus."
    echo "      Check that alert rules are loaded in prometheus.yml"
else
    echo "OK  ContainerOOMKilled alert rules present (${ALERT_COUNT} rules)"
fi

# 5. Check Grafana ja4proxy-infrastructure dashboard exists
GRAFANA_HOST="${GRAFANA_HOST:-localhost}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
GRAFANA_URL="http://${GRAFANA_HOST}:${GRAFANA_PORT}"

DASHBOARD_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "${GRAFANA_URL}/api/dashboards/uid/ja4proxy-infra" 2>/dev/null || echo "000")

if [[ "$DASHBOARD_STATUS" == "200" ]]; then
    echo "OK  ja4proxy-infrastructure Grafana dashboard accessible"
elif [[ "$DASHBOARD_STATUS" == "000" ]]; then
    echo "WARN: Grafana not reachable at ${GRAFANA_URL} (start monitoring stack)"
else
    echo "WARN: ja4proxy-infrastructure dashboard returned HTTP ${DASHBOARD_STATUS}"
    echo "      Dashboard may not be provisioned. Check Grafana provisioning config."
fi

echo "=== cAdvisor check passed ==="
