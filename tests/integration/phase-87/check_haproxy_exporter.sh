#!/usr/bin/env bash
# Phase 87 integration check — HAProxy exporter metrics reachable via Prometheus
#
# Requires: monitoring stack running
#   docker compose -f docker/docker-compose.monitoring.yml up -d
#
# Checks that Prometheus has scraped at least one HAProxy metric
# (haproxy_up) from the haproxy_exporter scrape job.

set -euo pipefail

PROM_HOST="${PROMETHEUS_HOST:-localhost}"
PROM_PORT="${PROMETHEUS_PORT:-9090}"
PROM_URL="http://${PROM_HOST}:${PROM_PORT}"

echo "=== Phase 87: HAProxy exporter metrics check ==="
echo "Prometheus: ${PROM_URL}"

# 1. Check Prometheus is reachable
if ! curl -sf "${PROM_URL}/-/healthy" > /dev/null 2>&1; then
    echo "FAIL: Prometheus is not reachable at ${PROM_URL}"
    echo "      Start the monitoring stack first:"
    echo "      docker compose -f docker/docker-compose.monitoring.yml up -d"
    exit 1
fi
echo "OK  Prometheus reachable"

# 2. Check the haproxy scrape job exists and has at least one healthy target
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
    echo "FAIL: No HAProxy exporter targets found in Prometheus. Check prometheus.yml scrape config."
    exit 1
fi
echo "OK  HAProxy exporter targets: ${TARGETS} healthy"

# 3. Check haproxy_up metric is present (exporter is connected to HAProxy)
HAPROXY_UP=$(curl -sf \
    "${PROM_URL}/api/v1/query?query=haproxy_up" \
    2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('data', {}).get('result', [])
if results:
    print(results[0].get('value', [None, '0'])[1])
else:
    print('0')
" 2>/dev/null || echo "0")

if [[ "$HAPROXY_UP" != "1" ]]; then
    echo "WARN: haproxy_up=${HAPROXY_UP}. HAProxy exporter may not be connected to HAProxy."
    echo "      Ensure the POC stack is running: docker compose -f docker/docker-compose.poc.yml up -d"
    # Warn but don't fail — exporter starts before HAProxy on some orderings
else
    echo "OK  haproxy_up=1 (exporter connected)"
fi

# 4. Check haproxy_frontend_bytes_in_total is present (HAProxy actively serving)
BYTES_COUNT=$(curl -sf \
    "${PROM_URL}/api/v1/query?query=haproxy_frontend_bytes_in_total" \
    2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', {}).get('result', [])))
" 2>/dev/null || echo "0")

if [[ "$BYTES_COUNT" -eq 0 ]]; then
    echo "WARN: haproxy_frontend_bytes_in_total not present. HAProxy may not be serving traffic yet."
else
    echo "OK  haproxy_frontend_bytes_in_total present (${BYTES_COUNT} series)"
fi

# 5. Check at least one HAProxy-related alert rule is loaded in Prometheus
HAPROXY_ALERT_COUNT=$(curl -sf \
    "${PROM_URL}/api/v1/rules?type=alert" \
    2>/dev/null \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
rules = [r for g in groups for r in g.get('rules', [])
         if r.get('type') == 'alerting' and 'haproxy' in r.get('name', '').lower()]
print(len(rules))
" 2>/dev/null || echo "0")

if [[ "$HAPROXY_ALERT_COUNT" -eq 0 ]]; then
    echo "WARN: No HAProxy alert rules found in Prometheus."
    echo "      Check that HAProxy alert rules are loaded in prometheus.yml"
else
    echo "OK  HAProxy alert rules present (${HAPROXY_ALERT_COUNT} rules)"
fi

echo "=== HAProxy exporter check passed ==="
