#!/bin/bash
echo "=========================================="
echo "JA4 Proxy Metrics Viewer"
echo "=========================================="
echo

echo "1. DIRECT PROXY METRICS (Port 9090):"
echo "--------------------------------------"
curl -s http://localhost:9090/metrics | grep -E "^ja4_" | grep -v "^#" | while read line; do
    metric=$(echo "$line" | cut -d'{' -f1 | cut -d' ' -f1)
    value=$(echo "$line" | awk '{print $NF}')
    if [[ "$value" != "0.0" ]] && [[ "$value" != "0" ]]; then
        echo "  $line"
    fi
done

echo
echo "2. PROMETHEUS QUERIES:"
echo "--------------------------------------"
echo "Active Connections:"
curl -s 'http://localhost:9091/api/v1/query?query=ja4_active_connections' | python3 -c "import sys,json; d=json.load(sys.stdin); print('  Value:', d['data']['result'][0]['value'][1] if d['data']['result'] else 'No data')" 2>/dev/null || echo "  Error querying"

echo
echo "Security Events:"
curl -s 'http://localhost:9091/api/v1/query?query=ja4_security_events_total' | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f\"  {r['metric']['event_type']}: {r['value'][1]}\") for r in d['data']['result']]" 2>/dev/null || echo "  No events"

echo
echo "3. ALL AVAILABLE JA4 METRICS IN PROMETHEUS:"
echo "--------------------------------------"
curl -s 'http://localhost:9091/api/v1/label/__name__/values' | python3 -c "import sys,json; [print(f\"  {m}\") for m in sorted(json.load(sys.stdin)['data']) if 'ja4' in m.lower()]" 2>/dev/null

echo
echo "4. PROMETHEUS TARGETS STATUS:"
echo "--------------------------------------"
curl -s http://localhost:9091/api/v1/targets | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f\"  {t['labels']['job']:30} {t['health']:10} {t.get('lastError', 'OK')[:60]}\") for t in d['data']['activeTargets']]" 2>/dev/null

echo
echo "=========================================="
echo "Access Points:"
echo "  Prometheus UI:  http://localhost:9091"
echo "  Grafana:        http://localhost:3001"
echo "  Proxy Metrics:  http://localhost:9090/metrics"
echo "=========================================="
