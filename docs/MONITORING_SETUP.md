# Prometheus & Grafana Alerting Setup Guide for JA4proxy

Complete step-by-step guide to set up monitoring, alerting, and dashboards for JA4proxy security events.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Prometheus Setup](#prometheus-setup)
4. [Alertmanager Setup](#alertmanager-setup)
5. [Grafana Setup](#grafana-setup)
6. [Testing Alerts](#testing-alerts)
7. [Alert Integrations](#alert-integrations)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Deploy monitoring stack
cd /home/sean/LLM/JA4proxy
docker compose -f docker-compose.monitoring.yml up -d

# 2. Access services
# Prometheus: http://localhost:9091
# Alertmanager: http://localhost:9093
# Grafana: http://localhost:3001 (admin/admin)

# 3. Import dashboard
# Navigate to Grafana → Dashboards → Import
# Upload: monitoring/grafana/dashboards/ja4proxy-overview.json

# 4. Test alerts
./test-ja4-blocking.sh
```

---

## Prerequisites

### Required Services
- ✅ Docker & Docker Compose
- ✅ JA4proxy running (./start-poc.sh)
- ✅ Metrics endpoint accessible (port 9090)

### Required Files
```
monitoring/
├── prometheus/
│   ├── prometheus.yml          # Main config
│   ├── alerts.yml             # Alert rules
│   └── recording_rules.yml    # Pre-computed metrics
├── alertmanager/
│   └── alertmanager.yml       # Alert routing
└── grafana/
    └── dashboards/
        └── ja4proxy-overview.json  # Dashboard
```

---

## Prometheus Setup

### Step 1: Create Prometheus Configuration

The configuration files are already created in `monitoring/prometheus/`.

**Key files:**
- `prometheus.yml` - Main configuration
- `alerts.yml` - 15+ alert rules
- `recording_rules.yml` - Performance optimizations

### Step 2: Create Docker Compose for Monitoring

Create `docker-compose.monitoring.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: ja4proxy-prometheus-monitoring
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--web.enable-lifecycle'
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./monitoring/prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro
      - ./monitoring/prometheus/recording_rules.yml:/etc/prometheus/recording_rules.yml:ro
      - prometheus-data:/prometheus
    restart: unless-stopped
    networks:
      - ja4proxy-network

  alertmanager:
    image: prom/alertmanager:latest
    container_name: ja4proxy-alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    ports:
      - "9093:9093"
    volumes:
      - ./monitoring/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager-data:/alertmanager
    restart: unless-stopped
    networks:
      - ja4proxy-network

  grafana:
    image: grafana/grafana:latest
    container_name: ja4proxy-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL=http://localhost:3001
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    restart: unless-stopped
    networks:
      - ja4proxy-network

volumes:
  prometheus-data:
  alertmanager-data:
  grafana-data:

networks:
  ja4proxy-network:
    external: true
```

### Step 3: Deploy Prometheus

```bash
# Create network if it doesn't exist
docker network create ja4proxy-network 2>/dev/null || true

# Start monitoring stack
docker compose -f docker-compose.monitoring.yml up -d

# Verify Prometheus is running
curl http://localhost:9091/-/healthy
# Expected: Prometheus is Healthy.

# Check targets
curl http://localhost:9091/api/v1/targets
```

### Step 4: Verify Alert Rules

```bash
# Check if alert rules are loaded
curl http://localhost:9091/api/v1/rules | jq '.data.groups[].name'

# Expected output:
# "ja4proxy_security_alerts"
# "ja4proxy_operational_alerts"
# "ja4proxy_business_alerts"

# Check specific alert
curl http://localhost:9091/api/v1/rules | jq '.data.groups[].rules[] | select(.name=="JA4ProxyMaliciousFingerprint")'
```

### Step 5: Test Prometheus Queries

Open http://localhost:9091 and test these queries:

```promql
# Current request rate
rate(ja4_requests_total[5m])

# Block percentage
(rate(ja4_blocked_requests_total[5m]) / rate(ja4_requests_total[5m])) * 100

# Active security events
sum by (tier) (rate(ja4_security_events_total[5m]))

# Top blocked fingerprints
topk(10, sum by (ja4_fingerprint) (increase(ja4_blocked_requests_total[1h])))
```

---

## Alertmanager Setup

### Step 1: Configure Notification Channels

Edit `monitoring/alertmanager/alertmanager.yml`:

**For Email Alerts:**
```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@yourdomain.com'
  smtp_auth_username: 'alerts@yourdomain.com'
  smtp_auth_password: 'your-app-password'
```

**For Slack Alerts:**
```yaml
receivers:
  - name: 'security-team'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#security-alerts'
```

**For PagerDuty:**
```yaml
receivers:
  - name: 'oncall-pager'
    pagerduty_configs:
      - service_key: 'YOUR-PAGERDUTY-INTEGRATION-KEY'
```

### Step 2: Test Alertmanager

```bash
# Check Alertmanager is running
curl http://localhost:9093/-/healthy

# View current configuration
curl http://localhost:9093/api/v1/status

# Send test alert
curl -H "Content-Type: application/json" -d '[{
  "labels": {
    "alertname": "TestAlert",
    "severity": "warning"
  },
  "annotations": {
    "summary": "This is a test alert"
  }
}]' http://localhost:9093/api/v1/alerts
```

### Step 3: View Active Alerts

```bash
# List all active alerts
curl http://localhost:9093/api/v1/alerts | jq '.data[]'

# View in browser
open http://localhost:9093
```

---

## Grafana Setup

### Step 1: Access Grafana

```bash
# Open Grafana
open http://localhost:3001

# Default credentials:
# Username: admin
# Password: admin
# (you'll be prompted to change on first login)
```

### Step 2: Add Prometheus Data Source

1. Navigate to **Configuration** → **Data Sources**
2. Click **Add data source**
3. Select **Prometheus**
4. Configure:
   - **Name:** JA4proxy Prometheus
   - **URL:** http://prometheus:9090
   - **Access:** Server (default)
5. Click **Save & Test**

### Step 3: Import JA4proxy Dashboard

**Method 1: Via UI**
1. Navigate to **Dashboards** → **Import**
2. Click **Upload JSON file**
3. Select `monitoring/grafana/dashboards/ja4proxy-overview.json`
4. Select **JA4proxy Prometheus** as data source
5. Click **Import**

**Method 2: Via API**
```bash
# Get Grafana API key (Settings → API Keys)
API_KEY="your-api-key"

# Import dashboard
curl -X POST http://localhost:3001/api/dashboards/db \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @monitoring/grafana/dashboards/ja4proxy-overview.json
```

**Method 3: Auto-provisioning**
```bash
# Create provisioning config
cat > monitoring/grafana/provisioning/dashboards/ja4proxy.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'JA4proxy'
    orgId: 1
    folder: 'Security'
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

# Restart Grafana
docker compose -f docker-compose.monitoring.yml restart grafana
```

### Step 4: Configure Grafana Alerts

1. Open the imported dashboard
2. For each panel with alerts:
   - Click panel title → **Edit**
   - Go to **Alert** tab
   - Configure notification channels
   - Set evaluation interval
   - Click **Save**

### Step 5: Create Notification Channels

**Email Notification:**
1. **Alerting** → **Notification channels** → **New channel**
2. **Type:** Email
3. **Addresses:** security@example.com
4. **Test** → **Save**

**Slack Notification:**
1. **Alerting** → **Notification channels** → **New channel**
2. **Type:** Slack
3. **Webhook URL:** (your Slack webhook)
4. **Channel:** #security-alerts
5. **Test** → **Save**

---

## Testing Alerts

### Test 1: Trigger Malicious Fingerprint Alert

```bash
# Run security test to trigger bans
./test-ja4-blocking.sh

# Wait 1-2 minutes for alert to fire

# Check Prometheus for firing alerts
curl http://localhost:9091/api/v1/alerts | jq '.data.alerts[] | select(.state=="firing")'

# Check Alertmanager
curl http://localhost:9093/api/v1/alerts | jq '.data[] | select(.status.state=="active")'
```

### Test 2: Trigger High Block Rate Alert

```bash
# Simulate high traffic with blocks
for i in {1..100}; do
  docker exec ja4proxy-redis redis-cli -a changeme \
    INCR "ja4:blocked_requests_total"
  sleep 0.1
done

# Alert should fire in 2-3 minutes
```

### Test 3: Trigger Rate Limit Alert

```bash
# Add many rate limit violations
IP="192.168.1.250"
for i in {1..20}; do
  docker exec ja4proxy-redis redis-cli -a changeme \
    ZADD "rate:by_ip:$IP:1s" "$(date +%s).$i" "conn_$i"
done

# Check if alert is firing
curl http://localhost:9091/api/v1/alerts | \
  jq '.data.alerts[] | select(.labels.alertname=="JA4ProxyRateLimitViolations")'
```

### Test 4: Simulate Service Down

```bash
# Stop JA4proxy
docker compose -f docker-compose.poc.yml stop proxy

# Wait 1 minute
sleep 60

# Check alerts
curl http://localhost:9091/api/v1/alerts | \
  jq '.data.alerts[] | select(.labels.alertname=="JA4ProxyServiceDown")'

# Restart service
docker compose -f docker-compose.poc.yml start proxy
```

---

## Alert Integrations

### Slack Integration

**Step 1: Create Slack Webhook**
1. Go to https://api.slack.com/apps
2. Create new app → **From scratch**
3. Add **Incoming Webhooks** feature
4. Create webhook for channel (e.g., #security-alerts)
5. Copy webhook URL

**Step 2: Configure Alertmanager**
```yaml
receivers:
  - name: 'security-team'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK'
        channel: '#security-alerts'
        username: 'JA4proxy Alerts'
        icon_emoji: ':rotating_light:'
        title: 'Security Alert: {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *Summary:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Severity:* {{ .Labels.severity }}
          {{ end }}
        send_resolved: true
```

### Email Integration (Gmail)

```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@gmail.com'
  smtp_auth_username: 'alerts@gmail.com'
  smtp_auth_password: 'your-app-password'  # Generate in Google Account settings
  smtp_require_tls: true

receivers:
  - name: 'email-alerts'
    email_configs:
      - to: 'security-team@example.com'
        headers:
          Subject: '[{{ .Status | toUpper }}] JA4proxy: {{ .GroupLabels.alertname }}'
        html: |
          <h2>JA4proxy Alert</h2>
          {{ range .Alerts }}
          <h3>{{ .Annotations.summary }}</h3>
          <p>{{ .Annotations.description }}</p>
          <p><strong>Severity:</strong> {{ .Labels.severity }}</p>
          <p><strong>Time:</strong> {{ .StartsAt }}</p>
          {{ end }}
```

### PagerDuty Integration

```yaml
receivers:
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR-INTEGRATION-KEY'
        description: '{{ .CommonAnnotations.summary }}'
        client: 'JA4proxy Alertmanager'
        client_url: 'http://localhost:3001'
        details:
          alert_count: '{{ .Alerts | len }}'
          firing: '{{ .Alerts.Firing | len }}'
          description: '{{ .CommonAnnotations.description }}'
        severity: '{{ .CommonLabels.severity }}'
```

### Webhook Integration (Custom SIEM)

```yaml
receivers:
  - name: 'siem'
    webhook_configs:
      - url: 'https://siem.example.com/api/alerts'
        send_resolved: true
        http_config:
          basic_auth:
            username: 'ja4proxy'
            password: 'your-password'
          tls_config:
            insecure_skip_verify: false
```

---

## Dashboard Panels Explained

### Panel 1: Security Overview
- **Metrics:** Request rate, block rate, list sizes
- **Use:** Quick health check
- **Alert on:** Unusual spikes

### Panel 2: Request Rate
- **Shows:** Total and blocked requests over time
- **Use:** Identify attack patterns
- **Alert on:** Sustained high block rate

### Panel 3: Block Rate %
- **Shows:** Percentage of blocked requests
- **Alert:** Fires if > 10% for 5 minutes
- **Use:** Detect ongoing attacks

### Panel 4: Security Events by Tier
- **Shows:** Distribution of suspicious/block/ban events
- **Use:** Understand threat severity
- **Normal:** Mostly suspicious, few bans

### Panel 5: Top Blocked Fingerprints
- **Shows:** Most frequently blocked JA4 fingerprints
- **Use:** Identify persistent attackers
- **Action:** Add to permanent blacklist

### Panel 6: Rate Limit Violations
- **Shows:** Rate limits exceeded by strategy
- **Use:** Fine-tune thresholds
- **Alert on:** Sudden spikes

### Panel 7: Whitelist/Blacklist Hits
- **Shows:** How often lists are matched
- **Use:** Validate list effectiveness
- **Green:** Whitelist allowing good traffic
- **Red:** Blacklist blocking bad traffic

### Panel 8: Active Connections
- **Shows:** Current active connections
- **Use:** Capacity planning
- **Alert on:** Approaching limits

### Panel 9: Request Latency
- **Shows:** p95 and p99 latency
- **Use:** Performance monitoring
- **Alert on:** Degradation

### Panel 10: Recent Security Events
- **Shows:** Live log stream of security events
- **Use:** Real-time monitoring
- **Filter:** SECURITY, BLOCK, BAN keywords

---

## Troubleshooting

### Issue: Alerts Not Firing

**Check 1: Verify metric exists**
```bash
curl http://localhost:9091/api/v1/query?query=ja4_blocked_requests_total
```

**Check 2: Verify alert rule syntax**
```bash
curl http://localhost:9091/api/v1/rules | jq '.data.groups[].rules[] | select(.health!="ok")'
```

**Check 3: Check alert evaluation**
```bash
curl http://localhost:9091/api/v1/alerts | jq '.data.alerts[] | select(.state=="pending" or .state=="firing")'
```

**Check 4: Verify Alertmanager connection**
```bash
curl http://localhost:9091/api/v1/alertmanagers
```

### Issue: Dashboard Panels Empty

**Check 1: Verify data source**
- Grafana → Configuration → Data Sources
- Test connection to Prometheus

**Check 2: Check metric names**
```bash
# List all metrics
curl http://localhost:9091/api/v1/label/__name__/values | jq '.data[]' | grep ja4
```

**Check 3: Verify time range**
- Dashboard time picker → Last 1 hour

### Issue: Notifications Not Sending

**Check 1: Alertmanager logs**
```bash
docker logs ja4proxy-alertmanager
```

**Check 2: Test receiver**
```bash
# Send test notification
amtool alert add --alertmanager.url=http://localhost:9093 \
  alertname=test severity=warning summary="Test alert"
```

**Check 3: Check routing**
```bash
curl http://localhost:9093/api/v1/status | jq '.data.config.route'
```

### Issue: High Memory Usage

**Solution 1: Reduce retention**
```yaml
# In prometheus.yml
storage:
  tsdb:
    retention.time: 15d  # Reduce from 30d
    retention.size: 5GB  # Reduce from 10GB
```

**Solution 2: Add resource limits**
```yaml
services:
  prometheus:
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
```

---

## Advanced Configuration

### Custom Alert Templates

Create `/etc/alertmanager/templates/custom.tmpl`:

```go
{{ define "slack.ja4proxy.title" }}
[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .GroupLabels.alertname }}
{{ end }}

{{ define "slack.ja4proxy.text" }}
{{ range .Alerts }}
*Alert:* {{ .Annotations.summary }}
*Description:* {{ .Annotations.description }}
*Severity:* {{ .Labels.severity }}
*Time:* {{ .StartsAt.Format "2006-01-02 15:04:05" }}
{{ if .Annotations.dashboard }}*Dashboard:* {{ .Annotations.dashboard }}{{ end }}
{{ if .Annotations.runbook }}*Runbook:* {{ .Annotations.runbook }}{{ end }}
{{ end }}
{{ end }}
```

### Silence Alerts

```bash
# Silence all alerts for maintenance
amtool silence add --alertmanager.url=http://localhost:9093 \
  alertname=~ '.*' \
  --duration=1h \
  --author="ops@example.com" \
  --comment="Maintenance window"

# Silence specific alert
amtool silence add --alertmanager.url=http://localhost:9093 \
  alertname=JA4ProxyHighBlockRate \
  --duration=30m \
  --comment="Expected high traffic"
```

### Query Performance Optimization

Use recording rules for expensive queries:

```yaml
# In recording_rules.yml
- record: ja4:blocked:percentage_5m
  expr: |
    (
      rate(ja4_blocked_requests_total[5m])
      /
      rate(ja4_requests_total[5m])
    ) * 100

# Use in alerts
- alert: HighBlockRate
  expr: ja4:blocked:percentage_5m > 10
```

---

## Next Steps

1. **Customize Thresholds:** Adjust alert thresholds based on your traffic
2. **Add Dashboards:** Create custom dashboards for your needs
3. **Integrate SIEM:** Forward alerts to your SIEM system
4. **Document Runbooks:** Create response procedures for each alert
5. **Test Regularly:** Run `./test-ja4-blocking.sh` weekly

---

## Quick Reference

**Prometheus:** http://localhost:9091  
**Alertmanager:** http://localhost:9093  
**Grafana:** http://localhost:3001

**Start Stack:**
```bash
docker compose -f docker-compose.monitoring.yml up -d
```

**View Logs:**
```bash
docker logs -f ja4proxy-prometheus-monitoring
docker logs -f ja4proxy-alertmanager
docker logs -f ja4proxy-grafana
```

**Reload Configs:**
```bash
# Prometheus (hot reload)
curl -X POST http://localhost:9091/-/reload

# Alertmanager (hot reload)
curl -X POST http://localhost:9093/-/reload

# Grafana (restart required)
docker compose -f docker-compose.monitoring.yml restart grafana
```

---

**Setup Complete!** 🎉

Your JA4proxy now has enterprise-grade monitoring and alerting.
