<!--
title: "Datadog / Dynatrace Capacity Runbook"
audience: oncall, sre
last_reviewed: 2026-04-15
phase: 101
-->

# Datadog / Dynatrace Capacity Runbook

This runbook covers capacity saturation alerts originating from the Phase 86i
monitoring integration. It applies to both Datadog and Dynatrace deployments
that scrape the JA4proxy Prometheus `/metrics` endpoint via the Dynatrace EF2
plugin (`deploy/dynatrace/ja4proxy-extension/plugin.py`) or a Datadog
OpenMetrics check.

**Related runbook:** `docs/runbooks/infrastructure.md` covers the underlying
Prometheus alert rules in the `ja4proxy_capacity` group (`DiskWillFillIn24h`,
`RedisMemoryWillHitLimitIn1h`, `ProxyAvailabilitySLOBurn`). This runbook
focuses on the Datadog/Dynatrace side: interpreting forwarded metrics, handling
agent-side failures, and responding to capacity saturation signals surfaced
through those platforms.

---

## Prerequisites

- Datadog Agent (or Dynatrace OneAgent/ActiveGate) deployed alongside the
  JA4proxy node(s).
- The JA4proxy Prometheus metrics endpoint reachable from the agent
  (default: `http://localhost:9090/metrics`).
- For Dynatrace: the EF2 extension uploaded and configured with `metrics_url`
  and optional `api_token` (see `deploy/dynatrace/ja4proxy-extension/`).
- For Datadog: an OpenMetrics check configured in
  `conf.d/openmetrics.d/conf.yaml` pointing at the JA4proxy `/metrics`
  endpoint.
- Access to the Grafana Infrastructure & Attack dashboard
  (`http://localhost:3001/d/ja4proxy-infrastructure`) for cross-referencing.

---

## Key Metrics

The following Prometheus metrics are relevant to capacity monitoring. These are
scraped by the Dynatrace plugin or Datadog OpenMetrics check and forwarded to
the respective platform.

### Connection capacity

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `ja4proxy_active_connections` | Gauge | — | Current in-flight connections across all proxy instances |
| `ja4proxy_connections_total` | Counter | `action` | Cumulative connection count by action (allow, block, tarpit, etc.) |
| `ja4proxy_connection_duration_seconds` | Histogram | `action` | Latency distribution per action |

### Resource saturation

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `container_memory_working_set_bytes` | Gauge | `name` | Container memory usage (filter `name="redis"` or `name="proxy"`) |
| `container_cpu_usage_seconds_total` | Counter | `name` | Container CPU consumption |
| `node_filesystem_avail_bytes` | Gauge | `fstype`, `mountpoint` | Available disk space per mount |

### Scoring pipeline

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `ja4proxy_risk_score_distribution` | Histogram | — | Distribution of composite risk scores |
| `ja4proxy_dial_setting` | Gauge | — | Current dial value (0 = monitor, 100 = full enforcement) |
| `ja4proxy_config_reloads_total` | Counter | — | Config reload events |

### External service health

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `ja4proxy_abuseipdb_lookups_total` | Counter | `result` (hit/miss/error) | AbuseIPDB lookup outcomes |
| `ja4proxy_dns_enrichment_errors_total` | Counter | — | FCrDNS worker failures |

---

## Saturation Thresholds

Use these thresholds when interpreting dashboards or configuring alert monitors
in Datadog/Dynatrace.

| Utilisation | Severity | Action |
|-------------|----------|--------|
| < 60% | Normal | No action required |
| 60 - 80% | Watch | Investigate trend. Check if a sustained attack is driving growth. No page. |
| 80 - 95% | Warning | Investigate immediately. Prepare to shed load (lower dial, disable expensive signals). Open an incident ticket. |
| > 95% | Critical | Page on-call. Execute rollback procedure (see below). Engage capacity planning. |

**How to calculate utilisation for key resources:**

- **Connections:** `ja4proxy_active_connections / proxy.max_connections` (from `config/proxy.yml`)
- **Redis memory:** `container_memory_working_set_bytes{name="redis"} / container_spec_memory_limit_bytes{name="redis"}`
- **Disk:** `1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)`
- **CPU:** `rate(container_cpu_usage_seconds_total[5m])` relative to allocated CPU quota

---

## Escalation Path

1. **L1 on-call** — Acknowledge alert, run immediate checks from this runbook, apply rollback if > 95%.
2. **L2 security engineering** — If capacity pressure is attack-driven (high block rate, campaign detection firing), escalate within 15 minutes.
3. **L3 platform / SRE** — If capacity pressure is organic growth or infrastructure-related (disk, memory limits), escalate for capacity planning.

**Information to gather before escalating:**

- Screenshot or link to the Datadog/Dynatrace/Grafana dashboard at the time of alert
- Current `ja4proxy_active_connections` value and configured `max_connections`
- Current `ja4proxy_dial_setting` value
- Redis `info memory` output: `used_memory_human`, `maxmemory_human`, `maxmemory_policy`
- Whether any campaign detection alerts are also firing (`ja4proxy_attack_detection` group)
- Time window and rate of growth (is this sudden or gradual?)

---

## Alert Silence Criteria

It is safe to silence capacity alerts in the following situations:

| Scenario | Max silence duration | Conditions |
|----------|---------------------|------------|
| Planned maintenance window | Duration of window + 30 min buffer | Change ticket exists; rollback plan documented |
| Known deployment (rolling upgrade) | 30 minutes | Deployment is tracked in CI; prior upgrade completed without incident |
| Benchmark / load test | Duration of test + 15 min | Test is coordinated with the team; dial is at 0 (monitor mode) |
| Known seasonal traffic spike | 4 hours max, then re-evaluate | Historical data confirms the pattern; headroom > 20% |

**Never silence alerts** when:
- The root cause is unknown
- Redis memory is above 90% with `noeviction` policy
- Disk utilisation is above 95%
- Multiple alert groups are firing simultaneously

---

## Rollback Procedure

When capacity pressure exceeds 95%, reduce load in this order. Each step is
independent and reversible.

### Step 1: Lower the dial

```bash
# Set dial to 0 (monitor mode) — all connections are allowed, scoring still runs
docker exec redis redis-cli SET config:dial 0
# Publish reload so all instances pick it up immediately
docker exec redis redis-cli PUBLISH config:reload '{"type":"config_reload"}'
```

This is the fastest way to reduce load. At dial=0 the proxy still scores
connections but never blocks, tarpits, or rate-limits — eliminating the
overhead of those actions.

### Step 2: Disable expensive signal modules

Edit `config/proxy.yml` or send SIGHUP after changing these:

```yaml
# Disable enrichment signals that make external calls
dns_enrichment:
  enabled: false
abuseipdb:
  enabled: false
rdap_enrichment:
  enabled: false
```

Then reload:
```bash
docker exec proxy kill -HUP 1
```

### Step 3: Reduce connection backlog

If `ja4proxy_active_connections` is near `max_connections`:

```bash
# Temporarily increase max connections (hot-reloadable)
# Edit config/proxy.yml: proxy.max_connections: 2000
docker exec proxy kill -HUP 1
```

Or, if the load is attack-driven, engage HAProxy rate limiting upstream:

```bash
# Check HAProxy frontend rate
docker exec haproxy curl -s http://localhost:8404/stats\;csv | grep FRONTEND
```

### Step 4: Scale horizontally

If a single proxy instance is saturated:

```bash
docker compose up -d --scale proxy=3
```

Ensure HAProxy backend config includes all instances.

---

## Troubleshooting

### Metrics endpoint unreachable

**Symptom:** Datadog/Dynatrace shows no data for `ja4proxy_*` metrics.

**Check:**
```bash
# Is the metrics endpoint responding?
curl -s http://localhost:9090/metrics | head -5

# Is the Datadog agent running?
datadog-agent status | grep openmetrics

# Is the Dynatrace plugin loaded?
# Check Dynatrace UI > Settings > Monitoring > Extensions
```

**Fix:** Verify `metrics_url` in the agent/extension config matches the actual
endpoint. If the proxy is behind Docker networking, use the container name or
host network IP, not `localhost`.

### Stale metrics data

**Symptom:** Dashboard shows data but timestamps are old (> 2 collection intervals).

**Check:**
```bash
# Verify scrape is recent
curl -s http://localhost:9090/metrics | grep "^# HELP" | wc -l
# Should return > 0; if 0, endpoint is returning empty

# Check agent collection interval
# Datadog: conf.d/openmetrics.d/conf.yaml → min_collection_interval
# Dynatrace: extension settings → collection interval
```

**Fix:** Restart the agent if the collection loop is stuck. Verify the JA4proxy
process is running (`docker ps`). If the proxy restarted, metrics reset to zero
which can cause rate calculations to show negative values briefly.

### Datadog agent misconfigured

**Symptom:** Agent is running but `ja4proxy_*` metrics do not appear in Datadog.

**Check:**
```bash
# Verify the check is loaded
datadog-agent configcheck | grep openmetrics

# Run the check manually
datadog-agent check openmetrics
```

**Common issues:**
- `namespace` not set to `ja4proxy` in the OpenMetrics check config
- TLS endpoint requires `tls_verify: false` or a valid CA bundle
- Bearer token expired or missing for authenticated endpoints
- Metric name prefix mismatch (Datadog prefixes with `namespace.`)

### Dynatrace NaN/Inf values

**Symptom:** Dynatrace shows gaps or errors in metric charts.

The Phase 86i Dynatrace plugin (`plugin.py`) skips non-numeric values during
Prometheus text parsing. If you see gaps:

1. Check the raw `/metrics` output for `NaN` or `+Inf` values:
   ```bash
   curl -s http://localhost:9090/metrics | grep -E "NaN|Inf"
   ```
2. `+Inf` in histogram `_bucket` lines is normal (the `le="+Inf"` bucket).
3. `NaN` in gauge or counter lines indicates the proxy has a bug or the metric
   was never initialised. File an issue.

---

*Last updated: 2026-04-15, Phase 101 scaffolding*
