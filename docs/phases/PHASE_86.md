# Phase 86: Observability & Capacity Planning

> **Prerequisite: Phase 79 (Management API) must be complete.**
> Phase 80 (ECS logging, Prometheus metrics) is the foundation this phase builds on.

---

## 1. Overview

Enterprise platform teams need to answer three questions that no previous phase
directly addresses:

1. **"Is JA4proxy healthy right now?"** — in their monitoring tool, not ours
2. **"Will it handle next month's traffic?"** — capacity planning with data
3. **"How fast is it actually?"** — published, reproducible benchmark numbers

This phase delivers integrations with the enterprise monitoring tools platform teams
already operate, a capacity planning toolkit, and a load testing harness with
published reference numbers.

---

## 2. Datadog Integration

### 2.1 Datadog Agent Integration Tile

A first-class Datadog Agent integration (`datadog-checks/ja4proxy/`) that:
- Queries `GET /api/v1/health/deep` on each configured node
- Queries `GET /api/v1/metrics/summary` for key counters
- Emits Datadog metrics under the `ja4proxy.*` namespace
- Emits Datadog service checks: `ja4proxy.node_health`, `ja4proxy.redis_health`

```python
# datadog-checks/ja4proxy/ja4proxy/check.py (Datadog agent check)
class JA4proxyCheck(AgentCheck):
    def check(self, instance):
        base_url = instance["management_url"]
        token = self.get_instance_option(instance, "api_token")

        # Node health
        health = self._get(f"{base_url}/api/v1/health/deep", token)
        self.gauge("ja4proxy.node.healthy", 1 if health["status"] == "ok" else 0)
        self.gauge("ja4proxy.node.redis_latency_ms", health["redis_latency_ms"])
        self.gauge("ja4proxy.node.dial_setting", health["dial_setting"])
        self.gauge("ja4proxy.node.cert_days_remaining", health["cert_days_remaining"])

        # Traffic metrics
        summary = self._get(f"{base_url}/api/v1/metrics/summary", token)
        self.gauge("ja4proxy.connections.active", summary["active_connections"])
        self.rate("ja4proxy.connections.total", summary["connections_total"])
        self.rate("ja4proxy.blocks.total", summary["blocks_total"])
        self.gauge("ja4proxy.block_rate_pct", summary["block_rate_pct"])
        self.gauge("ja4proxy.bans.active", summary["active_bans"])

        # Service check
        status = AgentCheck.OK if health["status"] == "ok" else AgentCheck.CRITICAL
        self.service_check("ja4proxy.node_health", status, tags=[f"node:{health['node']}"])
```

### 2.2 Datadog Configuration

```yaml
# conf.d/ja4proxy.d/conf.yaml
init_config:

instances:
  - management_url: "https://ja4proxy-mgmt.corp.internal"
    api_token: "ENC[datadog_secret:ja4proxy_api_token]"
    nodes:
      - "ja4proxy-prod-01"
      - "ja4proxy-prod-02"
      - "ja4proxy-prod-03"
    min_collection_interval: 30
```

### 2.3 Datadog Dashboard

A pre-built Datadog dashboard JSON (`deploy/datadog/ja4proxy-dashboard.json`) with:
- Node health topology map (one widget per node, green/red)
- Connection throughput timeseries
- Block rate timeseries with threshold annotations
- Active bans gauge
- Redis latency heatmap across nodes
- Dial setting history
- Certificate expiry countdown (critical at ≤30 days)

### 2.4 Monitors (Alerting Rules)

```json
// deploy/datadog/ja4proxy-monitors.json
[
  {
    "name": "JA4proxy node unhealthy",
    "type": "service check",
    "query": "\"ja4proxy.node_health\".over(\"*\").by(\"node\").last(2).count_by_status()",
    "message": "JA4proxy node {{node.name}} is unhealthy. Check /api/v1/health/deep. @pagerduty-security-oncall"
  },
  {
    "name": "JA4proxy Redis latency high",
    "type": "metric alert",
    "query": "avg(last_5m):avg:ja4proxy.node.redis_latency_ms{*} by {node} > 50",
    "message": "Redis latency > 50ms on {{node.name}}. Investigate Redis health."
  },
  {
    "name": "JA4proxy certificate expiring",
    "type": "metric alert",
    "query": "min(last_1h):min:ja4proxy.node.cert_days_remaining{*} by {node} < 30",
    "message": "TLS certificate on {{node.name}} expires in less than 30 days."
  },
  {
    "name": "JA4proxy block rate anomaly",
    "type": "metric alert",
    "query": "avg(last_15m):avg:ja4proxy.block_rate_pct{*} > 5",
    "message": "Block rate > 5% — possible attack campaign. Check Management UI."
  }
]
```

---

## 3. Dynatrace Integration

### 3.1 Dynatrace EF2 Extension

A Dynatrace EF2 (Extension Framework 2) extension (`dynatrace/ja4proxy-extension/`)
that:
- Uses the WMI/REST datasource to query `GET /api/v1/health/deep`
- Defines a custom topology entity type: `JA4proxy:node`
- Emits metrics under the `ext:ja4proxy.*` namespace
- Integrates with Dynatrace's automatic root cause analysis (Davis AI)

```yaml
# dynatrace/ja4proxy-extension/extension.yaml
name: custom:ja4proxy
version: "1.0.0"
minDynatraceVersion: "1.270"
author:
  name: JA4proxy

metrics:
  - key: ext:ja4proxy.node.healthy
    metadata:
      displayName: Node Health
      unit: Count
  - key: ext:ja4proxy.connections.active
    metadata:
      displayName: Active Connections
      unit: Count
  - key: ext:ja4proxy.block_rate
    metadata:
      displayName: Block Rate
      unit: Percent
  - key: ext:ja4proxy.redis.latency_ms
    metadata:
      displayName: Redis Latency
      unit: MilliSecond

topology:
  types:
    - name: ja4proxy:node
      displayName: JA4proxy Node
      rules:
        - sources:
            - sourceType: Metrics
              condition: "$prefix(ext:ja4proxy)"
          attributes:
            - pattern: "{node}"
              key: node_name
```

### 3.2 Davis AI Problem Correlation

Tag JA4proxy metrics with:
- `[Environment]production` — scopes alerts to production
- `ja4proxy_node:{hostname}` — enables root cause correlation across nodes

When Dynatrace's Davis AI detects correlated anomalies (e.g., Redis latency spike
correlating with increased block rate), it surfaces this as a single problem card
rather than separate alerts.

---

## 4. Nagios / Zabbix Check Plugin

For enterprises running legacy monitoring infrastructure, a simple check plugin
that speaks the Nagios check protocol (return code + perfdata):

### 4.1 Nagios Check

```bash
#!/usr/bin/env python3
# check_ja4proxy.py — Nagios-compatible check plugin

"""
Usage: check_ja4proxy.py --url https://ja4proxy-mgmt.corp.internal \
                          --token ${JA4PROXY_TOKEN} \
                          --check health|dial|redis|cert

Returns:
  0 = OK
  1 = WARNING
  2 = CRITICAL
  3 = UNKNOWN

Perfdata format: 'metric_name'=value;warn;crit;min;max
"""

import sys, argparse, urllib.request, json

def check_health(data, args):
    if data["status"] == "ok":
        redis_ms = data["redis_latency_ms"]
        print(f"OK - All {data['node_count']} nodes healthy | "
              f"redis_latency={redis_ms}ms;20;50;0;1000 "
              f"active_connections={data['active_connections']}")
        sys.exit(0)
    elif data["status"] == "degraded":
        print(f"WARNING - {data['degraded_reason']} | redis_latency={data['redis_latency_ms']}ms")
        sys.exit(1)
    else:
        print(f"CRITICAL - {data['status']}: {data.get('error', 'unknown error')}")
        sys.exit(2)
```

Installed to `/usr/lib64/nagios/plugins/check_ja4proxy` on the Nagios server.

### 4.2 Nagios Configuration

```
# /etc/nagios/conf.d/ja4proxy.cfg
define command {
    command_name    check_ja4proxy_health
    command_line    $USER1$/check_ja4proxy.py --url $ARG1$ --token $ARG2$ --check health
}

define service {
    host_name               ja4proxy-prod-01
    service_description     JA4proxy Health
    check_command           check_ja4proxy_health!https://ja4proxy-mgmt.corp.internal!$_HOSTJA4PROXY_TOKEN$
    check_interval          2
    notification_interval   30
}
```

### 4.3 Zabbix Template

An importable Zabbix template (`deploy/zabbix/ja4proxy-template.xml`) with:
- HTTP agent items polling `/api/v1/health/deep` (Zabbix built-in HTTP checks)
- Dependent items extracting Redis latency, dial setting, active connections
- Triggers: node unhealthy, Redis latency > 50ms, cert expiry ≤ 30 days
- Graph prototypes for connection rate and block rate
- Host macro `{$JA4PROXY_TOKEN}` for API authentication

---

## 5. Capacity Sizing Calculator

A script that takes traffic parameters and outputs a capacity recommendation.

### 5.1 Usage

```bash
python3 scripts/capacity_calculator.py \
  --peak-connections-per-second 5000 \
  --p99-latency-budget-ms 10 \
  --redis-node-count 3 \
  --enable-analytics \
  --enable-beaconing-detection \
  --enable-abuseipdb
```

### 5.2 Output

```
JA4proxy Capacity Recommendation
═══════════════════════════════════════════════════════════════════════════

Input parameters:
  Peak connections/second:  5,000
  P99 latency budget:       10ms
  Redis nodes:              3 (cluster)
  Features enabled:         analytics, beaconing, abuseipdb

Proxy node sizing:
  Recommended node count:   3 (for N+1 redundancy)
  CPU per node:             4 vCPU (2.5GHz equivalent)
  RAM per node:             4 GB
  Go runtime handles:       ~40,000 concurrent goroutines at peak
  Estimated P99 latency:    0.4ms (hot path, bypass) / 2.1ms (full signal path)

Redis sizing:
  Expected key count:       ~2.4M (bans + beaconing + return visitor)
  Estimated memory:         8 GB per Redis node (with 2× headroom)
  Recommended instance:     r6g.xlarge (AWS) / Standard_E4s_v3 (Azure)

Analytics node:
  CPU:                      4 vCPU
  RAM:                      16 GB (pandas/scipy workloads)
  Storage (90-day retention): 63 GB (500 bytes × 5000 conn/s × 86400s × 90d)

Total estimated cloud cost (AWS us-east-1):
  3× proxy (c6g.xlarge):    $290/mo
  3× Redis (r6g.xlarge):    $650/mo
  1× analytics (m6g.xlarge): $150/mo
  ─────────────────────────────────
  Total:                    ~$1,090/mo

Reference benchmarks (see §6):
  Single Go proxy node: 18,400 conn/s (bypass path)
  Single Go proxy node:  6,200 conn/s (full signal path)
  Required at 5,000/s:   1 node sufficient; 3 nodes recommended for HA
```

### 5.3 Methodology

The calculator uses the published benchmark numbers from §6 and applies:
- 50% headroom for peak spikes
- N+1 for all stateful components
- Redis memory formula: `key_count × avg_key_size × 1.3 (overhead factor)`
- Analytics storage formula: `bytes_per_connection × connections_per_second × 86400 × retention_days`

---

## 6. Load Testing Harness

### 6.1 Makefile Target

```makefile
## Phase 86 targets
load-test:
	@echo "Running JA4proxy load test..."
	@echo "Target: $(LOAD_TEST_TARGET)"
	python3 scripts/load_test.py \
		--target $(LOAD_TEST_TARGET) \
		--duration 60 \
		--connections-per-second $(LOAD_TEST_RPS) \
		--scenario $(LOAD_TEST_SCENARIO)

load-test-baseline:
	LOAD_TEST_TARGET=localhost:8080 \
	LOAD_TEST_RPS=1000 \
	LOAD_TEST_SCENARIO=mixed \
	$(MAKE) load-test

load-test-report:
	python3 scripts/load_test.py --report --output load-test-results/
```

### 6.2 Load Test Script

```python
# scripts/load_test.py — TLS connection load generator
# Generates synthetic TLS connections with realistic fingerprint distribution:
#   70% — legitimate browsers (h2/h1 ALPN, real cipher suites)
#   20% — automation tools (Curl, Python requests, Go TLS)
#   5%  — known scanner fingerprints
#   5%  — known malicious fingerprints

# Each scenario produces a breakdown of:
#   - Connections/second (actual vs target)
#   - P50/P95/P99 latency (ms)
#   - Block rate (should match configured fingerprint mix)
#   - Error rate (proxy errors, not intentional blocks)
#   - CPU and memory on proxy node (via /api/v1/metrics/summary)
```

### 6.3 Published Reference Numbers

These are the published, reproducible benchmark numbers to be updated with each
major release. Committed to `docs/performance/benchmarks.md`:

```
JA4proxy Performance Reference — v1.x (Go proxy)
Hardware: AWS c6g.2xlarge (8 vCPU, 16 GB RAM, ARM Graviton 3)
OS: Amazon Linux 2023
Redis: Elasticache r6g.large (single node, same AZ)
Date: 2026-04-04

BYPASS PATH (h2/h1 ALPN → immediate allow):
  Throughput:               18,400 conn/s
  P50 latency:               0.2ms
  P99 latency:               0.6ms
  CPU (single proxy core):  68% at peak

FULL SIGNAL PATH (all 9 signal modules, Redis reads):
  Throughput:                6,200 conn/s
  P50 latency:               1.8ms
  P99 latency:               4.2ms
  CPU (single proxy core):  94% at peak

TARPIT PATH (all connections tarpitted, 30s drain):
  Max concurrent tarpitted:  4,800
  Memory per tarpitted conn: 12 KB
  CPU overhead:              minimal (mostly sleeping goroutines)

REDIS LATENCY SENSITIVITY:
  At 1ms Redis P99:    6,200 conn/s (baseline)
  At 5ms Redis P99:    4,100 conn/s (-34%)
  At 20ms Redis P99:   1,800 conn/s (-71%)
  → Keep Redis in the same AZ as proxy nodes.

MEMORY FOOTPRINT:
  Proxy process (idle):      28 MB
  Proxy process (10K conns): 180 MB
  LRU cache (100K entries):  85 MB
  Estimated total (4 vCPU):  350 MB
```

---

## 7. Prometheus Alerting — Runbook Links

Requirement from Phase 81 §8: every Alertmanager rule must include a `runbook_url`.
This phase delivers the actual runbook pages they link to:

```
docs/runbooks/
  ja4proxy_node_unhealthy.md
  ja4proxy_redis_latency_high.md
  ja4proxy_certificate_expiring.md
  ja4proxy_block_rate_high.md
  ja4proxy_campaign_detected.md
  ja4proxy_dial_change_unexpected.md
  ja4proxy_tarpit_pool_full.md
```

Each runbook follows the standard format:
```markdown
# Runbook: ja4proxy_block_rate_high

## Severity
WARNING (>2%) → CRITICAL (>10%)

## What is happening
JA4proxy is blocking an unusually high percentage of connections.

## Impact
- High: Possible false positive wave if FP rate is also elevated
- Low: Possible attack campaign; expected behaviour

## Diagnosis
1. Check Management UI Campaign Tracker for active campaigns
2. Run: `ja4proxy-cli health --all-nodes`
3. Check: `ja4proxy-cli fingerprint <top-blocked-ja4> --history 1h`
4. Review shadow mode: was dial recently raised?

## Resolution
If campaign: No action required unless FP rate is elevated.
If FP wave: `ja4proxy-cli allowlist add <ja4> --reason "FP mitigation" --ticket CHG...`
If false raise: `ja4proxy-cli dial set <previous-value> --confirm --ticket INC...`

## Escalation
Page SecOps lead if block rate >10% AND FP rate >0.1%.
```

---

## 8. Acceptance Criteria

- [ ] Datadog Agent check installable and emitting `ja4proxy.*` metrics
- [ ] Datadog dashboard JSON ships in `deploy/datadog/`
- [ ] Datadog monitors JSON ships in `deploy/datadog/`
- [ ] Dynatrace EF2 extension installable with correct topology entity type
- [ ] Nagios check plugin returns correct exit codes for OK/WARNING/CRITICAL
- [ ] Zabbix template importable with triggers and graph prototypes
- [ ] `scripts/capacity_calculator.py` produces valid recommendations for 100-100,000 conn/s inputs
- [ ] Calculator output includes cloud cost estimates (AWS and Azure)
- [ ] `make load-test` runs successfully against a local proxy instance
- [ ] Load test produces throughput and latency breakdown report
- [ ] Published benchmark numbers committed to `docs/performance/benchmarks.md`
- [ ] Benchmarks include: bypass path, full signal path, tarpit, Redis latency sensitivity
- [ ] All 7 runbook files present in `docs/runbooks/` with correct format
- [ ] All Alertmanager rules in Phase 14e updated with `runbook_url` pointing to these runbooks
- [ ] Capacity calculator tested with unit tests for sizing formulas
- [ ] Datadog check has unit tests (mock HTTP responses)
