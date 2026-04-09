# Phase 86: Observability Upgrade & Capacity Planning

**Status:** PROPOSED

> **Prerequisites:**
> - Phase 41 (Robust Health Check API — `GET /api/v1/health/deep`) must be complete.
> - Phase 63 (SLOs, recording rules, `slo_overview.json` dashboard) must be complete.
> - Phase 79 (Management API v2, API tokens for bearer auth) must be complete.
> - Phase 80 (ECS logging, Prometheus metrics foundation) must be complete.
> - Phase 87 (Container & Host Infrastructure Observability, `ja4proxy-infrastructure.json`) must be complete.

---

## 1. Overview

Enterprise platform teams need to answer three questions that no previous phase
directly addresses:

1. **"Is JA4proxy healthy right now?"** — in their monitoring tool, not ours
2. **"Will it handle next month's traffic?"** — capacity planning with real data
3. **"How fast is it actually?"** — published, reproducible benchmark numbers

This phase delivers:

- Integrations with Datadog, Dynatrace, Nagios, and Zabbix
- A Grafana capacity planning dashboard (`04_capacity.json`)
- A load-testing harness with defined scenarios and a committed benchmark record
- A capacity sizing calculator wired to real benchmark measurements
- Seven operational runbooks covering the most actionable alerts
- Cleanup of all ~30 fake `runbook_url` placeholder values across alert rule files

**Size assessment:** This phase is **medium-large**. It is broken into three
independently-completable sub-phases below: 86a (integrations), 86b (load testing
and Grafana), and 86c (calculator, runbooks, and alert cleanup). Each sub-phase has
its own acceptance criteria and can be implemented and reviewed independently.
86c has a data dependency on 86b (benchmark numbers must exist before the
calculator constants are set).

---

## 2. Sub-Phase Summary

| Sub-phase | Scope | Status | Depends on |
|-----------|-------|--------|-----------|
| 86a | External monitoring integrations (Datadog, Dynatrace, Nagios, Zabbix) | PROPOSED | — |
| 86b | Load test harness, benchmark run, Grafana capacity dashboard | PROPOSED | — |
| 86c | Capacity calculator, runbooks, alert rule URL cleanup | PROPOSED | 86b (benchmark numbers) |

---

## 86a: External Monitoring Integrations

**Status:** PROPOSED

**Goal:** Ship first-class integrations for the four monitoring stacks most common
in enterprise environments. Platform teams should be able to drop the integration
artifact into their tooling and immediately see JA4proxy health without manual
configuration work.

### Design Principle: Prometheus-First

**Every numeric metric already exists in Prometheus.** The right architecture for
Datadog and Dynatrace is:

1. **Scrape `/metrics` directly** — Datadog's built-in OpenMetrics check and
   Dynatrace's OneAgent Prometheus scraping both do this natively, with zero custom
   code. This preserves full label richness (`action`, `bypass`, `signal` labels)
   that a management-API poll would lose.
2. **Use a custom check only for what Prometheus cannot express** — topology entity
   creation, multi-node service check roll-ups, and Alertmanager-style severity
   escalation require a thin custom layer on top.

Do not poll `/api/v1/metrics/summary` for numeric metrics. That endpoint is a
human-facing summary; continuous machine polling at 30-second intervals adds
unnecessary load and misses per-label breakdowns.

---

### 86a.1 Datadog Integration

#### Layer 1 — OpenMetrics Check (numeric metrics)

Configure Datadog's built-in OpenMetrics check to scrape the existing Prometheus
endpoint. No custom Python required for this layer.

```yaml
# conf.d/openmetrics.d/ja4proxy.yaml
init_config:

instances:
  # One instance per proxy node. Tag with node hostname.
  - openmetrics_endpoint: "http://ja4proxy-prod-01:9090/metrics"
    namespace: "ja4proxy"
    metrics:
      - ja4proxy_connections_total
      - ja4proxy_bypass_total
      - ja4proxy_pipeline_duration_seconds
      - ja4proxy_risk_score
      - ja4proxy_dial_current
      - ja4proxy_dial_changes_total
      - ja4proxy_tarpit_concurrent
      - ja4proxy_tarpit_overflow_total
      - ja4proxy_blocklist_entries
      - ja4proxy_blocklist_last_refresh_success_seconds
      - ja4proxy_blocklist_matches_total
      - ja4proxy_abuseipdb_quota_exhausted
      - ja4proxy_abuseipdb_cache_hit_ratio
      - ja4proxy_analytics_stream_lag_seconds
      - ja4proxy_analytics_score_drift_detected
    tags:
      - "node:ja4proxy-prod-01"
      - "env:production"
    min_collection_interval: 30
    send_histograms_buckets: true
    send_distribution_buckets: true
    type_overrides:
      ja4proxy_pipeline_duration_seconds: "histogram"
      ja4proxy_risk_score: "histogram"
```

Add one instance block per proxy node. The `namespace: "ja4proxy"` prefix maps
Prometheus names to Datadog metric names — `ja4proxy_connections_total` becomes
`ja4proxy.connections.total` in Datadog automatically.

#### Layer 2 — Custom Check (topology + service checks)

The custom check does only what the OpenMetrics check cannot: create a topology
entity per node, emit Datadog service checks (`OK`/`WARNING`/`CRITICAL`), and
compute derived gauges (e.g., cert days remaining) from the deep health endpoint.

```python
# datadog-checks/ja4proxy/ja4proxy/check.py
import json
import urllib.request
from datadog_checks.base import AgentCheck

class JA4proxyCheck(AgentCheck):
    """
    Thin custom check — topology and service checks only.
    Numeric metrics are scraped by the OpenMetrics check (Layer 1).
    One instance per proxy node in conf.d/ja4proxy.d/conf.yaml.
    """

    def check(self, instance: dict) -> None:
        base_url = instance["management_url"]
        token    = instance["api_token"]
        node     = instance.get("node_name", base_url)
        tags     = [f"node:{node}"] + instance.get("tags", [])

        health = self._get_json(f"{base_url}/api/v1/health/deep", token)
        if not health:
            self.service_check(
                "ja4proxy.node_health",
                AgentCheck.UNKNOWN,
                tags=tags,
                message=f"Could not reach management API at {base_url}",
            )
            return

        # Service check (topology)
        if health.get("status") == "ok":
            sc_status = AgentCheck.OK
        elif health.get("status") == "degraded":
            sc_status = AgentCheck.WARNING
        else:
            sc_status = AgentCheck.CRITICAL

        self.service_check("ja4proxy.node_health", sc_status, tags=tags)
        self.service_check(
            "ja4proxy.redis_health",
            AgentCheck.OK if health["components"]["redis"]["status"] == "healthy" else AgentCheck.CRITICAL,
            tags=tags,
        )

        # Derived gauges not available in Prometheus
        redis_comp = health["components"]["redis"]
        self.gauge("ja4proxy.redis.latency_ms", redis_comp.get("latency_ms", 0), tags=tags)
        self.gauge("ja4proxy.cert.days_remaining", health.get("cert_days_remaining", 0), tags=tags)
        self.gauge("ja4proxy.node.dial_current", health.get("dial", 0), tags=tags)

    def _get_json(self, url: str, token: str) -> dict:
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            self.warning(f"JA4proxy API call failed [{url}]: {e}")
            return {}
```

One `instance` entry per node (not a `nodes` list under one instance — per-node
instances are the Datadog pattern for correct per-node tagging):

```yaml
# conf.d/ja4proxy.d/conf.yaml
init_config:

instances:
  - management_url: "https://ja4proxy-prod-01:8090"
    api_token: "ENC[datadog_secret:ja4proxy_api_token]"
    node_name: "ja4proxy-prod-01"
    tags: ["env:production", "region:eu-west-1"]

  - management_url: "https://ja4proxy-prod-02:8090"
    api_token: "ENC[datadog_secret:ja4proxy_api_token]"
    node_name: "ja4proxy-prod-02"
    tags: ["env:production", "region:eu-west-1"]
```

#### Datadog Dashboard

A pre-built dashboard JSON (`deploy/datadog/ja4proxy-dashboard.json`) with:
- Node health topology map (one service check widget per node, green/amber/red)
- Connection throughput timeseries (`ja4proxy.connections.total` rate)
- Block rate by action (stacked: `block`, `ban`, `tarpit`)
- Active bans gauge (`ja4proxy.bans.active`)
- Redis latency heatmap across nodes (`ja4proxy.redis.latency_ms` by `node`)
- Dial history step chart (`ja4proxy.node.dial_current`)
- Certificate expiry countdown — critical at ≤30 days
- Score drift indicator (`ja4proxy.analytics.score_drift_detected`)

#### Datadog Monitors

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
    "query": "avg(last_5m):avg:ja4proxy.redis.latency_ms{*} by {node} > 50",
    "message": "Redis latency > 50ms on {{node.name}}. Investigate Redis health."
  },
  {
    "name": "JA4proxy certificate expiring soon",
    "type": "metric alert",
    "query": "min(last_1h):min:ja4proxy.cert.days_remaining{*} by {node} < 30",
    "message": "TLS certificate on {{node.name}} expires in less than 30 days."
  },
  {
    "name": "JA4proxy block rate anomaly",
    "type": "metric alert",
    "query": "avg(last_15m):avg:ja4proxy.connections.total{action:block} > 5",
    "message": "Block rate elevated — possible attack campaign. Check Management UI."
  }
]
```

---

### 86a.2 Dynatrace EF2 Extension

A Dynatrace Extension Framework 2 (EF2) extension (`dynatrace/ja4proxy-extension/`)
that uses the Python remote execution model to query the Prometheus endpoint and
report metrics with a custom topology entity type.

```yaml
# dynatrace/ja4proxy-extension/extension.yaml
name: custom:ja4proxy
version: "1.0.0"
minDynatraceVersion: "1.270"
author:
  name: JA4proxy

# Datasource: Python remote extension module
python:
  runtime: python
  activation:
    remote:
      path: "extension.py"

# Metric declarations for Dynatrace metric ingest
metrics:
  - key: ext:ja4proxy.connections.total
    metadata:
      displayName: Connections Total
      unit: Count
      description: "Total connections by action label"
  - key: ext:ja4proxy.dial.current
    metadata:
      displayName: Dial Setting
      unit: Count
      description: "Current dial value (0-100)"
  - key: ext:ja4proxy.block_rate
    metadata:
      displayName: Block Rate (%)
      unit: Percent
  - key: ext:ja4proxy.redis.latency_ms
    metadata:
      displayName: Redis Latency
      unit: MilliSecond
  - key: ext:ja4proxy.pipeline.p99_ms
    metadata:
      displayName: Pipeline P99 Latency
      unit: MilliSecond
  - key: ext:ja4proxy.score_drift_detected
    metadata:
      displayName: Score Drift Detected
      unit: Count
      description: "1 if score drift detected, else 0"

# Topology: one JA4proxy:node entity per proxy instance
topology:
  types:
    - name: ja4proxy:node
      displayName: JA4proxy Node
      rules:
        - sources:
            - sourceType: Metrics
              # Select metrics produced by this extension
          attributes:
            - key: node_name
              displayName: Node Name
              pattern: "{node}"

# Activation schema: user-visible config fields in Dynatrace UI
activationSchema:
  types:
    ja4proxy:node:
      displayName: JA4proxy Configuration
      properties:
        prometheus_url:
          displayName: Prometheus Metrics URL
          type: url
          default: "http://localhost:9090/metrics"
        management_url:
          displayName: Management API URL
          type: url
          default: "http://localhost:8090"
        api_token:
          displayName: Management API Token
          type: secret
```

```python
# dynatrace/ja4proxy-extension/extension.py
"""
JA4proxy Dynatrace EF2 remote Python extension.
Scrapes the Prometheus /metrics endpoint and forwards key metrics to Dynatrace.
Runs one instance per configured JA4proxy node.
"""
import urllib.request
from dynatrace_extension import Extension, ExtensionRemotePlugin

class JA4proxyExtension(Extension):
    def query(self) -> None:
        config = self.activation_config
        prom_url = config.get("prometheus_url", "http://localhost:9090/metrics")
        node = config.get("node_name", "unknown")

        raw = self._scrape(prom_url)
        if not raw:
            return

        metrics = self._parse_prometheus(raw)
        dim = {"node": node}

        self.report_metric("ext:ja4proxy.dial.current",
                           metrics.get("ja4proxy_dial_current", 0), dim)
        self.report_metric("ext:ja4proxy.score_drift_detected",
                           metrics.get("ja4proxy_analytics_score_drift_detected", 0), dim)

        # Block rate = blocks / (blocks + allows) over last scrape delta
        blocks  = metrics.get("ja4proxy_connections_total{action=block}", 0)
        allows  = metrics.get("ja4proxy_connections_total{action=allow}", 0)
        total   = blocks + allows
        self.report_metric("ext:ja4proxy.block_rate",
                           (blocks / total * 100) if total > 0 else 0, dim)

    def _scrape(self, url: str) -> str:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return r.read().decode()
        except Exception as e:
            self.logger.warning(f"Prometheus scrape failed [{url}]: {e}")
            return ""

    def _parse_prometheus(self, text: str) -> dict:
        """Minimal line-by-line parser for prometheus text format."""
        result = {}
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                result[parts[0]] = float(parts[1])
        return result
```

#### Davis AI Problem Correlation

Tag JA4proxy metrics with:
- `dt.entity.ja4proxy:node` — enables entity-level correlation
- `[Environment]production` — scopes Davis AI problem cards to production

When Davis AI detects correlated anomalies (e.g., Redis latency spike correlating
with increased block rate), it surfaces them as a single problem card rather than
separate alerts.

---

### 86a.3 Nagios / Zabbix Check Plugin

For enterprises running legacy monitoring infrastructure.

#### Nagios Check Plugin — Complete Implementation

```python
#!/usr/bin/env python3
# check_ja4proxy.py — Nagios-compatible check plugin
"""
Usage:
  check_ja4proxy.py --url URL --token TOKEN --check MODE [options]

Modes:
  health  Overall node health (default)
  dial    Current dial value vs. expected range
  redis   Redis latency check
  cert    TLS certificate expiry check

Returns:
  0 = OK
  1 = WARNING
  2 = CRITICAL
  3 = UNKNOWN (API unreachable or unexpected response)

Perfdata format: 'metric_name'=value;warn;crit;min;max
"""

import sys
import argparse
import urllib.request
import urllib.error
import json
from typing import Optional


def get_json(url: str, token: str, timeout: int = 10) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"UNKNOWN - Cannot reach management API: {e.reason}")
        sys.exit(3)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"UNKNOWN - Malformed response from management API: {e}")
        sys.exit(3)
    except Exception as e:
        print(f"UNKNOWN - Unexpected error: {e}")
        sys.exit(3)


def check_health(data: dict) -> None:
    status = data.get("status", "unknown")
    node_count = data.get("node_count", 1)
    redis_ms   = data.get("components", {}).get("redis", {}).get("latency_ms", 0)
    active     = data.get("active_connections", 0)
    perfdata   = (f"redis_latency={redis_ms}ms;20;50;0;1000 "
                  f"active_connections={active};;")
    if status == "ok":
        print(f"OK - All {node_count} nodes healthy | {perfdata}")
        sys.exit(0)
    elif status == "degraded":
        reason = data.get("degraded_reason", "component degraded")
        print(f"WARNING - {reason} | {perfdata}")
        sys.exit(1)
    else:
        error = data.get("error", status)
        print(f"CRITICAL - {error} | {perfdata}")
        sys.exit(2)


def check_dial(data: dict, args: argparse.Namespace) -> None:
    dial = data.get("dial", -1)
    if dial < 0:
        print("UNKNOWN - dial value missing from health response")
        sys.exit(3)
    perfdata = f"dial={dial};{args.warn};{args.crit};0;100"
    if dial >= args.crit:
        print(f"CRITICAL - Dial at {dial} (threshold {args.crit}) | {perfdata}")
        sys.exit(2)
    elif dial >= args.warn:
        print(f"WARNING - Dial at {dial} (threshold {args.warn}) | {perfdata}")
        sys.exit(1)
    else:
        print(f"OK - Dial at {dial} | {perfdata}")
        sys.exit(0)


def check_redis(data: dict, args: argparse.Namespace) -> None:
    redis_ms = data.get("components", {}).get("redis", {}).get("latency_ms")
    if redis_ms is None:
        print("UNKNOWN - redis latency missing from health response")
        sys.exit(3)
    perfdata = f"redis_latency={redis_ms}ms;{args.warn};{args.crit};0;5000"
    if redis_ms >= args.crit:
        print(f"CRITICAL - Redis latency {redis_ms}ms | {perfdata}")
        sys.exit(2)
    elif redis_ms >= args.warn:
        print(f"WARNING - Redis latency {redis_ms}ms | {perfdata}")
        sys.exit(1)
    else:
        print(f"OK - Redis latency {redis_ms}ms | {perfdata}")
        sys.exit(0)


def check_cert(data: dict, args: argparse.Namespace) -> None:
    days = data.get("cert_days_remaining")
    if days is None:
        print("UNKNOWN - cert_days_remaining missing from health response")
        sys.exit(3)
    perfdata = f"cert_days_remaining={days}d;{args.warn};{args.crit};0;"
    if days <= args.crit:
        print(f"CRITICAL - Certificate expires in {days} days | {perfdata}")
        sys.exit(2)
    elif days <= args.warn:
        print(f"WARNING - Certificate expires in {days} days | {perfdata}")
        sys.exit(1)
    else:
        print(f"OK - Certificate valid for {days} days | {perfdata}")
        sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Nagios check for JA4proxy")
    parser.add_argument("--url",   required=True,  help="Management API base URL")
    parser.add_argument("--token", required=True,  help="Bearer token")
    parser.add_argument("--check", default="health",
                        choices=["health", "dial", "redis", "cert"])
    parser.add_argument("--warn",  type=int, default=20,
                        help="Warning threshold (ms for redis; days for cert; dial value)")
    parser.add_argument("--crit",  type=int, default=50,
                        help="Critical threshold (same units as --warn)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout in seconds")
    args = parser.parse_args()

    data = get_json(f"{args.url}/api/v1/health/deep", args.token, args.timeout)

    dispatch = {
        "health": check_health,
        "dial":   check_dial,
        "redis":  check_redis,
        "cert":   check_cert,
    }
    dispatch[args.check](data, args)


if __name__ == "__main__":
    main()
```

Installed to `/usr/lib64/nagios/plugins/check_ja4proxy` on the Nagios server.

#### Nagios Configuration

```
# /etc/nagios/conf.d/ja4proxy.cfg
define command {
    command_name    check_ja4proxy_health
    command_line    $USER1$/check_ja4proxy.py --url $ARG1$ --token $ARG2$ --check health
}
define command {
    command_name    check_ja4proxy_redis
    command_line    $USER1$/check_ja4proxy.py --url $ARG1$ --token $ARG2$ --check redis --warn 20 --crit 50
}
define command {
    command_name    check_ja4proxy_cert
    command_line    $USER1$/check_ja4proxy.py --url $ARG1$ --token $ARG2$ --check cert --warn 60 --crit 30
}
define command {
    command_name    check_ja4proxy_dial
    command_line    $USER1$/check_ja4proxy.py --url $ARG1$ --token $ARG2$ --check dial --warn 70 --crit 90
}

define service {
    host_name               ja4proxy-prod-01
    service_description     JA4proxy Health
    check_command           check_ja4proxy_health!https://ja4proxy-mgmt.corp.internal!$_HOSTJA4PROXY_TOKEN$
    check_interval          2
    notification_interval   30
}
define service {
    host_name               ja4proxy-prod-01
    service_description     JA4proxy Certificate Expiry
    check_command           check_ja4proxy_cert!https://ja4proxy-mgmt.corp.internal!$_HOSTJA4PROXY_TOKEN$
    check_interval          60
    notification_interval   1440
}
```

#### Zabbix Template

An importable Zabbix template (`deploy/zabbix/ja4proxy-template.xml`) with:
- HTTP agent items polling `/api/v1/health/deep` every 60s (Zabbix built-in HTTP checks)
- Dependent items extracting: Redis latency, dial value, active connections,
  cert days remaining, status string
- Triggers:
  - `ja4proxy_node_unhealthy` — `status != "ok"` for 2m → HIGH
  - `ja4proxy_redis_latency_high` — Redis latency > 50ms for 5m → WARNING
  - `ja4proxy_cert_expiring` — cert days remaining < 30 → WARNING; < 7 → HIGH
  - `ja4proxy_dial_critical` — dial > 90 → INFO (informational, not an incident)
- Graph prototypes for connection rate and block rate (sourced from Prometheus via
  Zabbix Prometheus agent items on the `/metrics` endpoint)
- Host macro `{$JA4PROXY_TOKEN}` for API bearer authentication
- Host macro `{$JA4PROXY_METRICS_URL}` for Prometheus endpoint

---

### 86a Acceptance Criteria

- [ ] Datadog OpenMetrics check config (`conf.d/openmetrics.d/ja4proxy.yaml`) scrapes `/metrics`; all `ja4proxy_*` metrics visible in Datadog
- [ ] Datadog custom check (`datadog-checks/ja4proxy/`) emits only topology + derived gauges; does not duplicate OpenMetrics metrics
- [ ] Datadog check: one instance per node (not a nodes list)
- [ ] Datadog check: UNKNOWN service check emitted when management API is unreachable
- [ ] Datadog dashboard JSON ships in `deploy/datadog/ja4proxy-dashboard.json`
- [ ] Datadog monitors JSON ships in `deploy/datadog/ja4proxy-monitors.json`
- [ ] Dynatrace EF2 `extension.yaml` passes `dt ext validate` (valid datasource, metrics, topology, activationSchema)
- [ ] Dynatrace `extension.py` correctly parses Prometheus text format and reports metrics
- [ ] Nagios check plugin returns correct exit codes: 0 (OK), 1 (WARNING), 2 (CRITICAL), 3 (UNKNOWN)
- [ ] Nagios check plugin handles unreachable management API with exit 3, not exit 2
- [ ] Nagios check implements all four modes: `health`, `dial`, `redis`, `cert`
- [ ] Zabbix template importable; all triggers and graph prototypes present
- [ ] Zabbix template uses `{$JA4PROXY_TOKEN}` macro for auth
- [ ] Unit tests for Datadog check: mock HTTP responses for each check mode (OK, degraded, unreachable)
- [ ] Unit tests for Nagios check: mock HTTP responses for each `--check` mode

---

## 86b: Load Testing, Benchmarks & Grafana Capacity Dashboard

**Status:** PROPOSED

**Goal:** Produce committed, reproducible benchmark numbers on reference hardware
and a Grafana dashboard that makes it immediately visible when a deployed instance
is approaching those limits.

---

### 86b.1 Load Test Harness

The existing `scripts/tls-traffic-generator.py` already generates TLS connections
with a configurable fingerprint distribution. **Do not duplicate it.** Extend it
with structured measurement output, duration control, and scenario aliases.

```python
# scripts/load_test.py — load test harness built on tls_traffic_generator
"""
Wraps tls_traffic_generator.py with:
 - Timed runs (--duration-seconds)
 - Named scenarios with fixed fingerprint distributions
 - Structured JSON results written to load-test-results/
 - Optional Prometheus push (--push-gateway URL) to observe results in Grafana

Usage:
  python3 scripts/load_test.py \\
    --target localhost:8080 \\
    --duration-seconds 60 \\
    --connections-per-second 1000 \\
    --scenario mixed \\
    [--push-gateway http://localhost:9091]
"""
```

#### Defined Scenarios

All scenarios are fingerprint distribution presets passed to the underlying
traffic generator. An implementing agent must not invent new names.

| Scenario | Browser ALPN | Automation tools | Known scanners | Known malicious | Purpose |
|----------|-------------|-----------------|----------------|-----------------|---------|
| `bypass-only` | 100% | 0% | 0% | 0% | Bypass path throughput ceiling |
| `full-signal` | 0% | 100% | 0% | 0% | Full scoring path (all unknown fingerprints, Redis reads) |
| `attack-wave` | 0% | 0% | 50% | 50% | Block path + Redis write throughput |
| `mixed` | 70% | 20% | 5% | 5% | Representative production traffic |

#### Benchmark measurement definition

For this proxy, **throughput** is defined as:

> Connections per second where proxy latency ≤ P99 latency budget.
> Proxy latency = time from **ClientHello received** to **proxy decision emitted**
> (allow/block/tarpit). Does NOT include TCP accept time or backend TCP handshake time
> — those are outside the proxy's control.

The P99 latency budget is 10ms (from OBSERVABILITY_STANDARDS.md §6).

#### Makefile Targets

```makefile
## Phase 86 targets
load-test:
	@echo "Running JA4proxy load test..."
	python3 scripts/load_test.py \
		--target $(LOAD_TEST_TARGET) \
		--duration-seconds 60 \
		--connections-per-second $(LOAD_TEST_RPS) \
		--scenario $(LOAD_TEST_SCENARIO)

load-test-baseline:
	LOAD_TEST_TARGET=localhost:8080 \
	LOAD_TEST_RPS=1000 \
	LOAD_TEST_SCENARIO=mixed \
	$(MAKE) load-test

load-test-benchmark:
	@echo "Running full reference benchmark suite (takes ~10 minutes)..."
	@mkdir -p load-test-results
	python3 scripts/load_test.py --target $(LOAD_TEST_TARGET) \
		--duration-seconds 120 --scenario bypass-only \
		--output load-test-results/bypass-only.json
	python3 scripts/load_test.py --target $(LOAD_TEST_TARGET) \
		--duration-seconds 120 --scenario full-signal \
		--output load-test-results/full-signal.json
	python3 scripts/load_test.py --target $(LOAD_TEST_TARGET) \
		--duration-seconds 120 --scenario attack-wave \
		--output load-test-results/attack-wave.json
	python3 scripts/load_test.py --target $(LOAD_TEST_TARGET) \
		--duration-seconds 120 --scenario mixed \
		--output load-test-results/mixed.json
	python3 scripts/load_test.py --report \
		--input load-test-results/ \
		--output docs/performance/benchmarks.md

load-test-report:
	python3 scripts/load_test.py --report \
		--input load-test-results/ \
		--output docs/performance/benchmarks.md

test-phase-86b:
	python -m pytest tests/phase-86b/ -v
```

#### Prometheus Metrics for Load Test Runs

Per OBSERVABILITY_STANDARDS.md §7, observable behaviour must declare metrics.
The load test emits these to a Prometheus Pushgateway during a run, so results
are visible in Grafana:

```
ja4proxy_loadtest_connections_attempted_total   counter  Connections attempted
ja4proxy_loadtest_connections_completed_total   counter  Connections completed without error
ja4proxy_loadtest_errors_total{reason}          counter  Connection errors (timeout|refused|ssl_error)
ja4proxy_loadtest_latency_seconds               histogram Measured proxy latency per connection; buckets [0.0001,0.001,0.005,0.01,0.025,0.05,0.1,0.5,1.0]
ja4proxy_loadtest_throughput_cps                gauge    Achieved connections/second (last 10s window)
```

Add these to `docs/OBSERVABILITY_STANDARDS.md §1d` under a new `Load Testing` subsection.

---

### 86b.2 Benchmark Reference Record

**Do not pre-fill with estimates.** Run `make load-test-benchmark` on the reference
hardware and commit the measured results to `docs/performance/benchmarks.md`.

**Reference hardware:**
- AWS c6g.2xlarge (8 vCPU, 16 GB RAM, ARM Graviton 3) — or document actual hardware
- Amazon Linux 2023 — or document actual OS
- Redis: ElastiCache r6g.large single node, same AZ — or equivalent

The committed record must include:

```
JA4proxy Performance Reference
═══════════════════════════════════════════════════════════

Hardware:   [record actual hardware]
OS:         [record actual OS]
Redis:      [record actual Redis config]
Git SHA:    [commit hash]
Date:       [date of run]
Go version: [go version output]

Definition: "throughput" = ClientHello-received → proxy-decision, P99 ≤ 10ms.
            TCP accept and backend handshake excluded (outside proxy control).

BYPASS PATH (h2/h1 ALPN → immediate allow):
  Max throughput:          [measure] conn/s
  P50 latency:             [measure] ms
  P99 latency:             [measure] ms
  CPU (single proxy core): [measure] % at peak

FULL SIGNAL PATH (all signal modules enabled, Redis reads):
  Max throughput:          [measure] conn/s
  P50 latency:             [measure] ms
  P99 latency:             [measure] ms
  CPU (single proxy core): [measure] % at peak

ATTACK WAVE PATH (block decisions, Redis writes):
  Max throughput:          [measure] conn/s
  P99 latency:             [measure] ms

TARPIT PATH:
  Max concurrent tarpitted: [measure]
  Memory per tarpitted conn: [measure] KB

REDIS LATENCY SENSITIVITY (full signal path at fixed 1000 conn/s):
  At Redis P99 = 1ms:      [measure] conn/s
  At Redis P99 = 5ms:      [measure] conn/s
  At Redis P99 = 20ms:     [measure] conn/s

MEMORY FOOTPRINT:
  Proxy process (idle):          [measure] MB
  Proxy process (10K open conns):[measure] MB
  LRU cache (100K entries):      [measure] MB
```

---

### 86b.3 Grafana Capacity Planning Dashboard

Add a new dashboard `04_capacity.json` to `monitoring/grafana/dashboards/`.
This follows the existing numbering convention from `OBSERVABILITY_STANDARDS.md §3a`.

**Do NOT add capacity panels to the existing `ja4proxy-overview.json` or
`ja4proxy-infrastructure.json`.** Those dashboards have defined audiences (SecOps
and Ops respectively). Capacity planning has a different audience: the platform
team deciding whether to scale before a problem occurs.

**Dashboard:** `monitoring/grafana/dashboards/04_capacity.json`
**Audience:** Platform / capacity planning team
**Refresh:** 5 minutes (capacity data does not need real-time refresh)

Provision in `monitoring/grafana/provisioning/dashboards/default.yml` alongside the other dashboards.

**Row 1: Throughput Headroom**

- Current connections/s vs. published bypass-path benchmark ceiling (gauge, 0–100%, red > 80%)
- Current connections/s vs. published full-signal-path benchmark ceiling (gauge, 0–100%, red > 80%)
- Headroom percentage: `(benchmark_ceiling - current_rate) / benchmark_ceiling * 100`
- These panels use a Grafana annotation from `docs/performance/benchmarks.md` constants stored as dashboard variables (`BYPASS_CEILING_CPS`, `SIGNAL_CEILING_CPS`) — set these from the 86b benchmark run

**Row 2: Latency Budget**

- Pipeline P99 latency trend (7 days) — `histogram_quantile(0.99, rate(ja4proxy_pipeline_duration_seconds_bucket[5m]))`
- P99 budget line at 5ms (target) and 10ms (alert threshold) as reference lines
- Redis latency impact: scatter/heatmap of pipeline P99 vs. Redis P99 (1h window)

**Row 3: Scaling Pressure Indicators**

- Per-node active goroutines or connection count (if exposed)
- Tarpit pool fill fraction: `ja4proxy_tarpit_concurrent / 500`
- HAProxy backend queue depth (`haproxy_backend_current_queue`) — proxy is at capacity when > 0 for 30s (from Phase 87)
- Redis memory utilisation fraction

**Row 4: 30-Day Growth Trend**

- Connections/s over 30 days (timeseries with linear regression trend line using Grafana's built-in transform)
- Projected date when connections/s crosses 80% of the benchmark ceiling (stat panel, derived from trend slope)
- Note: this panel requires a 30-day Prometheus retention window. If retention is shorter, the panel shows available data and notes the retention limit.

---

### 86b Acceptance Criteria

- [ ] `scripts/load_test.py` imports and extends `tls_traffic_generator.py`; does not duplicate TLS connection logic
- [ ] All four scenarios (`bypass-only`, `full-signal`, `attack-wave`, `mixed`) implemented and selectable via `--scenario`
- [ ] Throughput measurement is ClientHello-received → proxy-decision (documented in script docstring)
- [ ] `make load-test-baseline` runs successfully against a local proxy instance
- [ ] `make load-test-benchmark` runs all four scenarios and produces `docs/performance/benchmarks.md`
- [ ] Actual measured numbers committed to `docs/performance/benchmarks.md` — no placeholder values
- [ ] Benchmarks include: all four scenario paths, Redis latency sensitivity table, memory footprint
- [ ] Hardware, OS, Go version, and Git SHA recorded in benchmark file
- [ ] Prometheus load test metrics declared in `docs/OBSERVABILITY_STANDARDS.md §1d`
- [ ] Load test optionally pushes metrics to Prometheus Pushgateway (`--push-gateway` flag)
- [ ] `monitoring/grafana/dashboards/04_capacity.json` present and provisioned
- [ ] Capacity dashboard provisioned in `monitoring/grafana/provisioning/dashboards/default.yml`
- [ ] Dashboard Row 1 headroom panels reference benchmark ceiling constants from dashboard variables
- [ ] Dashboard Row 4 growth trend covers 30 days (or notes retention limit)
- [ ] Unit tests for load test scenario distribution logic

---

## 86c: Capacity Calculator, Runbooks & Alert URL Cleanup

**Status:** PROPOSED

**Depends on:** 86b — benchmark numbers must be committed to `docs/performance/benchmarks.md`
before the calculator constants are finalised. Implement the calculator structure in 86c,
but do not hardcode ceiling values until 86b is complete.

**Goal:** Give operators a sizing tool they can trust (because it's grounded in real
measurements), and ensure every Alertmanager alert links to a real, actionable runbook.

---

### 86c.1 Capacity Sizing Calculator

```bash
python3 scripts/capacity_calculator.py \
  --peak-connections-per-second 5000 \
  --p99-latency-budget-ms 10 \
  --redis-node-count 3 \
  --enable-analytics \
  --enable-beaconing-detection \
  --enable-abuseipdb
```

#### Implementation Notes

The calculator reads benchmark ceiling values from `docs/performance/benchmarks.md`
at runtime (not hardcoded). If the file is absent, it exits with a clear error:

```
ERROR: Benchmark file not found at docs/performance/benchmarks.md.
Run 'make load-test-benchmark' first to populate measured values.
```

Cloud pricing constants are hardcoded with a date comment — they will drift,
and that is acceptable. Operators should re-validate costs annually.

```python
# Cloud pricing — AWS us-east-1, on-demand, as of 2026-04.
# Source: https://aws.amazon.com/ec2/pricing/on-demand/
# Update annually or when planning a deployment.
AWS_PRICES = {
    "c6g.xlarge":  0.136,   # 4 vCPU 8 GB — proxy node
    "c6g.2xlarge": 0.272,   # 8 vCPU 16 GB — proxy node (high traffic)
    "r6g.large":   0.201,   # 2 vCPU 16 GB — Redis
    "r6g.xlarge":  0.403,   # 4 vCPU 32 GB — Redis (large dataset)
    "m6g.xlarge":  0.192,   # 4 vCPU 16 GB — analytics node
}

# Azure pricing — West Europe, pay-as-you-go, as of 2026-04.
# Source: https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/
# Update annually or when planning a deployment.
AZURE_PRICES = {
    "Standard_F4s_v2":  0.169,   # 4 vCPU 8 GB — proxy node equivalent
    "Standard_F8s_v2":  0.338,   # 8 vCPU 16 GB — proxy node (high traffic)
    "Standard_E4s_v3":  0.252,   # 4 vCPU 32 GB — Redis equivalent
    "Standard_E8s_v3":  0.504,   # 8 vCPU 64 GB — Redis (large dataset)
    "Standard_D4s_v3":  0.192,   # 4 vCPU 16 GB — analytics node equivalent
}
```

#### Sample Output

```
JA4proxy Capacity Recommendation
═══════════════════════════════════════════════════════════════════════════

Input parameters:
  Peak connections/second:  5,000
  P99 latency budget:       10ms
  Redis nodes:              3 (cluster)
  Features enabled:         analytics, beaconing, abuseipdb

Benchmark basis:
  Bypass path ceiling:      [from docs/performance/benchmarks.md]  conn/s
  Full signal path ceiling: [from docs/performance/benchmarks.md]  conn/s
  (Hardware: [from benchmarks.md]; Date: [from benchmarks.md])

Proxy node sizing:
  Recommended node count:   3 (N+1 redundancy; 5,000 / signal_ceiling < 1 node needed)
  vCPU per node:            4 (2.5GHz equivalent)
  RAM per node:             4 GB
  Estimated P99 latency:    within budget at this load

Redis sizing:
  Expected key count:       ~2.4M (bans + beaconing + return visitor @ 5K conn/s)
  Estimated memory:         8 GB per Redis node (key_count × avg_key_size × 1.3 overhead)
  Recommended (AWS):        r6g.xlarge | Recommended (Azure): Standard_E4s_v3

Analytics node:
  vCPU:                     4
  RAM:                      16 GB
  Storage (90-day retention): 63 GB (500 bytes × 5,000 conn/s × 86400s × 90d)

Estimated monthly cloud cost:
  ── AWS us-east-1 (pricing as of 2026-04) ──────────────────
  3× proxy (c6g.xlarge):        $293/mo
  3× Redis (r6g.xlarge):        $869/mo
  1× analytics (m6g.xlarge):    $140/mo
  Total AWS:                   ~$1,302/mo

  ── Azure West Europe (pricing as of 2026-04) ──────────────
  3× proxy (Standard_F4s_v2):   $366/mo
  3× Redis (Standard_E4s_v3):   $816/mo
  1× analytics (Standard_D4s_v3): $140/mo
  Total Azure:                 ~$1,322/mo

  Note: Prices are on-demand; reserved instances typically 30–40% cheaper.
  Note: Prices dated 2026-04. Re-validate annually against current pricing.
```

#### Sizing Methodology

- 50% headroom applied on top of measured peak connections/second
- N+1 for all stateful components (Redis, proxy)
- Redis memory formula: `key_count × avg_key_size × 1.3 (overhead factor)`
- Analytics storage: `bytes_per_connection × connections_per_second × 86400 × retention_days`
- Latency budget is checked against the Redis latency sensitivity table from benchmarks

---

### 86c.2 Operational Runbooks

Seven standalone runbook files — one per high-value alert. These are short, focused,
and designed to be linked directly from `runbook_url` in Alertmanager.

Where a topic overlaps with an existing runbook (e.g., `security_incident_response.md`),
the new file is still created as a standalone document, and may cross-reference the
existing runbook for deeper context. This ensures every alert has a dedicated,
unchanging URL.

Files to create in `docs/runbooks/`:

| File | Alert it covers |
|------|----------------|
| `ja4proxy_node_unhealthy.md` | `ProxyInstanceDown` |
| `ja4proxy_redis_latency_high.md` | `RedisMemoryHigh`, `RedisDown` |
| `ja4proxy_certificate_expiring.md` | (new alert — see §86c.3) |
| `ja4proxy_block_rate_high.md` | `ProxyHighBlockRate` |
| `ja4proxy_campaign_detected.md` | `SpamhausMatchRate`, `ScoreDriftDetected` |
| `ja4proxy_dial_change_unexpected.md` | `ProxyDialChanged` |
| `ja4proxy_tarpit_pool_full.md` | `ProxyTarpitConcurrentHigh` |

Each follows the standard format (severity, what is happening, impact, diagnosis
steps, resolution, escalation). Diagnosis steps must be actionable CLI commands —
no placeholders.

Example runbook structure:
```markdown
# Runbook: ja4proxy_block_rate_high

## Severity
WARNING (>10 blocks/s for 2m) → CRITICAL (>100 blocks/s for 2m)

## What is happening
JA4proxy is blocking an unusually high fraction of connections.

## Impact
- LOW RISK: Possibly an attack campaign; blocking is working as intended.
- HIGH RISK: Possible false positive wave if the browser shadow score is also elevated.

## Diagnosis
1. Check browser shadow score:
   `ja4proxy-cli metrics --node all --metric ja4proxy_analytics_shadow_score_median`
   If > 15, a FP wave is likely. If < 5, this is a genuine attack. Proceed accordingly.
2. Check active campaigns:
   `ja4proxy-cli campaign list --active`
3. Check top blocked fingerprints:
   `ja4proxy-cli fingerprint top --action block --window 1h`
4. Check Management UI Campaign Tracker for correlated subnet activity.

## Resolution — Attack campaign (shadow score normal)
No action required unless collateral FP rate is elevated.
Monitor: `ja4proxy-cli metrics --metric ja4proxy_analytics_calibration_issue`

## Resolution — False positive wave (shadow score elevated)
1. Identify the FP fingerprint: `ja4proxy-cli fingerprint top --action block --window 15m`
2. Add to allowlist: `ja4proxy-cli allowlist add <ja4> --reason "FP mitigation" --ticket CHG-XXXXX`
3. If dial was recently raised, consider temporarily lowering it:
   `ja4proxy-cli dial set <previous> --confirm --ticket INC-XXXXX`

## Escalation
Page SecOps lead if block rate > 100/s AND shadow score > 20 simultaneously.

## Related runbooks
- [security_incident_response.md](security_incident_response.md) — incident escalation paths
```

---

### 86c.3 Alert Rule URL Cleanup

**Problem:** All `monitoring/alertmanager/rules/*.yml` files contain fake placeholder
`runbook_url` values of the form:

```yaml
runbook_url: "https://docs.ja4proxy.example.com/runbooks/{{ $labels.alertname }}"
```

These resolve to nothing in Alertmanager. The `{{ $labels.alertname }}` template is
valid Alertmanager syntax but points to a non-existent domain.

**Task:** Replace every fake URL with a real relative path to the corresponding
runbook file. Where a dedicated runbook does not yet exist (Phase 86c creates 7),
point to the most relevant existing runbook with an anchor.

The Makefile target for this cleanup:

```makefile
update-alertmanager-runbook-urls:
	@echo "Updating Alertmanager runbook URLs across all rule files..."
	python3 scripts/update_runbook_urls.py \
		--rules-dir monitoring/alertmanager/rules/ \
		--mapping docs/phases/PHASE_86_runbook_mapping.yml
```

Create `docs/phases/PHASE_86_runbook_mapping.yml` as the authoritative mapping from
alert name to runbook path:

```yaml
# PHASE_86_runbook_mapping.yml
# Maps alert name (from Alertmanager label) to the runbook file path.
# Used by scripts/update_runbook_urls.py.
# Format: AlertName: "docs/runbooks/filename.md#anchor-if-needed"

ProxyInstanceDown:           "docs/runbooks/ja4proxy_node_unhealthy.md"
ProxyHighBlockRate:          "docs/runbooks/ja4proxy_block_rate_high.md"
ProxyDialChanged:            "docs/runbooks/ja4proxy_dial_change_unexpected.md"
ProxyTarpitConcurrentHigh:   "docs/runbooks/ja4proxy_tarpit_pool_full.md"
RedisDown:                   "docs/runbooks/ja4proxy_redis_latency_high.md"
RedisMemoryHigh:             "docs/runbooks/ja4proxy_redis_latency_high.md"
AbuseIPDBQuotaExhausted:     "docs/runbooks/external_api_failures.md#abuseipdb-quota"
SpamhausDownloadFailed:      "docs/runbooks/feed_management.md#download-failed"
SpamhausListStale:           "docs/runbooks/feed_management.md#list-stale"
PipelineInternalError:       "docs/runbooks/security_incident_response.md#pipeline-internal-error"
ExceptionRateSpike:          "docs/runbooks/security_incident_response.md#exception-rate-spike"
ScoreDriftDetected:          "docs/runbooks/ja4proxy_campaign_detected.md"
BrowserShadowScoreElevated:  "docs/runbooks/ja4proxy_block_rate_high.md#false-positive-wave"
HighBlockRate:               "docs/runbooks/ja4proxy_block_rate_high.md"
BackupFailed:                "docs/runbooks/cloud_backup_operations.md"
# ... (extend as new alerts are added; this file is the source of truth)
```

This approach means all 30+ alert rules are updated in one sweep by a script, rather
than by hand-editing each rule file. The mapping file is also the audit trail for
"which alert links to which runbook."

Also add a **new alert rule** for certificate expiry, which is currently detected only
via Datadog (§86a.1) but is absent from the Prometheus/Alertmanager stack:

```yaml
# monitoring/alertmanager/rules/proxy.rules.yml — append to existing group
      - alert: ProxyCertificateExpiringSoon
        expr: ja4proxy_cert_days_remaining < 30
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "TLS certificate on {{ $labels.node }} expires in {{ $value }} days"
          runbook_url: "docs/runbooks/ja4proxy_certificate_expiring.md"
```

> Note: `ja4proxy_cert_days_remaining` must be added to the Prometheus metric
> registry (`docs/OBSERVABILITY_STANDARDS.md §1d`) and emitted by the Go proxy's
> health/metrics endpoint. If this metric does not exist by Phase 86c implementation
> time, file a coordination note in `PHASE_86_notes.md` pointing to the phase that
> should add it.

---

### 86c Acceptance Criteria

- [ ] `scripts/capacity_calculator.py` reads benchmark ceilings from `docs/performance/benchmarks.md` at runtime; exits with clear error if file absent
- [ ] Calculator output includes cloud cost estimates for both AWS and Azure
- [ ] AWS and Azure pricing constants are dated with a source comment
- [ ] Calculator produces valid recommendations for inputs 100–100,000 conn/s
- [ ] `scripts/update_runbook_urls.py` updates all fake `https://docs.ja4proxy.example.com/` URLs to real local paths
- [ ] `docs/phases/PHASE_86_runbook_mapping.yml` covers every alert in every `monitoring/alertmanager/rules/*.yml` file
- [ ] All 7 runbook files present in `docs/runbooks/` with standard format
- [ ] Every runbook has: Severity, What is happening, Impact, Diagnosis (actionable commands), Resolution, Escalation
- [ ] `ProxyCertificateExpiringSoon` alert rule added to `proxy.rules.yml`
- [ ] `ja4proxy_cert_days_remaining` added to `docs/OBSERVABILITY_STANDARDS.md §1d` (or coordination note filed)
- [ ] After running `update-alertmanager-runbook-urls`, zero remaining `docs.ja4proxy.example.com` URLs in any rules file
- [ ] Unit tests for capacity calculator sizing formulas (at least: node count, Redis memory, storage sizing)
- [ ] Unit tests for `update_runbook_urls.py` (mock rules files, assert correct URL substitution)

---

## 8. Overall Acceptance Criteria

All three sub-phase checklists must be fully checked before Phase 86 is marked
COMPLETE in `docs/phases/manifest.yaml`.

### Summary checklist

**86a — Integrations**
- [ ] All 86a acceptance criteria above

**86b — Load testing and capacity dashboard**
- [ ] All 86b acceptance criteria above

**86c — Calculator, runbooks, alert cleanup**
- [ ] All 86c acceptance criteria above

### Cross-cutting requirements

- [ ] `CHANGELOG.md` updated with a Phase 86 entry
- [ ] `docs/phases/manifest.yaml` updated: `status: COMPLETE`
- [ ] `make sync` run; `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md` regenerated
- [ ] `PHASE_86_notes.md` written summarising key decisions (especially benchmark hardware and any metric gaps discovered)
- [ ] `docs/OBSERVABILITY_STANDARDS.md §1d` updated with load test metrics and `ja4proxy_cert_days_remaining`
- [ ] All new Makefile targets added at the bottom of the Makefile under `## Phase 86 targets`; no existing targets modified
