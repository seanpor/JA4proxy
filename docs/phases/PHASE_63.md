# Phase 63: Service Level Objectives

---

## 1. Overview

JA4proxy already has:

- 200+ Prometheus metrics in the `ja4proxy_*` namespace
- Grafana dashboards in `monitoring/grafana/dashboards/`
- Alertmanager rules in `monitoring/alertmanager/rules/` (Phase 14e)
- OpenTelemetry tracing (Phase 16)
- A deep health endpoint at `GET /api/v1/health/deep` (Phase 41)
- Recording rules in `monitoring/prometheus/recording_rules.yml`

This phase does NOT re-implement any of that. The instrumentation is complete.

The problem: 200+ metrics exist but zero Service Level Objectives are defined. There
is no way to answer "is the proxy operating normally right now?" without manually
inspecting dashboards and applying ad-hoc judgement. A SIEM integration (Phase 80)
fed by these metrics without SLOs produces alerts with no actionable threshold — you
cannot page on a number that has no agreed-upon bound.

This phase delivers:

1. Four SLI definitions with precise PromQL expressions
2. Numeric SLO targets for three of the four SLIs
3. Prometheus recording rules for error budget arithmetic
4. Multiwindow burn-rate alert rules in a new `slo_alerts.yml`
5. A Grafana SLO dashboard provisioned as `monitoring/grafana/dashboards/slo_overview.json`
6. On-call runbook skeletons — one per SLI burn-rate alert

---

## 2. SLI Definitions

An SLI (Service Level Indicator) is a ratio: good events / total events, measured over
a rolling window. A good event is a specific observable outcome that means "the system
is doing its job." All four SLIs below are expressed as PromQL ratios so they can be
recorded, graphed, and compared against SLO targets.

### 2.1 Availability SLI

**Definition:** Fraction of 5-minute windows in which the proxy is successfully
processing connections (allowed or blocked). A connection that produces a
`ja4proxy_connection_errors_total` increment is not a good event — it means the
proxy encountered an internal error before reaching a decision.

```promql
# SLI value (ratio 0–1)
rate(ja4proxy_connections_total[5m])
/
(
  rate(ja4proxy_connections_total[5m])
  + rate(ja4proxy_connection_errors_total[5m])
)
```

**SLO target:** 99.9% over a 28-day rolling window.

**Error budget:** 0.1% of 28 days = 40.32 minutes of allowable bad minutes per window.

**Notes:**
- `ja4proxy_connections_total` increments on every connection that reaches a
  decision (allow, block, tarpit, ban, rate_limit, flag). It does not increment on
  connections that fail before the pipeline runs.
- `ja4proxy_connection_errors_total` increments when an unhandled exception or
  timeout occurs in `handle_connection()`.
- Both metrics carry a `{job="ja4proxy"}` label. When multiple proxy instances
  run, aggregate with `sum(rate(...))` in the numerator and denominator
  separately before dividing.

### 2.2 Latency SLI

**Definition:** Fraction of connections processed within 10 milliseconds end-to-end
(from TCP accept to the first byte forwarded or the RST sent). The histogram bucket
`{le="0.01"}` in `ja4proxy_request_duration_seconds` is the measurement point.

```promql
# SLI value (ratio 0–1)
rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[5m])
/
rate(ja4proxy_request_duration_seconds_count[5m])
```

**SLO target:** 99% of connections processed in <10ms over a 28-day rolling window.

**Error budget:** 1% of all connections may exceed 10ms.

**Notes:**
- The 10ms threshold covers the proxy's internal decision cost. It excludes backend
  connection time, which is not under proxy control.
- The `le="0.01"` bucket must exist in the histogram. Verify with:
  `promtool query instant http://localhost:9090 'ja4proxy_request_duration_seconds_bucket{le="0.01"}'`
- If the bucket does not exist, it must be added to the histogram definition in
  `proxy.py` / `cmd/proxy/main.go` before this SLI can be measured.

### 2.3 Redis Correctness SLI

**Definition:** Fraction of Redis operations that succeed. Redis failure degrades
proxy correctness because bans, rate limits, and block lists are no longer enforced —
the proxy still accepts connections (fail-open by design) but cannot apply
policy decisions that depend on Redis state.

```promql
# SLI value (ratio 0–1)
rate(ja4proxy_redis_operations_total{result="ok"}[5m])
/
rate(ja4proxy_redis_operations_total[5m])
```

**SLO target:** 99.5% Redis operation success rate over a 28-day rolling window.

**Error budget:** 0.5% of Redis operations may fail.

**Notes:**
- `ja4proxy_redis_operations_total` must carry a `result` label with values `"ok"`
  and `"error"`. If it currently only has `result="error"` (error counter only),
  an `"ok"` series must be added at every Redis call site.
- Redis failures are expected during planned Redis restarts and cluster failovers.
  These are recorded in the error budget but do not require a page if the duration
  is within the maintenance window announced in advance.
- A 99.5% SLO at 5ms average Redis operation means up to ~72 minutes of Redis
  unavailability per 28-day window before the budget is exhausted.

### 2.4 False Positive Rate (Policy Metric — No Hard SLO)

**Definition:** Fraction of connections that are blocked (action in `block`, `ban`,
`tarpit`, `rate_limit`) relative to all connections in a 5-minute window.

```promql
# False positive rate indicator (ratio 0–1)
rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[5m])
/
rate(ja4proxy_connections_total[5m])
```

**SLO target:** None. This is a policy metric. The blocking rate depends on the
dial setting and the traffic profile of each deployment. At dial=0, the blocking
rate is always 0 regardless of scored traffic.

**Alert threshold:** Alert if the 5-minute blocking ratio exceeds 5% (i.e., more
than 1 in 20 connections is blocked). This threshold indicates either a mass attack,
a misconfiguration that is creating false positives, or a sudden change in traffic
composition. It is an observation alert, not a paging alert.

**Notes:**
- The 5% threshold is a starting point. Operators must adjust it for their traffic
  profile after observing baseline blocking rates for at least one week.
- This metric is reported on the SLO dashboard for visibility but does not
  contribute to any error budget.

---

## 3. Prometheus Recording Rules

File: `monitoring/prometheus/slo_recording_rules.yml`

This file is separate from the existing `monitoring/prometheus/recording_rules.yml`
(which records operational aggregations). Keeping SLO rules in their own file makes
it straightforward to validate them independently with `promtool check rules`.

```yaml
# monitoring/prometheus/slo_recording_rules.yml
# SLO recording rules for JA4proxy.
# These rules implement the Google SRE "multiwindow, multi-burn-rate" alerting
# pattern. Short windows (1h, 6h) detect fast burns. Long windows (6h, 3d)
# detect slow burns that would exhaust the 28-day budget without triggering
# fast-burn alerts.
#
# All ratios are dimensionless (0–1). Multiply by 100 for percentage display.

groups:
  - name: ja4proxy_slo_base
    interval: 1m
    rules:
      # ── Availability ────────────────────────────────────────────────────────
      - record: job:ja4proxy_availability:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_connections_total[5m]))
          /
          (
            sum(rate(ja4proxy_connections_total[5m]))
            + sum(rate(ja4proxy_connection_errors_total[5m]))
          )

      - record: job:ja4proxy_availability:ratio_rate1h
        expr: |
          sum(rate(ja4proxy_connections_total[1h]))
          /
          (
            sum(rate(ja4proxy_connections_total[1h]))
            + sum(rate(ja4proxy_connection_errors_total[1h]))
          )

      - record: job:ja4proxy_availability:ratio_rate6h
        expr: |
          sum(rate(ja4proxy_connections_total[6h]))
          /
          (
            sum(rate(ja4proxy_connections_total[6h]))
            + sum(rate(ja4proxy_connection_errors_total[6h]))
          )

      - record: job:ja4proxy_availability:ratio_rate3d
        expr: |
          sum(rate(ja4proxy_connections_total[3d]))
          /
          (
            sum(rate(ja4proxy_connections_total[3d]))
            + sum(rate(ja4proxy_connection_errors_total[3d]))
          )

      # ── Latency ─────────────────────────────────────────────────────────────
      - record: job:ja4proxy_latency_p99_good:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[5m]))
          / sum(rate(ja4proxy_request_duration_seconds_count[5m]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate1h
        expr: |
          sum(rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[1h]))
          / sum(rate(ja4proxy_request_duration_seconds_count[1h]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate6h
        expr: |
          sum(rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[6h]))
          / sum(rate(ja4proxy_request_duration_seconds_count[6h]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate3d
        expr: |
          sum(rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[3d]))
          / sum(rate(ja4proxy_request_duration_seconds_count[3d]))

      # ── Redis Correctness ────────────────────────────────────────────────────
      - record: job:ja4proxy_redis_correctness:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_redis_operations_total{result="ok"}[5m]))
          / sum(rate(ja4proxy_redis_operations_total[5m]))

      - record: job:ja4proxy_redis_correctness:ratio_rate1h
        expr: |
          sum(rate(ja4proxy_redis_operations_total{result="ok"}[1h]))
          / sum(rate(ja4proxy_redis_operations_total[1h]))

      - record: job:ja4proxy_redis_correctness:ratio_rate6h
        expr: |
          sum(rate(ja4proxy_redis_operations_total{result="ok"}[6h]))
          / sum(rate(ja4proxy_redis_operations_total[6h]))

      - record: job:ja4proxy_redis_correctness:ratio_rate3d
        expr: |
          sum(rate(ja4proxy_redis_operations_total{result="ok"}[3d]))
          / sum(rate(ja4proxy_redis_operations_total[3d]))

  - name: ja4proxy_slo_burn_rates
    interval: 1m
    rules:
      # Error budget burn rates.
      # A burn rate of 1.0 means the budget is being consumed at exactly the
      # rate that would exhaust it over 28 days. A burn rate of 14.4 means
      # the budget will be exhausted in 2 hours (28d / 14.4 = 2h × 24 = 2h).
      #
      # Formula: burn_rate = (1 - sli_ratio) / (1 - slo_target)
      # where slo_target is the numeric SLO (e.g. 0.999 for 99.9%).

      # Availability burn rates (SLO = 0.999)
      - record: job:ja4proxy_availability:burn_rate1h
        expr: (1 - job:ja4proxy_availability:ratio_rate1h) / 0.001

      - record: job:ja4proxy_availability:burn_rate6h
        expr: (1 - job:ja4proxy_availability:ratio_rate6h) / 0.001

      - record: job:ja4proxy_availability:burn_rate3d
        expr: (1 - job:ja4proxy_availability:ratio_rate3d) / 0.001

      # Latency burn rates (SLO = 0.99)
      - record: job:ja4proxy_latency_p99_good:burn_rate1h
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate1h) / 0.01

      - record: job:ja4proxy_latency_p99_good:burn_rate6h
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate6h) / 0.01

      - record: job:ja4proxy_latency_p99_good:burn_rate3d
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate3d) / 0.01

      # Redis correctness burn rates (SLO = 0.995)
      - record: job:ja4proxy_redis_correctness:burn_rate1h
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate1h) / 0.005

      - record: job:ja4proxy_redis_correctness:burn_rate6h
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate6h) / 0.005

      - record: job:ja4proxy_redis_correctness:burn_rate3d
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate3d) / 0.005

  - name: ja4proxy_slo_budget_remaining
    interval: 5m
    rules:
      # 28-day error budget remaining as a ratio (1.0 = full budget, 0 = exhausted).
      # Uses the 3d window as a proxy for the 28-day rolling window.
      # For a true 28-day calculation, use `increase()` over 28d on raw counters
      # after sufficient data has accumulated.

      - record: job:ja4proxy_availability:budget_remaining28d
        expr: |
          clamp_min(
            1 - (
              (1 - job:ja4proxy_availability:ratio_rate3d) * 28
              / (28 * 0.001)
            ),
            0
          )

      - record: job:ja4proxy_latency_p99_good:budget_remaining28d
        expr: |
          clamp_min(
            1 - (
              (1 - job:ja4proxy_latency_p99_good:ratio_rate3d) * 28
              / (28 * 0.01)
            ),
            0
          )

      - record: job:ja4proxy_redis_correctness:budget_remaining28d
        expr: |
          clamp_min(
            1 - (
              (1 - job:ja4proxy_redis_correctness:ratio_rate3d) * 28
              / (28 * 0.005)
            ),
            0
          )

      # False positive rate (no error budget, but record for dashboard display)
      - record: job:ja4proxy_false_positive_rate:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[5m]))
          / sum(rate(ja4proxy_connections_total[5m]))
```

Add `slo_recording_rules.yml` to the `rule_files` list in
`monitoring/prometheus/prometheus.yml`:

```yaml
rule_files:
  - "alerts.yml"
  - "recording_rules.yml"
  - "slo_recording_rules.yml"   # Phase 63
```

---

## 4. Alertmanager SLO Burn-Rate Alerts

File: `monitoring/alertmanager/rules/slo_alerts.yml`

This follows the multiwindow alerting pattern from Google SRE Workbook Chapter 5.
Each SLI has two alert tiers:

- **Fast burn** (`_FastBurn`): burns >2% of the 28-day budget in 1 hour. Requires
  the burn rate to be elevated in both the 1h and 6h windows simultaneously — this
  prevents a brief spike from paging. Fires immediately on short duration `for: 2m`.
  Action: page the on-call engineer now.
- **Slow burn** (`_SlowBurn`): burns >5% of the 28-day budget over 6 hours. Checked
  against the 6h and 3d windows. `for: 15m` to reduce noise. Action: ticket.

Burn rate thresholds:
- Fast burn fires when `burn_rate1h > 14.4` AND `burn_rate6h > 14.4`
  (14.4 = 1h consumes 2% of 28-day budget: 28d × 24h × 0.02 / 1h = 13.44 → rounded
  up to 14.4 for a 1-hour window triggering on 2% consumption)
- Slow burn fires when `burn_rate6h > 6` AND `burn_rate3d > 1`
  (6 = 6h window consuming 5% of 28d budget: 28d × 24h × 0.05 / 6h ≈ 5.6 → 6)

```yaml
# monitoring/alertmanager/rules/slo_alerts.yml
# Phase 63: SLO burn-rate alerts.
# Implements the Google SRE multiwindow, multi-burn-rate alerting pattern.
# See: https://sre.google/workbook/alerting-on-slos/#6-multiwindow-multi-burn-rate-alerts

groups:
  - name: ja4proxy_slo_availability
    rules:
      - alert: JA4ProxyAvailabilityFastBurn
        expr: |
          job:ja4proxy_availability:burn_rate1h > 14.4
          and
          job:ja4proxy_availability:burn_rate6h > 14.4
        for: 2m
        labels:
          severity: critical
          slo: availability
          burn_tier: fast
        annotations:
          summary: "Availability SLO fast burn: error budget exhausting rapidly"
          description: >
            The 1h burn rate is {{ $value | humanize }}× (threshold 14.4×).
            At this rate the 28-day error budget will be exhausted in under 2 hours.
          runbook_url: "docs/runbooks/slo_availability.md"

      - alert: JA4ProxyAvailabilitySlowBurn
        expr: |
          job:ja4proxy_availability:burn_rate6h > 6
          and
          job:ja4proxy_availability:burn_rate3d > 1
        for: 15m
        labels:
          severity: warning
          slo: availability
          burn_tier: slow
        annotations:
          summary: "Availability SLO slow burn: error budget degrading"
          description: >
            The 6h burn rate is {{ $value | humanize }}× (threshold 6×).
            At this rate the 28-day error budget will be exhausted within the week.
          runbook_url: "docs/runbooks/slo_availability.md"

  - name: ja4proxy_slo_latency
    rules:
      - alert: JA4ProxyLatencyFastBurn
        expr: |
          job:ja4proxy_latency_p99_good:burn_rate1h > 14.4
          and
          job:ja4proxy_latency_p99_good:burn_rate6h > 14.4
        for: 2m
        labels:
          severity: critical
          slo: latency
          burn_tier: fast
        annotations:
          summary: "Latency SLO fast burn: p99 latency budget exhausting rapidly"
          description: >
            The 1h latency burn rate is {{ $value | humanize }}× (threshold 14.4×).
            More than 1% of connections are exceeding the 10ms threshold and the
            rate is accelerating.
          runbook_url: "docs/runbooks/slo_latency.md"

      - alert: JA4ProxyLatencySlowBurn
        expr: |
          job:ja4proxy_latency_p99_good:burn_rate6h > 6
          and
          job:ja4proxy_latency_p99_good:burn_rate3d > 1
        for: 15m
        labels:
          severity: warning
          slo: latency
          burn_tier: slow
        annotations:
          summary: "Latency SLO slow burn: p99 latency budget degrading"
          description: >
            The 6h latency burn rate is {{ $value | humanize }}×.
            Review connection counts and Redis response times.
          runbook_url: "docs/runbooks/slo_latency.md"

  - name: ja4proxy_slo_redis_correctness
    rules:
      - alert: JA4ProxyRedisCorrectnessFastBurn
        expr: |
          job:ja4proxy_redis_correctness:burn_rate1h > 14.4
          and
          job:ja4proxy_redis_correctness:burn_rate6h > 14.4
        for: 2m
        labels:
          severity: critical
          slo: redis_correctness
          burn_tier: fast
        annotations:
          summary: "Redis correctness SLO fast burn: policy enforcement degraded"
          description: >
            Redis operation error rate is causing rapid error budget burn
            (1h burn rate {{ $value | humanize }}×). Bans, rate limits, and
            block lists may not be applying correctly. Fail-open is active.
          runbook_url: "docs/runbooks/slo_redis_correctness.md"

      - alert: JA4ProxyRedisCorrectnessSlowBurn
        expr: |
          job:ja4proxy_redis_correctness:burn_rate6h > 6
          and
          job:ja4proxy_redis_correctness:burn_rate3d > 1
        for: 15m
        labels:
          severity: warning
          slo: redis_correctness
          burn_tier: slow
        annotations:
          summary: "Redis correctness SLO slow burn: intermittent Redis errors"
          description: >
            The 6h Redis error burn rate is {{ $value | humanize }}×. Review
            Redis connection pool exhaustion and network stability.
          runbook_url: "docs/runbooks/slo_redis_correctness.md"

  - name: ja4proxy_slo_false_positive
    rules:
      - alert: JA4ProxyHighBlockRate
        # Policy observation alert — not an SLO burn-rate alert.
        # Fires when more than 5% of connections are blocked in a 5-minute window.
        # This may indicate a mass attack, a misconfiguration, or a false positive
        # wave. Requires manual investigation before taking action.
        expr: job:ja4proxy_false_positive_rate:ratio_rate5m > 0.05
        for: 5m
        labels:
          severity: warning
          slo: false_positive_rate
        annotations:
          summary: "Block rate >5%: potential false positive wave or mass attack"
          description: >
            {{ $value | humanizePercentage }} of connections are being blocked.
            Check the dial setting, recent blacklist changes, and traffic origin.
            Do not raise the dial further until the cause is confirmed.
          runbook_url: "docs/runbooks/slo_availability.md"
```

---

## 5. SLO Grafana Dashboard

File: `monitoring/grafana/dashboards/slo_overview.json`

The dashboard has three rows. All panels use the recording rules defined in Section 3
rather than raw metric queries. The datasource UID `PBFA97CFB590B2093` matches the
existing Prometheus datasource defined in
`monitoring/grafana/provisioning/datasources/prometheus.yml`.

```json
{
  "id": null,
  "uid": "ja4proxy-slo-overview",
  "title": "JA4 Proxy — SLO Overview",
  "tags": ["ja4", "slo", "sre"],
  "timezone": "browser",
  "schemaVersion": 38,
  "version": 1,
  "refresh": "1m",
  "time": {"from": "now-28d", "to": "now"},
  "panels": [

    {
      "id": 1,
      "title": "Row 1 — Current SLI vs Target",
      "type": "row",
      "collapsed": false,
      "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0}
    },

    {
      "id": 10,
      "title": "Availability SLI",
      "description": "Target: 99.9%. Fraction of connections without internal errors.",
      "type": "stat",
      "gridPos": {"h": 5, "w": 8, "x": 0, "y": 1},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "decimals": 3,
          "min": 0,
          "max": 1,
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.998},
              {"color": "green",  "value": 0.999}
            ]
          },
          "mappings": []
        }
      },
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"]}
      },
      "targets": [
        {
          "expr": "job:ja4proxy_availability:ratio_rate5m",
          "legendFormat": "Availability"
        }
      ]
    },

    {
      "id": 11,
      "title": "Latency SLI (p99 <10ms)",
      "description": "Target: 99%. Fraction of connections completing within 10ms.",
      "type": "stat",
      "gridPos": {"h": 5, "w": 8, "x": 8, "y": 1},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "decimals": 3,
          "min": 0,
          "max": 1,
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.985},
              {"color": "green",  "value": 0.99}
            ]
          }
        }
      },
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"]}
      },
      "targets": [
        {
          "expr": "job:ja4proxy_latency_p99_good:ratio_rate5m",
          "legendFormat": "Latency SLI"
        }
      ]
    },

    {
      "id": 12,
      "title": "Redis Correctness SLI",
      "description": "Target: 99.5%. Fraction of Redis operations that succeed.",
      "type": "stat",
      "gridPos": {"h": 5, "w": 8, "x": 16, "y": 1},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "decimals": 3,
          "min": 0,
          "max": 1,
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.99},
              {"color": "green",  "value": 0.995}
            ]
          }
        }
      },
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"]}
      },
      "targets": [
        {
          "expr": "job:ja4proxy_redis_correctness:ratio_rate5m",
          "legendFormat": "Redis Correctness"
        }
      ]
    },

    {
      "id": 2,
      "title": "Row 2 — Error Budget Remaining (28-day)",
      "type": "row",
      "collapsed": false,
      "gridPos": {"h": 1, "w": 24, "x": 0, "y": 6}
    },

    {
      "id": 20,
      "title": "Availability — Budget Remaining",
      "description": "28-day error budget remaining. SLO: 99.9%. Budget: 40 minutes.",
      "type": "timeseries",
      "gridPos": {"h": 7, "w": 8, "x": 0, "y": 7},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "min": 0,
          "max": 1,
          "custom": {
            "lineWidth": 2,
            "fillOpacity": 10
          },
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.25},
              {"color": "green",  "value": 0.5}
            ]
          }
        }
      },
      "options": {
        "tooltip": {"mode": "single"}
      },
      "targets": [
        {
          "expr": "job:ja4proxy_availability:budget_remaining28d",
          "legendFormat": "Availability budget"
        }
      ]
    },

    {
      "id": 21,
      "title": "Latency — Budget Remaining",
      "description": "28-day error budget remaining. SLO: 99%. Budget: ~7 hours of slow connections.",
      "type": "timeseries",
      "gridPos": {"h": 7, "w": 8, "x": 8, "y": 7},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "min": 0,
          "max": 1,
          "custom": {"lineWidth": 2, "fillOpacity": 10},
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.25},
              {"color": "green",  "value": 0.5}
            ]
          }
        }
      },
      "targets": [
        {
          "expr": "job:ja4proxy_latency_p99_good:budget_remaining28d",
          "legendFormat": "Latency budget"
        }
      ]
    },

    {
      "id": 22,
      "title": "Redis Correctness — Budget Remaining",
      "description": "28-day error budget remaining. SLO: 99.5%. Budget: ~72 minutes.",
      "type": "timeseries",
      "gridPos": {"h": 7, "w": 8, "x": 16, "y": 7},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "min": 0,
          "max": 1,
          "custom": {"lineWidth": 2, "fillOpacity": 10},
          "color": {"mode": "thresholds"},
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "red",    "value": null},
              {"color": "yellow", "value": 0.25},
              {"color": "green",  "value": 0.5}
            ]
          }
        }
      },
      "targets": [
        {
          "expr": "job:ja4proxy_redis_correctness:budget_remaining28d",
          "legendFormat": "Redis correctness budget"
        }
      ]
    },

    {
      "id": 3,
      "title": "Row 3 — False Positive Rate",
      "type": "row",
      "collapsed": false,
      "gridPos": {"h": 1, "w": 24, "x": 0, "y": 14}
    },

    {
      "id": 30,
      "title": "Block Rate (% of connections)",
      "description": "Observation metric. Alert threshold: >5%. No SLO.",
      "type": "timeseries",
      "gridPos": {"h": 7, "w": 24, "x": 0, "y": 15},
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "min": 0,
          "custom": {"lineWidth": 2, "fillOpacity": 5}
        },
        "overrides": [
          {
            "matcher": {"id": "byName", "options": "5% threshold"},
            "properties": [
              {"id": "custom.lineStyle",  "value": {"fill": "dash"}},
              {"id": "color",             "value": {"mode": "fixed", "fixedColor": "red"}},
              {"id": "custom.lineWidth",  "value": 1}
            ]
          }
        ]
      },
      "targets": [
        {
          "expr": "job:ja4proxy_false_positive_rate:ratio_rate5m",
          "legendFormat": "Block rate"
        },
        {
          "expr": "vector(0.05)",
          "legendFormat": "5% threshold"
        }
      ]
    }
  ]
}
```

---

## 6. On-Call Runbook Skeletons

Three runbook files. Each follows the same four-section structure used in existing
runbooks under `docs/runbooks/`. Fill in `[FILL IN]` placeholders with org-specific
contact and escalation information before the phase is marked complete.

### 6.1 `docs/runbooks/slo_availability.md`

```markdown
# Runbook: Availability SLO Burn-Rate Alert

## Alert trigger condition

```promql
job:ja4proxy_availability:burn_rate1h > 14.4
and
job:ja4proxy_availability:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

## Initial triage

1. Check deep health endpoint:
   ```bash
   curl -s http://<proxy-host>:9090/api/v1/health/deep | python3 -m json.tool
   ```
   Any `"status": "degraded"` field identifies the failing component.

2. Check proxy CLI health:
   ```bash
   ja4proxy health --verbose
   ```

3. Check Prometheus for the raw rate:
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_availability:ratio_rate5m' \
     | python3 -m json.tool
   ```

4. Check proxy logs for `event=connection_error` entries:
   ```bash
   journalctl -u ja4proxy --since "10 minutes ago" -o json | \
     python3 -c "import sys,json; [print(l) for l in sys.stdin if 'connection_error' in l]"
   ```

## Decision tree

- **Proxy process is not running (`up{job="ja4proxy"} == 0`)**
  → Restart: `systemctl restart ja4proxy` (or `docker compose restart proxy`).
  → If it crashes again immediately, check `ja4proxy_errors_total` and journal logs.

- **Redis is down**
  → This is expected to trigger the Redis correctness alert, not the availability
    alert. If availability is degraded due to Redis: the proxy is not failing open
    correctly. Check `src/cache/local_cache.py` and the `fail_open` config key.
  → Page Redis on-call: `[FILL IN]`

- **High connection rate causing exhaustion**
  → Check `ja4proxy_active_connections` gauge vs the configured `max_connections`
    limit. If near the limit, either add proxy instances or temporarily raise
    `max_connections` in `config/proxy.yml` and send `SIGHUP`.

- **Burn rate is fast but proxy appears healthy**
  → Check if a new proxy deployment just occurred and the 1h window is carrying
    startup errors from before the fix. Wait 10 minutes for the window to roll.

## Escalation

- Severity `critical` (fast burn): page primary on-call: `[FILL IN]`
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If unresolved after 30 minutes: escalate to `[FILL IN]`
```

### 6.2 `docs/runbooks/slo_latency.md`

```markdown
# Runbook: Latency SLO Burn-Rate Alert

## Alert trigger condition

```promql
job:ja4proxy_latency_p99_good:burn_rate1h > 14.4
and
job:ja4proxy_latency_p99_good:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

## Initial triage

1. Check current p99 latency:
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.99,rate(ja4proxy_request_duration_seconds_bucket[5m]))' \
     | python3 -m json.tool
   ```

2. Check active connection count:
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=ja4proxy_active_connections' \
     | python3 -m json.tool
   ```

3. Check Redis operation latency (Redis slowness adds directly to proxy latency):
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.99,rate(ja4proxy_redis_operation_duration_seconds_bucket[5m]))' \
     | python3 -m json.tool
   ```

4. Check for tarpit saturation:
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=ja4proxy_tarpit_concurrent' \
     | python3 -m json.tool
   ```

## Decision tree

- **Active connections near configured limit**
  → Latency is expected to rise as the connection pool saturates. Scale horizontally:
    add proxy instances behind HAProxy, or raise `max_connections` if headroom exists.

- **Redis p99 latency >5ms**
  → Redis is slow. Check Redis CPU, memory, and network. This is a Redis problem, not
    a proxy problem. Page Redis on-call: `[FILL IN]`

- **Tarpit concurrent count >400**
  → Tarpit is near its 500-connection cap. The tarpit workers are consuming resources
    that slow normal connection handling. Review `tarpit_capacity.md` runbook.
    Consider lowering `tarpit_max_concurrent` to free resources.

- **Latency spike correlates with a recent deploy**
  → Check git log and rollback if the spike started within 5 minutes of deploy.
    Roll back: `docker compose up -d --no-build proxy` (previous image tag).

- **No obvious cause**
  → Check system-level metrics: CPU steal time, network receive buffer drops
    (`netstat -s | grep "receive buffer errors"`), and kernel connection backlog
    (`ss -s | grep "TCP:"`).

## Escalation

- Severity `critical` (fast burn): page primary on-call: `[FILL IN]`
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If unresolved after 30 minutes: escalate to `[FILL IN]`
```

### 6.3 `docs/runbooks/slo_redis_correctness.md`

```markdown
# Runbook: Redis Correctness SLO Burn-Rate Alert

## Alert trigger condition

```promql
job:ja4proxy_redis_correctness:burn_rate1h > 14.4
and
job:ja4proxy_redis_correctness:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

**Important:** When this alert fires, the proxy is still accepting connections
(fail-open design). However, bans, rate limits, Spamhaus block lists, and AbuseIPDB
decisions may not be enforcing correctly. Treat this as a security degradation, not
just a reliability event.

## Initial triage

1. Check Redis connectivity from a proxy host:
   ```bash
   redis-cli -h <redis-host> -p 6379 ping
   ```

2. Check Redis error rate in Prometheus:
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=rate(ja4proxy_redis_operations_total{result="error"}[5m])' \
     | python3 -m json.tool
   ```

3. Check which Redis operations are failing (look for a `command` label if present):
   ```bash
   curl -sg 'http://localhost:9090/api/v1/query?query=rate(ja4proxy_redis_operations_total{result="error"}[5m])' \
     | python3 -m json.tool
   ```

4. Check proxy logs for Redis error events:
   ```bash
   journalctl -u ja4proxy --since "10 minutes ago" -o json | \
     python3 -c "import sys,json; [print(l) for l in sys.stdin if 'redis' in l.lower()]"
   ```

## Decision tree

- **Redis is completely unreachable (ping fails)**
  → Proxy is in full fail-open mode. No policy decisions involving Redis state
    are applying. Page Redis on-call immediately: `[FILL IN]`
  → Until Redis recovers, the proxy will not block known-bad IPs or enforce
    rate limits. Notify the security team: `[FILL IN]`

- **Redis responds to ping but errors are high**
  → Redis may be under memory pressure (OOM killer evicting keys) or overloaded.
  → Check Redis INFO: `redis-cli INFO memory` and `redis-cli INFO stats`.
  → If `used_memory_rss > maxmemory * 0.9`, Redis is near eviction threshold.

- **Intermittent errors only during connection spikes**
  → Redis connection pool may be exhausted. Check `ja4proxy_redis_pool_exhausted_total`.
  → Increase `redis_pool_size` in `config/proxy.yml` and reload with `SIGHUP`.

- **Redis is fine but the SLI is below target after Redis recovery**
  → The 1h and 6h windows are still carrying errors from before the fix.
  → Confirm Redis is healthy, then wait for the windows to roll. The SLI
    should recover within 1h.

## Escalation

- Severity `critical` (fast burn): page primary on-call AND notify security team:
  `[FILL IN]`. Reason: policy enforcement is degraded.
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If Redis is down and cannot be recovered within 15 minutes: escalate to
  `[FILL IN]` and consider enabling a temporary static ACL via `config/proxy.yml`
  `static_ip_blocklist` as a manual fallback.
```

---

## 7. Makefile Targets

Add to the bottom of `Makefile` (never edit existing targets):

```makefile
## Phase 63 targets — SLO validation and reporting

validate-slo-rules:
	promtool check rules monitoring/prometheus/slo_recording_rules.yml
	promtool check rules monitoring/alertmanager/rules/slo_alerts.yml
	@echo "SLO recording rules and alert rules are syntactically valid."

slo-report:
	@echo "=== JA4proxy SLO Report ==="
	@echo ""
	@echo "Availability SLI (target: 99.9%):"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_availability:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Current (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
	@echo ""
	@echo "Latency SLI (target: 99% <10ms):"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_latency_p99_good:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Current (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
	@echo ""
	@echo "Redis Correctness SLI (target: 99.5%):"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_redis_correctness:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Current (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
	@echo ""
	@echo "Error Budget Remaining (28-day approximation):"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_availability:budget_remaining28d' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Availability:', round(float(v[0]['value'][1])*100, 2) if v else 'NO DATA', '%')"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_latency_p99_good:budget_remaining28d' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Latency:     ', round(float(v[0]['value'][1])*100, 2) if v else 'NO DATA', '%')"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_redis_correctness:budget_remaining28d' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('  Redis:       ', round(float(v[0]['value'][1])*100, 2) if v else 'NO DATA', '%')"
```

`make validate-slo-rules` requires `promtool` to be installed (`apt install prometheus`
or download from the Prometheus release page). It does not require a running Prometheus
instance.

`make slo-report` requires a Prometheus instance running at `localhost:9090` with at
least 3 days of data for the budget-remaining calculations to be meaningful.

---

## 8. Acceptance Criteria

- [ ] `monitoring/prometheus/slo_recording_rules.yml` exists and passes
      `promtool check rules` with zero errors
- [ ] `monitoring/prometheus/prometheus.yml` includes `slo_recording_rules.yml` in
      its `rule_files` list
- [ ] All twelve base recording rules exist (three SLIs × four time windows:
      5m, 1h, 6h, 3d)
- [ ] All nine burn-rate recording rules exist (three SLIs × three windows: 1h, 6h, 3d)
- [ ] All three budget-remaining rules exist (one per SLI)
- [ ] `monitoring/alertmanager/rules/slo_alerts.yml` exists and passes
      `promtool check rules` with zero errors
- [ ] Six burn-rate alerts defined: fast and slow burn for each of the three SLIs
- [ ] One policy observation alert (`JA4ProxyHighBlockRate`) defined with 5%
      threshold and `for: 5m`
- [ ] All seven alerts include a `runbook_url` annotation pointing to a file that
      exists under `docs/runbooks/`
- [ ] `monitoring/grafana/dashboards/slo_overview.json` exists and is valid JSON
- [ ] SLO dashboard has three rows: current SLI stat panels, error budget time series,
      false positive rate with threshold line
- [ ] Stat panels for availability, latency, and Redis correctness show green above
      SLO target, yellow in the warning band, red below
- [ ] `docs/runbooks/slo_availability.md` exists with all four sections
- [ ] `docs/runbooks/slo_latency.md` exists with all four sections
- [ ] `docs/runbooks/slo_redis_correctness.md` exists with all four sections
- [ ] `make validate-slo-rules` target added to bottom of `Makefile` and runs without
      error against the delivered rule files
- [ ] `make slo-report` target added to bottom of `Makefile`
- [ ] `ja4proxy_request_duration_seconds_bucket{le="0.01"}` bucket confirmed to exist
      in histogram definition (proxy.py and cmd/proxy/main.go); if missing, add it and
      note the change in `PHASE_63_notes.md`
- [ ] `ja4proxy_redis_operations_total` confirmed to carry both `result="ok"` and
      `result="error"` label values; if only `result="error"` exists, add the `"ok"`
      series and note the change in `PHASE_63_notes.md`
