# Phase 63: Service Level Objectives

---

## 1. Overview

JA4proxy already has:

- 200+ Prometheus metrics (mixed `ja4_*` and `ja4proxy_*` namespaces — see §1.5 for the naming inconsistency and required fixes)
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

1. Five SLI definitions with precise PromQL expressions (§2.1–§2.4 observation metrics,
   §2.5 False Positive Rate SLO, §2.6 Throughput SLO)
2. Numeric SLO targets for the three availability/latency/Redis SLIs plus the §2.5
   FP Rate SLO with an Alertmanager inhibit rule for declared attack windows
3. Prometheus recording rules for error budget arithmetic
4. Multiwindow burn-rate alert rules in a new `slo_alerts.yml`, including the
   `JA4proxyHighBlockingRate` alert (the primary FP protection alert)
5. A Grafana SLO dashboard provisioned as `monitoring/grafana/dashboards/slo_overview.json`
6. Four on-call runbooks with actionable Step 1–4 diagnostic commands (not placeholders)
7. SLO review cadence with a defined 4-week baseline period (§9)

---

## 1.5 Metric Naming Prerequisite

**This section must be read before implementing any PromQL expressions in this phase.**

The proxy codebase has an inconsistent metric naming convention that affects SLO
correctness. This inconsistency must be acknowledged and partially resolved before
SLO recording rules will work correctly.

### Current state (as of the proxy.py implementation)

| Metric name in proxy.py | prometheus_client registration |
|---|---|
| `ja4_requests_total` | Counter — labels: `fingerprint_name`, `action`, `source_country`, `tls_version`. Actions: `"blocked"`, `"allowed"`, `"tarpitted"`, `"rate_limited"`, `"banned"` |
| `ja4_request_duration_seconds` | Histogram — buckets: 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0 |
| `ja4proxy_active_connections` | Gauge |
| `ja4_blocked_requests_total` | Counter — labels: `reason`, `source_country`, `attack_type` |
| `ja4proxy_tarpit_concurrent` | Gauge |
| `ja4proxy_tarpit_overflow_total` | Counter — labels: `action` |

### Metrics referenced in this phase that do NOT currently exist

| Metric referenced in sections 2–4 | Status | Action required |
|---|---|---|
| `ja4proxy_connections_total` | Does not exist | The concept maps to `ja4_requests_total`; rename to `ja4proxy_requests_total` during standardisation (see below) |
| `ja4proxy_connection_errors_total` | Does not exist | Add to `proxy.py` `handle_connection()` error handler |
| `ja4proxy_request_duration_seconds` | Wrong prefix (`ja4_` not `ja4proxy_`) | Rename during metric standardisation |
| `ja4proxy_redis_operations_total` | Does not exist | Add to every Redis call site in `proxy.py` and `src/` |

### Standard going forward

The standard for all new metrics in this project is the `ja4proxy_` prefix.
The `ja4_` prefix used by the original metrics is a legacy inconsistency.

**Required fixes (prerequisite for SLO recording rules to produce accurate data):**

1. **Rename `ja4_requests_total` to `ja4proxy_requests_total`** in `proxy.py` and all
   test files. Update any dashboard JSON that references the old name. The SLI
   expressions in sections 2 and 3 of this phase use `ja4proxy_requests_total`
   (not `ja4proxy_connections_total`) as the post-rename target name.

2. **Rename `ja4_request_duration_seconds` to `ja4proxy_request_duration_seconds`** in
   `proxy.py`. The `le="0.01"` bucket already exists (confirmed in `proxy.py` bucket
   list: `0.001, 0.005, 0.01, ...`); no bucket change is needed.

3. **Add `ja4proxy_connection_errors_total`** counter to `proxy.py`:
   ```python
   CONNECTION_ERRORS = Counter(
       "ja4proxy_connection_errors_total",
       "Unhandled errors in handle_connection() before a policy decision is reached",
       ["error_type"],  # values: "redis_timeout", "tls_parse_error", "backend_refused", "oom", "unknown"
   )
   ```
   Increment this in the `except` block of `handle_connection()`.

4. **Add `ja4proxy_redis_operations_total`** counter to `proxy.py` and all Redis call
   sites in `src/`:
   ```python
   REDIS_OPERATIONS = Counter(
       "ja4proxy_redis_operations_total",
       "Redis operations performed by the proxy",
       ["command", "result"],  # result: "ok" or "error"
   )
   ```
   Increment `result="ok"` on success and `result="error"` on any `RedisError` exception.

### PromQL fallback expressions (current metric names)

All PromQL expressions in sections 2, 3, and 4 use the **target (post-rename) metric
names** (`ja4proxy_*` prefix throughout). Until the renames and additions above are
complete, use the following fallback expressions that work against the current metric
names:

| SLI | Target expression (post-rename) | Fallback expression (current names) |
|---|---|---|
| Availability — numerator | `rate(ja4proxy_requests_total[5m])` | `rate(ja4_requests_total[5m])` |
| Availability — denominator | `rate(ja4proxy_requests_total[5m]) + rate(ja4proxy_connection_errors_total[5m])` | `rate(ja4_requests_total[5m])` only — `connection_errors` does not yet exist; SLI reads as 1.0 until the metric is added |
| Latency | `rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[5m])` | `rate(ja4_request_duration_seconds_bucket{le="0.01"}[5m])` |
| Redis correctness | `rate(ja4proxy_redis_operations_total{result="ok"}[5m])` | Not available until metric added; recording rule returns `NaN` |
| False positive rate | `rate(ja4proxy_requests_total{action=~"blocked\|banned\|tarpitted\|rate_limited"}[5m])` | `rate(ja4_requests_total{action=~"blocked\|banned\|tarpitted\|rate_limited"}[5m])` |

Note the action label value details: `ja4_requests_total` (and its renamed successor)
uses `"tarpitted"` (not `"tarpit"`) and `"rate_limited"` (not `"rate_limit"`). The
regex filters in sections 2.4, 2.5, and the alert rules must match these exact values.

Document all of the above findings in `PHASE_63_notes.md` when submitting.

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
# Target metric name (post-rename): ja4proxy_requests_total
# Current fallback: ja4_requests_total
rate(ja4proxy_requests_total[5m])
/
(
  rate(ja4proxy_requests_total[5m])
  + rate(ja4proxy_connection_errors_total[5m])
)
```

**SLO target:** 99.9% over a 28-day rolling window.

**Error budget:** 0.1% of 28 days = 40.32 minutes of allowable bad minutes per window.

**Notes:**
- `ja4proxy_requests_total` (renamed from `ja4_requests_total` — see §1.5) increments
  on every connection that reaches a decision (allowed, blocked, tarpitted, banned,
  rate_limited, flagged). It does not increment on connections that fail before the
  pipeline runs.
- `ja4proxy_connection_errors_total` increments when an unhandled exception or
  timeout occurs in `handle_connection()`. This metric does not yet exist in
  `proxy.py` — see §1.5 for the code addition required.
- Both metrics carry a `{job="ja4proxy"}` label. When multiple proxy instances
  run, aggregate with `sum(rate(...))` in the numerator and denominator
  separately before dividing.

### 2.2 Latency SLI

**Definition:** Fraction of connections processed within 10 milliseconds end-to-end
(from TCP accept to the first byte forwarded or the RST sent). The histogram bucket
`{le="0.01"}` in `ja4proxy_request_duration_seconds` is the measurement point.

```promql
# SLI value (ratio 0–1)
# Target metric name (post-rename): ja4proxy_request_duration_seconds
# Current fallback: ja4_request_duration_seconds
rate(ja4proxy_request_duration_seconds_bucket{le="0.01"}[5m])
/
rate(ja4proxy_request_duration_seconds_count[5m])
```

**SLO target:** 99% of connections processed in <10ms over a 28-day rolling window.

**Error budget:** 1% of all connections may exceed 10ms.

**Notes:**
- The 10ms threshold covers the proxy's internal decision cost. It excludes backend
  connection time, which is not under proxy control.
- The `le="0.01"` bucket exists in `proxy.py` (confirmed: buckets list is
  `0.001, 0.005, 0.01, 0.025, ...`). No bucket change is needed.
- Before the rename, verify with the current name:
  `promtool query instant http://localhost:9090 'ja4_request_duration_seconds_bucket{le="0.01"}'`
- After the rename (§1.5), use:
  `promtool query instant http://localhost:9090 'ja4proxy_request_duration_seconds_bucket{le="0.01"}'`

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
- `ja4proxy_redis_operations_total` does not yet exist in `proxy.py` — see §1.5 for
  the code addition required. Until it is added, the recording rule for this SLI
  returns `NaN` and the Redis correctness panels in the dashboard will show no data.
- When added, the metric must carry a `result` label with both `"ok"` and `"error"`
  values, incremented at every Redis call site.
- Redis failures are expected during planned Redis restarts and cluster failovers.
  These are recorded in the error budget but do not require a page if the duration
  is within the maintenance window announced in advance.
- A 99.5% SLO at 5ms average Redis operation means up to ~72 minutes of Redis
  unavailability per 28-day window before the budget is exhausted.

### 2.4 False Positive Rate (Observation Metric)

**Definition:** Fraction of connections that are blocked (action in `block`, `ban`,
`tarpit`, `rate_limit`) relative to all connections in a 5-minute window.

```promql
# False positive rate indicator (ratio 0–1)
# Target metric name (post-rename): ja4proxy_requests_total
# Current fallback: ja4_requests_total
# Action label values in ja4_requests_total: "blocked", "tarpitted", "rate_limited", "banned"
# (note: "tarpitted" not "tarpit"; "rate_limited" not "rate_limit")
rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[5m])
/
rate(ja4proxy_requests_total[5m])
```

**Notes:**
- At dial=0, the blocking rate is always 0 regardless of scored traffic. The SLO
  in §2.5 applies only at dial ≥ 50.
- This recording rule feeds both the dashboard and the §2.5 SLO alert.
- At dial=0 (monitor mode) this metric is always 0 by design.
- The action label values on `ja4_requests_total` / `ja4proxy_requests_total` are
  `"blocked"`, `"tarpitted"`, `"rate_limited"`, `"banned"` — not the shorter forms
  `"block"`, `"tarpit"`, `"rate_limit"`. Use the full forms in regex filters.

---

### 2.5 False Positive Rate SLO

**Definition:** Fraction of connections at dial ≥ 50 that result in a block, ban,
tarpit, or rate_limit action, measured over a rolling 1-hour window. At dial=0
(monitor mode) this metric is always 0 by design and the SLO does not apply.

```promql
# FP Rate indicator (ratio 0–1, only meaningful when dial > 0)
# Target metric name (post-rename): ja4proxy_requests_total
# Current fallback: ja4_requests_total
# Use full action label values: "blocked", "tarpitted", "rate_limited", "banned"
rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[5m])
/
rate(ja4proxy_requests_total[5m])
```

**SLO target:** The blocking rate must not exceed 2% during any rolling 1-hour window
when dial ≥ 50.

**Why 2% and not lower?** At high dial settings during an active attack campaign,
blocking rates can legitimately reach 5–15%. The 2% threshold applies specifically
when the operator has confirmed there is no ongoing attack (i.e., normal traffic
conditions). During a declared attack window, this alert is silenced via Alertmanager
inhibit rules against an `attack_in_progress` alert.

**Why this matters:** This SLO is the only metric that directly measures the product's
primary failure mode — blocking legitimate users. Without it, the proxy can be
silently misconfigured to block 20% of connections and no alert fires until users
complain. A 2% blocking rate on normal traffic means roughly 1 in 50 connections is
blocked; at 10,000 connections/hour that is 200 blocked users per hour — enterprise
customers will escalate this within minutes.

**Error budget:** This SLO operates on a per-incident basis rather than a rolling
28-day error budget. Any 1-hour window with blocking rate > 2% (outside a declared
attack window) is a policy incident requiring investigation. There is no error budget
accumulation — every incident is investigated.

**Alerting rule:**
```yaml
- alert: JA4proxyHighBlockingRate
  expr: |
    # NOTE: uses ja4proxy_requests_total (renamed from ja4_requests_total — see §1.5)
    # Action label values are "blocked", "tarpitted", "rate_limited", "banned"
    (
      rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[1h])
      / rate(ja4proxy_requests_total[1h])
    ) > 0.02
    and
    ja4proxy_dial_setting >= 50
  for: 5m
  labels:
    severity: warning
    team: security-ops
  annotations:
    summary: "JA4proxy blocking rate exceeds 2% — possible false positive spike"
    description: |
      Blocking rate is {{ $value | humanizePercentage }} over the last hour
      with dial at {{ $labels.dial_setting }}.
      This may indicate a misconfiguration, an overly aggressive dial setting,
      or a legitimate attack campaign.
      Runbook: docs/runbooks/slo_fp_rate_runbook.md
```

**Inhibit rule for declared attack windows:**
Add to Alertmanager configuration:
```yaml
inhibit_rules:
  - source_match:
      alertname: JA4proxyAttackCampaignDetected
    target_match:
      alertname: JA4proxyHighBlockingRate
    equal: ['job']
```

The `JA4proxyAttackCampaignDetected` alert is produced by the analytics node (Phase 12)
when a coordinated attack campaign is identified. When it is active, the FP rate SLO
alert is suppressed because high blocking is expected.

---

### 2.6 Throughput SLO (Capacity Commitment)

**Definition:** The proxy must process all incoming connections without queueing.
A queueing proxy is one where `ja4proxy_active_connections` grows unboundedly over
a 5-minute window.

```promql
# Throughput health indicator: active connections not growing unboundedly
# Alert if active connections have grown by more than 100 in 5 minutes
# (growth indicates connections are not completing)
increase(ja4proxy_active_connections[5m]) > 100
```

**SLO target:** Zero unbounded connection growth over any 5-minute window.

**Notes:**
- This SLO is a leading indicator for capacity exhaustion, not a hard throughput
  guarantee. The proxy's documented throughput ceiling (Python: ~8,100 conn/s at
  4 workers; Go: TBD after Phase 65 benchmarks) is the practical limit.
- A growing active connection count indicates the proxy is accepting connections
  faster than it is completing them — either because the backend is slow or because
  the proxy itself is saturated.
- This SLO does NOT page immediately; it feeds into the capacity planning workflow
  documented in Phase 86.

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
      # Uses ja4proxy_requests_total (renamed from ja4_requests_total — see §1.5).
      # Until renamed, substitute ja4_requests_total in the fallback expressions.
      # ja4proxy_connection_errors_total does not yet exist; add it per §1.5.
      # Until added, the denominator equals the numerator and the SLI reads as 1.0.
      - record: job:ja4proxy_availability:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_requests_total[5m]))
          /
          (
            sum(rate(ja4proxy_requests_total[5m]))
            + sum(rate(ja4proxy_connection_errors_total[5m]))
          )

      - record: job:ja4proxy_availability:ratio_rate1h
        expr: |
          sum(rate(ja4proxy_requests_total[1h]))
          /
          (
            sum(rate(ja4proxy_requests_total[1h]))
            + sum(rate(ja4proxy_connection_errors_total[1h]))
          )

      - record: job:ja4proxy_availability:ratio_rate6h
        expr: |
          sum(rate(ja4proxy_requests_total[6h]))
          /
          (
            sum(rate(ja4proxy_requests_total[6h]))
            + sum(rate(ja4proxy_connection_errors_total[6h]))
          )

      - record: job:ja4proxy_availability:ratio_rate3d
        expr: |
          sum(rate(ja4proxy_requests_total[3d]))
          /
          (
            sum(rate(ja4proxy_requests_total[3d]))
            + sum(rate(ja4proxy_connection_errors_total[3d]))
          )

      # ── Latency ─────────────────────────────────────────────────────────────
      # Uses ja4proxy_request_duration_seconds (renamed from ja4_request_duration_seconds
      # — see §1.5). Until renamed, substitute ja4_request_duration_seconds.
      # The le="0.01" bucket exists in the current histogram definition.
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
      # ja4proxy_redis_operations_total does not yet exist — add it per §1.5.
      # Until added, these recording rules return NaN; Redis correctness panels
      # in the dashboard will show no data until the metric is instrumented.
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
      # Uses ja4proxy_requests_total (renamed from ja4_requests_total — see §1.5).
      # Action label values: "blocked", "tarpitted", "rate_limited", "banned"
      # (full forms as stored in the metric, not short forms like "block"/"tarpit")
      - record: job:ja4proxy_false_positive_rate:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[5m]))
          / sum(rate(ja4proxy_requests_total[5m]))
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
          runbook_url: "docs/runbooks/slo_availability_runbook.md"

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
          runbook_url: "docs/runbooks/slo_availability_runbook.md"

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
          runbook_url: "docs/runbooks/slo_latency_runbook.md"

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
          runbook_url: "docs/runbooks/slo_latency_runbook.md"

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
          runbook_url: "docs/runbooks/slo_redis_correctness_runbook.md"

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
          runbook_url: "docs/runbooks/slo_redis_correctness_runbook.md"

  - name: ja4proxy_slo_false_positive
    rules:
      # §2.5 FP Rate SLO alert — fires when blocking rate > 2% at dial >= 50.
      # Suppressed by JA4proxyAttackCampaignDetected inhibit rule during attack windows.
      # NOTE: uses ja4proxy_requests_total (renamed from ja4_requests_total — see §1.5)
      # Action label values: "blocked", "tarpitted", "rate_limited", "banned"
      - alert: JA4proxyHighBlockingRate
        expr: |
          (
            rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[1h])
            / rate(ja4proxy_requests_total[1h])
          ) > 0.02
          and
          ja4proxy_dial_setting >= 50
        for: 5m
        labels:
          severity: warning
          slo: false_positive_rate
          team: security-ops
        annotations:
          summary: "JA4proxy blocking rate exceeds 2% — possible false positive spike"
          description: |
            Blocking rate is {{ $value | humanizePercentage }} over the last hour
            with dial at {{ $labels.dial_setting }}.
            This may indicate a misconfiguration, an overly aggressive dial setting,
            or a legitimate attack campaign.
          runbook_url: "docs/runbooks/slo_fp_rate_runbook.md"

      # §2.4 observation alert — fires at high block rates regardless of dial.
      # This is a broad-signal warning; the §2.5 alert is the actionable SLO alert.
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
          runbook_url: "docs/runbooks/slo_fp_rate_runbook.md"
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

## 6. On-Call Runbooks

Four runbook files — one per SLI plus one for the FP Rate SLO. Each follows the
same four-section structure used in existing runbooks under `docs/runbooks/`. The
`[FILL IN]` escalation placeholders must be replaced with org-specific contact
information before the phase is marked complete, but the diagnostic steps are
complete and actionable as written.

### 6.1 `docs/runbooks/slo_availability_runbook.md`

```markdown
# Runbook: JA4proxyAvailabilityBurnRateFast

**Alert fires when:** Availability SLI burn rate > 14.4 over a 1-hour window
(the error budget will exhaust in < 2 hours if not addressed).

## Alert trigger condition

```promql
job:ja4proxy_availability:burn_rate1h > 14.4
and
job:ja4proxy_availability:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

## Step 1 — Determine scope

```bash
# Which proxy nodes are affected?
curl -s http://localhost:8090/api/v1/health/deep | python3 -m json.tool
# Check all nodes if multi-instance:
for node in proxy-1 proxy-2 proxy-3; do
  echo "=== $node ==="; curl -s http://$node:8090/api/v1/health/deep | python3 -m json.tool
done
```

Any `"status": "degraded"` field identifies the failing component.

## Step 2 — Check error rate by category

In Grafana: SLO Overview dashboard -> Availability SLI panel -> drill down to
`ja4proxy_connection_errors_total` by `error_type` label.

Common causes and responses:
- `error_type="redis_timeout"`: Redis is slow/unavailable. See Redis failure runbook.
- `error_type="backend_refused"`: Backend is down. Escalate to backend team.
- `error_type="tls_parse_error"`: Parser bug or unusual TLS. Check recent deployments.
- `error_type="oom"`: Memory pressure. Check `ja4proxy_memory_bytes`, restart if needed.

Also check proxy logs for `event=connection_error` entries:
```bash
journalctl -u ja4proxy --since "10 minutes ago" -o json | \
  python3 -c "import sys,json; [print(l) for l in sys.stdin if 'connection_error' in l]"
```

## Step 3 — If a recent deployment is suspected

```bash
git log --oneline -5  # Check last 5 commits on main
# Roll back if needed:
docker-compose up -d --no-deps ja4proxy=<previous-tag>
```

## Step 4 — Escalate

- Severity `critical` (fast burn): page primary on-call: `[FILL IN]`
  The error budget expires in < 2 hours. If not resolved within 30 minutes, escalate.
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If unresolved after 30 minutes: escalate to `[FILL IN]`
```

### 6.2 `docs/runbooks/slo_latency_runbook.md`

```markdown
# Runbook: JA4proxyLatencyBurnRateFast

**Alert fires when:** More than 1% of connections are taking > 10ms, sustained
for > 5 minutes.

## Alert trigger condition

```promql
job:ja4proxy_latency_p99_good:burn_rate1h > 14.4
and
job:ja4proxy_latency_p99_good:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

## Step 1 — Check Redis latency

```bash
redis-cli --latency -h redis
# Expected: < 1ms. If > 5ms, Redis is the bottleneck.
```

Also check current p99 latency via Prometheus:
```bash
# Use current metric name (ja4_request_duration_seconds) until rename is applied:
curl -sg 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.99,rate(ja4_request_duration_seconds_bucket[5m]))' \
  | python3 -m json.tool
# After rename (ja4proxy_request_duration_seconds):
# curl -sg 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.99,rate(ja4proxy_request_duration_seconds_bucket[5m]))' \
#   | python3 -m json.tool
```

## Step 2 — Check signal collection times

In Grafana: per-signal latency panel. The slowest signals (AbuseIPDB, RDAP) are
fire-and-forget — they should not affect the hot path. If they do, check that
`asyncio.create_task()` is being used for these calls, not `await`.

Also check active connection count and tarpit saturation:
```bash
curl -sg 'http://localhost:9090/api/v1/query?query=ja4proxy_active_connections' \
  | python3 -m json.tool
curl -sg 'http://localhost:9090/api/v1/query?query=ja4proxy_tarpit_concurrent' \
  | python3 -m json.tool
```

If tarpit concurrent count > 400, it is near its 500-connection cap and consuming
resources that slow normal connection handling. Consider lowering
`tarpit_max_concurrent` to free resources.

## Step 3 — Check proxy CPU

If the Python proxy is CPU-bound (>80% single core), the GIL is the bottleneck.
Add a worker instance (HAProxy auto-distributes):
```bash
docker-compose up -d --scale ja4proxy=<current+1>
```

If the latency spike correlates with a recent deployment, roll back:
```bash
git log --oneline -5
docker compose up -d --no-build proxy  # reverts to previous image tag
```

## Step 4 — Check for connection storms

A sudden spike in new connections will push latency up. Check
`ja4proxy_requests_total` rate (renamed from `ja4_requests_total` — see §1.5)
— if it has spiked, the high latency may be transient as the proxy works through
the queue. Also check system-level metrics:
```bash
netstat -s | grep "receive buffer errors"
ss -s | grep "TCP:"
```

## Escalation

- Severity `critical` (fast burn): page primary on-call: `[FILL IN]`
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If unresolved after 30 minutes: escalate to `[FILL IN]`
```

### 6.3 `docs/runbooks/slo_redis_correctness_runbook.md`

```markdown
# Runbook: JA4proxyRedisCorrectnessBurnRateFast

**Alert fires when:** Redis operation error rate > 0.5% sustained.

This alert means the proxy is operating in degraded mode — bans, rate limits,
and enrichment decisions are unreliable. The proxy continues to forward traffic
(fail-open), but policy enforcement is weakened.

## Alert trigger condition

```promql
job:ja4proxy_redis_correctness:burn_rate1h > 14.4
and
job:ja4proxy_redis_correctness:burn_rate6h > 14.4
```

Slow-burn variant: `burn_rate6h > 6 and burn_rate3d > 1` (severity: warning).

## Step 1 — Assess Redis health

```bash
redis-cli INFO server | grep -E "redis_version|uptime_in_seconds|connected_clients"
redis-cli INFO stats | grep -E "rejected_connections|instantaneous_ops_per_sec"
redis-cli INFO memory | grep -E "used_memory_human|maxmemory_human"
```

Also check Redis connectivity from a proxy host:
```bash
redis-cli -h <redis-host> -p 6379 ping
```

## Step 2 — Check for memory pressure

If Redis `used_memory` is approaching `maxmemory`, Redis is evicting keys. The
proxy's `redis.maxmemory-policy` should be `allkeys-lru` (evicts least-recently-used
keys first). Verify:
```bash
redis-cli CONFIG GET maxmemory-policy
```

Check proxy logs for Redis error events:
```bash
journalctl -u ja4proxy --since "10 minutes ago" -o json | \
  python3 -c "import sys,json; [print(l) for l in sys.stdin if 'redis' in l.lower()]"
```

## Step 3 — Check connection pool exhaustion

A Redis connection pool that is full causes blocking waits, which appear as errors
in high-load scenarios. Check `ja4proxy_redis_pool_exhausted_total`. If the pool
is exhausted, increase `redis_pool_size` in `config/proxy.yml` and reload:
```bash
kill -HUP $(pgrep -f ja4proxy)   # or docker-compose kill -s HUP proxy
```

## Step 4 — Check network between proxy and Redis

```bash
redis-cli --latency -h redis -p 6379
# Sustained > 5ms indicates network or Redis disk I/O issues
```

If Redis is completely unreachable (ping fails), the proxy is in full fail-open
mode. No policy decisions involving Redis state are applying. Notify the security
team immediately: `[FILL IN]`

- Severity `critical` (fast burn): page primary on-call AND notify security team:
  `[FILL IN]`. Reason: policy enforcement is degraded.
- Severity `warning` (slow burn): file ticket assigned to `[FILL IN]`
- If Redis is down and cannot be recovered within 15 minutes: escalate to
  `[FILL IN]` and consider enabling a temporary static ACL via `config/proxy.yml`
  `static_ip_blocklist` as a manual fallback.
```

### 6.4 `docs/runbooks/slo_fp_rate_runbook.md`

```markdown
# Runbook: JA4proxyHighBlockingRate

**Alert fires when:** Blocking rate > 2% over the last 1 hour with dial >= 50.

This alert means either (a) there is a misconfiguration causing false positives,
(b) the dial is set too aggressively for the current traffic profile, or (c) there
is an ongoing attack campaign (in which case the alert should be inhibited — see below).

## Alert trigger condition

```promql
# Uses ja4proxy_requests_total (renamed from ja4_requests_total — see §1.5 of PHASE_63.md)
# Action label values: "blocked", "tarpitted", "rate_limited", "banned"
(
  rate(ja4proxy_requests_total{action=~"blocked|banned|tarpitted|rate_limited"}[1h])
  / rate(ja4proxy_requests_total[1h])
) > 0.02
and
ja4proxy_dial_setting >= 50
```

## Step 1 — Check whether an attack campaign is declared

If `JA4proxyAttackCampaignDetected` is also firing, the high blocking rate is
expected. The Alertmanager inhibit rule should have suppressed this alert; if it
did not, check the Alertmanager inhibit configuration.

```bash
curl -s http://localhost:9093/api/v2/alerts | \
  python3 -m json.tool | grep -A5 "JA4proxyAttackCampaignDetected"
```

If an attack is confirmed, silence this alert for the duration:
```bash
# In Alertmanager UI: create silence for JA4proxyHighBlockingRate for 4h
```

## Step 2 — Identify which action is driving the block rate

```bash
# Note: metric is ja4proxy_requests_total (renamed from ja4_requests_total)
curl -sg 'http://localhost:9090/api/v1/query?query=rate(ja4proxy_requests_total[5m])' \
  | python3 -m json.tool
```

In Grafana: SLO Overview dashboard -> Block Rate panel -> break down by `action` label.

- `action="blocked"` (JA4 blacklist, country, Spamhaus): check for recent blacklist
  changes. A bad entry added to the JA4 blacklist or a country blacklist change can
  instantly spike the block rate.
- `action="banned"`: check `ja4proxy_bans_active_total` — a mass ban event may have
  occurred (e.g., a scoring bug that over-bans).
- `action="rate_limited"`: check for a traffic surge from a single IP range.
- `action="tarpitted"`: check `ja4proxy_tarpit_concurrent`.

## Step 3 — Check for a recent dial change or config reload

```bash
redis-cli LRANGE management:policy_audit 0 9 | python3 -m json.tool
```

A recent dial increase (e.g., from 40 to 60) with an ill-calibrated threshold can
immediately start blocking legitimate traffic. If the dial was recently raised, lower
it back to the previous setting:
```bash
# Via management API:
curl -X PUT http://localhost:8090/api/v1/config/dial -d '{"value": 40}'
# Or via config file + SIGHUP:
# Edit config/proxy.yml: dial: 40
kill -HUP $(pgrep -f ja4proxy)
```

## Step 4 — Escalate

If the cause is identified and fixed, monitor for 15 minutes to confirm the blocking
rate drops below 2%.

If no cause is found within 20 minutes:
- Lower the dial to 0 (monitor mode) immediately to stop blocking legitimate traffic.
- Escalate to `[FILL IN]` with the time range and blocking rate.
- File a policy incident report describing the blocking window, volume of affected
  connections, and the dial setting at the time.

Severity: `warning`. This alert does not require an immediate page but does require
investigation within 30 minutes. If the blocking rate exceeds 10% (1 in 10 connections
blocked), treat as `critical` and page on-call.
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
- [ ] §2.5 FP Rate SLO exists with a numeric target (2% blocking rate) and an alert rule
- [ ] The `JA4proxyHighBlockingRate` alert exists in `slo_alerts.yml` with
      `ja4proxy_dial_setting >= 50` condition and `for: 5m`
- [ ] Alertmanager inhibit rule for `JA4proxyAttackCampaignDetected` exists in
      `slo_alerts.yml` to suppress FP rate alerts during declared attack windows
- [ ] §2.6 Throughput SLO exists with a connection growth alert rule
- [ ] All alerts include a `runbook_url` annotation pointing to a file that
      exists under `docs/runbooks/`
- [ ] `monitoring/grafana/dashboards/slo_overview.json` exists and is valid JSON
- [ ] SLO dashboard has three rows: current SLI stat panels, error budget time series,
      false positive rate with threshold line
- [ ] Stat panels for availability, latency, and Redis correctness show green above
      SLO target, yellow in the warning band, red below
- [ ] `docs/runbooks/slo_availability_runbook.md` exists with Step 1–4 diagnostic
      commands (not placeholder text)
- [ ] `docs/runbooks/slo_latency_runbook.md` exists with Step 1–4 diagnostic
      commands (not placeholder text)
- [ ] `docs/runbooks/slo_redis_correctness_runbook.md` exists with Step 1–4 diagnostic
      commands (not placeholder text)
- [ ] `docs/runbooks/slo_fp_rate_runbook.md` exists with Step 1–4 diagnostic
      commands and attack campaign inhibit instructions
- [ ] `make validate-slo-rules` target added to bottom of `Makefile` and runs without
      error against the delivered rule files
- [ ] `make slo-report` target added to bottom of `Makefile`
- [ ] Metric naming prerequisite (§1.5) addressed:
      - [ ] `ja4_requests_total` renamed to `ja4proxy_requests_total` in `proxy.py`
            and all referencing files
      - [ ] `ja4_request_duration_seconds` renamed to `ja4proxy_request_duration_seconds`
            in `proxy.py`; `le="0.01"` bucket confirmed present (it is — no bucket change
            needed)
      - [ ] `ja4proxy_connection_errors_total` counter added to `proxy.py`
            `handle_connection()` error handler
      - [ ] `ja4proxy_redis_operations_total` counter with `result="ok"` and
            `result="error"` labels added to all Redis call sites in `proxy.py` and `src/`
      - [ ] All of the above changes noted in `PHASE_63_notes.md`
- [ ] §9 SLO Review Cadence section exists and defines the 4-week baseline period
      and review process

---

## 9. SLO Review Cadence

### 9.1 Weekly Error Budget Check

Once per week, confirm that no error budget has been consumed in the preceding 7 days.
The check is automated via a Prometheus query:

```promql
# Is the 28-day availability error budget > 50% remaining?
job:ja4proxy_availability:budget_remaining28d > 0.5
```

If any error budget is below 50%, schedule a review before it exhausts.

### 9.2 First Deployment Baseline Period

SLO targets were set before the proxy was deployed at scale. The first 4 weeks of
production deployment constitute a baseline period. During this period:

- SLO alerts fire and are recorded, but do not require immediate on-call response.
- The observed SLI values are used to calibrate whether the targets are achievable
  (too tight) or unchallenging (too loose).
- After 4 weeks, the team reviews the baseline and adjusts SLO targets if needed.

The 99.9% availability target is conservative for a fail-open proxy — the proxy
itself rarely generates connection errors; errors usually come from Redis or backend
failures. If the observed availability is 99.99%, consider tightening to 99.95%.

If the observed p99 latency is consistently < 2ms, consider tightening the 10ms
latency SLO target to 5ms.

### 9.3 SLO Target Changes

SLO targets are not changed reactively (i.e., not because an alert is annoying).
They are changed after at least one full 28-day measurement period has passed, with
data showing the target is systematically unachievable or trivially easy to maintain.

SLO target changes are documented in an ADR (`docs/decisions/ADR-NNN.md`) with the
measurement data that motivated the change.
