# Phase 63 — Service Level Objectives

> **Status:** PROPOSED
> **Size:** M
> **Owner files:** `monitoring/prometheus/slo_recording_rules.yml`, `monitoring/alertmanager/rules/slo_alerts.yml`, `monitoring/grafana/dashboards/slo_overview.json`, `internal/metrics/metrics.go` (three new metrics only), `internal/redis/client.go` (instrument), `cmd/proxy/main.go` (instrument), `docs/runbooks/slo_*.md`, `Makefile` (new targets only)
> **Independent of:** Phase 61, 62, 64 (Phase 64 alerts on a gauge this phase emits — see §1.3)
> **Last rewritten:** 2026-04-09

---

## What this phase is

Define four SLIs (availability, latency, Redis correctness, false positive
rate) for the **Go** production proxy, write the recording rules, the
multi-window multi-burn-rate alert rules, the Grafana SLO dashboard, and
four on-call runbooks. Add the three Prometheus metrics needed to compute
the SLIs.

## What this phase is NOT

This phase **does not** rename `ja4_*` metrics in `proxy.py`. The previous
version of Phase 63 had a "§1.5 Metric Naming Prerequisite" section that
spent half a page explaining how to rename `ja4_requests_total` to
`ja4proxy_requests_total` in the Python proxy. **All Go metrics already
conform to the `ja4proxy_*` prefix** — see `internal/metrics/metrics.go`.
The Python proxy is deprecated and its metric names are out of scope.

It also does not redesign the existing Grafana dashboards, the existing
recording rules in `monitoring/prometheus/recording_rules.yml`, or the
existing alert rules in `monitoring/alertmanager/rules/`. SLO files are
delivered as new sibling files alongside what already exists.

---

## What already exists on disk

Read first, before writing anything:

```bash
ls monitoring/prometheus/                   # prometheus.yml, recording_rules.yml exist
ls monitoring/alertmanager/rules/           # several .yml files from Phase 14e
ls monitoring/grafana/dashboards/           # several .json files
grep -nE 'ja4proxy_' internal/metrics/metrics.go | wc -l   # ~30 metrics, all prefixed
```

Key facts about the Go metric surface (`internal/metrics/metrics.go`):

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `ja4proxy_connections_total` | Counter | `action` | values: `allow`, `flag`, `rate_limit`, `tarpit`, `block`, `ban` — **short forms**, not `blocked`/`banned` |
| `ja4proxy_active_connections` | Gauge | — | |
| `ja4proxy_pipeline_duration_seconds` | Histogram | — | DefBuckets: includes `0.005, 0.01, 0.025, 0.05, ...` |
| `ja4proxy_dial_current` | Gauge | — | the dial value (0–100) |
| `ja4proxy_security_events_total` | Counter | `type` | |
| `ja4proxy_signal_total` | Counter | `name` | |

Three metrics this phase **adds** to `internal/metrics/metrics.go`:

1. `ja4proxy_connection_errors_total{error_type}` — counter for unhandled
   errors in the connection handler
2. `ja4proxy_redis_operations_total{command,result}` — counter for every
   Redis call, with `result="ok"` or `result="error"`
3. `ja4proxy_tls_cert_expiry_timestamp_seconds` — gauge of the listener TLS
   cert's `NotAfter` (Unix seconds). **Phase 64 depends on this gauge.**

These three are the only code edits this phase requires. Everything else
is YAML, JSON, and Markdown.

---

## Implementation checklist

### Step 1 — Add the three Prometheus metrics

Edit `internal/metrics/metrics.go`. Add the three vars below to the existing
`var (...)` block and add them to the `Register()` call list:

```go
ConnectionErrorsTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "ja4proxy_connection_errors_total",
        Help: "Unhandled errors in the connection handler before a policy decision",
    },
    []string{"error_type"}, // "redis_timeout", "tls_parse_error", "backend_refused", "oom", "unknown"
)

RedisOperationsTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "ja4proxy_redis_operations_total",
        Help: "Redis operations performed by the proxy",
    },
    []string{"command", "result"}, // result: "ok" or "error"
)

TLSCertExpiryTimestampSeconds = prometheus.NewGauge(
    prometheus.GaugeOpts{
        Name: "ja4proxy_tls_cert_expiry_timestamp_seconds",
        Help: "Listener TLS certificate NotAfter as a Unix timestamp",
    },
)
```

Instrument the call sites:

- **`cmd/proxy/main.go`** — in the connection-handler error path, call
  `metrics.ConnectionErrorsTotal.WithLabelValues(classify(err)).Inc()` where
  `classify(err)` maps an error to one of the five `error_type` values.
  A small inline `switch` is sufficient — do not introduce a new package.
- **`internal/redis/client.go`** — wrap each method (`Get`, `Set`, `ZAdd`,
  `Eval`, etc.) so that on success it calls
  `metrics.RedisOperationsTotal.WithLabelValues("get", "ok").Inc()` and on
  error calls `(.., "error").Inc()`. Do this in the existing thin wrapper
  layer; do not modify go-redis itself.
- **`cmd/proxy/main.go`** — at startup and on every config reload, parse
  the TLS cert from `tls_cert_file` and call
  `metrics.TLSCertExpiryTimestampSeconds.Set(float64(cert.NotAfter.Unix()))`.

Verify after the build:

```bash
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./internal/metrics/...
curl -s http://localhost:9090/metrics | grep -E '^ja4proxy_(connection_errors|redis_operations|tls_cert_expiry)'
```

### Step 2 — `monitoring/prometheus/slo_recording_rules.yml`

A new file (do not edit `recording_rules.yml`). Three groups, all on
1-minute interval. The recording rules implement Google SRE's multi-window
multi-burn-rate pattern.

```yaml
groups:
  - name: ja4proxy_slo_base
    interval: 1m
    rules:
      # ── Availability ─────────────────────────────────────────────────────
      # good = connections that reached a decision
      # bad  = connections that hit ConnectionErrorsTotal before a decision
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

      # ── Latency ──────────────────────────────────────────────────────────
      # The Go proxy uses ja4proxy_pipeline_duration_seconds with DefBuckets,
      # which includes le="0.01" — no histogram change is required.
      - record: job:ja4proxy_latency_p99_good:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_pipeline_duration_seconds_bucket{le="0.01"}[5m]))
          / sum(rate(ja4proxy_pipeline_duration_seconds_count[5m]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate1h
        expr: |
          sum(rate(ja4proxy_pipeline_duration_seconds_bucket{le="0.01"}[1h]))
          / sum(rate(ja4proxy_pipeline_duration_seconds_count[1h]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate6h
        expr: |
          sum(rate(ja4proxy_pipeline_duration_seconds_bucket{le="0.01"}[6h]))
          / sum(rate(ja4proxy_pipeline_duration_seconds_count[6h]))

      - record: job:ja4proxy_latency_p99_good:ratio_rate3d
        expr: |
          sum(rate(ja4proxy_pipeline_duration_seconds_bucket{le="0.01"}[3d]))
          / sum(rate(ja4proxy_pipeline_duration_seconds_count[3d]))

      # ── Redis correctness ────────────────────────────────────────────────
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
      # burn_rate = (1 - sli_ratio) / (1 - slo_target)
      # SLO targets: availability=0.999, latency=0.99, redis=0.995

      - record: job:ja4proxy_availability:burn_rate1h
        expr: (1 - job:ja4proxy_availability:ratio_rate1h) / 0.001
      - record: job:ja4proxy_availability:burn_rate6h
        expr: (1 - job:ja4proxy_availability:ratio_rate6h) / 0.001
      - record: job:ja4proxy_availability:burn_rate3d
        expr: (1 - job:ja4proxy_availability:ratio_rate3d) / 0.001

      - record: job:ja4proxy_latency_p99_good:burn_rate1h
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate1h) / 0.01
      - record: job:ja4proxy_latency_p99_good:burn_rate6h
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate6h) / 0.01
      - record: job:ja4proxy_latency_p99_good:burn_rate3d
        expr: (1 - job:ja4proxy_latency_p99_good:ratio_rate3d) / 0.01

      - record: job:ja4proxy_redis_correctness:burn_rate1h
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate1h) / 0.005
      - record: job:ja4proxy_redis_correctness:burn_rate6h
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate6h) / 0.005
      - record: job:ja4proxy_redis_correctness:burn_rate3d
        expr: (1 - job:ja4proxy_redis_correctness:ratio_rate3d) / 0.005

  - name: ja4proxy_slo_budget_remaining
    interval: 5m
    rules:
      - record: job:ja4proxy_availability:budget_remaining28d
        expr: |
          clamp_min(
            1 - ((1 - job:ja4proxy_availability:ratio_rate3d) * 28 / (28 * 0.001)),
            0
          )
      - record: job:ja4proxy_latency_p99_good:budget_remaining28d
        expr: |
          clamp_min(
            1 - ((1 - job:ja4proxy_latency_p99_good:ratio_rate3d) * 28 / (28 * 0.01)),
            0
          )
      - record: job:ja4proxy_redis_correctness:budget_remaining28d
        expr: |
          clamp_min(
            1 - ((1 - job:ja4proxy_redis_correctness:ratio_rate3d) * 28 / (28 * 0.005)),
            0
          )

      # FP-rate observation rule. Note: action label values are short forms in Go
      # (`block`, `ban`, `tarpit`, `rate_limit`) — not Python-style `blocked`/`banned`.
      - record: job:ja4proxy_false_positive_rate:ratio_rate5m
        expr: |
          sum(rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[5m]))
          / sum(rate(ja4proxy_connections_total[5m]))
```

Add the new file to `monitoring/prometheus/prometheus.yml`:

```yaml
rule_files:
  - "alerts.yml"
  - "recording_rules.yml"
  - "slo_recording_rules.yml"   # phase-63
```

### Step 3 — `monitoring/alertmanager/rules/slo_alerts.yml`

Two alert tiers per SLI: fast burn (`burn_rate1h > 14.4 AND burn_rate6h > 14.4`,
`for: 2m`, severity `critical`) and slow burn (`burn_rate6h > 6 AND
burn_rate3d > 1`, `for: 15m`, severity `warning`). Plus the FP-rate alerts.

```yaml
groups:
  - name: ja4proxy_slo_availability
    rules:
      - alert: JA4ProxyAvailabilityFastBurn
        expr: |
          job:ja4proxy_availability:burn_rate1h > 14.4
          and
          job:ja4proxy_availability:burn_rate6h > 14.4
        for: 2m
        labels: {severity: critical, slo: availability, burn_tier: fast}
        annotations:
          summary: "Availability SLO fast burn: error budget exhausting rapidly"
          description: "1h burn rate {{ $value | humanize }}× (threshold 14.4×)."
          runbook_url: "docs/runbooks/slo_availability_runbook.md"

      - alert: JA4ProxyAvailabilitySlowBurn
        expr: |
          job:ja4proxy_availability:burn_rate6h > 6
          and
          job:ja4proxy_availability:burn_rate3d > 1
        for: 15m
        labels: {severity: warning, slo: availability, burn_tier: slow}
        annotations:
          summary: "Availability SLO slow burn"
          runbook_url: "docs/runbooks/slo_availability_runbook.md"

  - name: ja4proxy_slo_latency
    rules:
      - alert: JA4ProxyLatencyFastBurn
        expr: |
          job:ja4proxy_latency_p99_good:burn_rate1h > 14.4
          and
          job:ja4proxy_latency_p99_good:burn_rate6h > 14.4
        for: 2m
        labels: {severity: critical, slo: latency, burn_tier: fast}
        annotations:
          summary: "Latency SLO fast burn: p99 budget exhausting"
          runbook_url: "docs/runbooks/slo_latency_runbook.md"

      - alert: JA4ProxyLatencySlowBurn
        expr: |
          job:ja4proxy_latency_p99_good:burn_rate6h > 6
          and
          job:ja4proxy_latency_p99_good:burn_rate3d > 1
        for: 15m
        labels: {severity: warning, slo: latency, burn_tier: slow}
        annotations:
          runbook_url: "docs/runbooks/slo_latency_runbook.md"

  - name: ja4proxy_slo_redis_correctness
    rules:
      - alert: JA4ProxyRedisCorrectnessFastBurn
        expr: |
          job:ja4proxy_redis_correctness:burn_rate1h > 14.4
          and
          job:ja4proxy_redis_correctness:burn_rate6h > 14.4
        for: 2m
        labels: {severity: critical, slo: redis_correctness, burn_tier: fast}
        annotations:
          summary: "Redis correctness SLO fast burn: policy enforcement degraded"
          description: "Bans, rate limits, and block lists may not apply. Fail-open is active."
          runbook_url: "docs/runbooks/slo_redis_correctness_runbook.md"

      - alert: JA4ProxyRedisCorrectnessSlowBurn
        expr: |
          job:ja4proxy_redis_correctness:burn_rate6h > 6
          and
          job:ja4proxy_redis_correctness:burn_rate3d > 1
        for: 15m
        labels: {severity: warning, slo: redis_correctness, burn_tier: slow}
        annotations:
          runbook_url: "docs/runbooks/slo_redis_correctness_runbook.md"

  - name: ja4proxy_slo_false_positive
    rules:
      # Action label values in the Go metric are short forms.
      - alert: JA4proxyHighBlockingRate
        expr: |
          (
            rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[1h])
            / rate(ja4proxy_connections_total[1h])
          ) > 0.02
          and
          ja4proxy_dial_current >= 50
        for: 5m
        labels: {severity: warning, slo: false_positive_rate, team: security-ops}
        annotations:
          summary: "JA4proxy blocking rate exceeds 2% — possible false positive spike"
          description: "Blocking rate {{ $value | humanizePercentage }} at dial >= 50."
          runbook_url: "docs/runbooks/slo_fp_rate_runbook.md"

      - alert: JA4ProxyHighBlockRate
        expr: job:ja4proxy_false_positive_rate:ratio_rate5m > 0.05
        for: 5m
        labels: {severity: warning, slo: false_positive_rate}
        annotations:
          summary: "Block rate >5%: potential FP wave or mass attack"
          runbook_url: "docs/runbooks/slo_fp_rate_runbook.md"
```

Add the inhibit rule for declared attack campaigns to the Alertmanager
config (`monitoring/alertmanager/alertmanager.yml`):

```yaml
inhibit_rules:
  - source_match:
      alertname: JA4proxyAttackCampaignDetected
    target_match:
      alertname: JA4proxyHighBlockingRate
    equal: ['job']
```

### Step 4 — `monitoring/grafana/dashboards/slo_overview.json`

Three rows: current SLI stat panels, error-budget timeseries, FP-rate
chart with a 5% threshold line. The dashboard queries only the recording
rules from Step 2 — never the raw histograms or counters. The full JSON
structure from the previous version of this phase is preserved verbatim
(see git history of this file at commit `<previous>` for the full panel
list); the only edit is updating the FP-rate panel target to use the
short-form action label values:

```promql
sum(rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[5m]))
/ sum(rate(ja4proxy_connections_total[5m]))
```

Datasource UID matches the existing Prometheus datasource defined in
`monitoring/grafana/provisioning/datasources/prometheus.yml`.

### Step 5 — Four runbooks

Create under `docs/runbooks/`. Each follows the four-step structure used
by existing runbooks. Hot-reload signals must use the production-correct
form for the deployment target — **never** `kill -HUP $(pgrep -f proxy.py)`,
which only worked for the deprecated Python proxy:

```bash
systemctl kill --signal=HUP ja4proxy.service     # systemd
docker kill --signal=HUP ja4proxy                # Docker Compose
podman kill --signal=HUP ja4proxy                # Podman/Quadlet
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1   # Kubernetes
```

Files to create:

- `docs/runbooks/slo_availability_runbook.md` — diagnose
  `ConnectionErrorsTotal` by `error_type`, check `/api/v1/health/deep`,
  inspect logs, roll back recent deploys
- `docs/runbooks/slo_latency_runbook.md` — `redis-cli --latency`, p99
  histogram query, active connection count, tarpit saturation, scale up
- `docs/runbooks/slo_redis_correctness_runbook.md` — `redis-cli INFO`,
  memory pressure, connection pool exhaustion, fail-open warning
- `docs/runbooks/slo_fp_rate_runbook.md` — check for declared attack,
  break down by action label, check `management:policy_audit`, dial
  rollback path

Each runbook ends with an Escalation section. Use `[FILL IN]` placeholders
for org-specific contact info — the orchestrator fills these in once.

### Step 6 — Makefile targets

Add to the bottom of `Makefile`:

```makefile
## Phase 63 targets — SLO validation and reporting

validate-slo-rules:
	promtool check rules monitoring/prometheus/slo_recording_rules.yml
	promtool check rules monitoring/alertmanager/rules/slo_alerts.yml
	@echo "SLO recording rules and alert rules are syntactically valid."

slo-report:
	@echo "=== JA4proxy SLO Report ==="
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_availability:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('Availability (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_latency_p99_good:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('Latency    (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
	@curl -sg 'http://localhost:9090/api/v1/query?query=job:ja4proxy_redis_correctness:ratio_rate5m' \
		| python3 -c "import sys,json; d=json.load(sys.stdin); v=d['data']['result']; print('Redis      (5m):', round(float(v[0]['value'][1])*100, 4) if v else 'NO DATA', '%')"
```

---

## SLO targets and error budgets

| SLI | Target | 28-day budget | Alert tier |
|---|---|---|---|
| Availability | 99.9% | 40 minutes of bad minutes | Burn-rate fast/slow |
| Latency (p99 < 10 ms) | 99% of connections | 1% of connections may exceed 10 ms | Burn-rate fast/slow |
| Redis correctness | 99.5% | ~72 minutes Redis-error time | Burn-rate fast/slow |
| FP rate | < 2% blocking rate at dial ≥ 50 | per-incident, no rolling budget | `JA4proxyHighBlockingRate` |

The 99.9% availability target is conservative for a fail-open proxy — most
errors propagate from Redis or backend, not the proxy itself. After the
4-week baseline period (§9), revisit the targets.

---

## SLO review cadence

### Weekly error-budget check

Once per week, confirm no error budget below 50%:

```promql
job:ja4proxy_availability:budget_remaining28d > 0.5
```

If any SLI drops below 50% remaining, schedule a review before exhaustion.

### First-deployment baseline (4 weeks)

The 4 weeks following first production deployment of the SLO rules is a
**baseline period**. Alerts fire and are recorded but do not require
immediate on-call response. After 4 weeks, review observed SLI values
and adjust targets if they are systematically too tight or trivially loose.

### SLO target changes

Target changes require an ADR (`docs/decisions/ADR-NNN.md`) with the
measurement data motivating the change. Targets are not changed reactively
because an alert is annoying.

---

## Acceptance criteria

- [ ] `internal/metrics/metrics.go` defines `ConnectionErrorsTotal`, `RedisOperationsTotal`, and `TLSCertExpiryTimestampSeconds`, registered in `Register()`
- [ ] `cmd/proxy/main.go` increments `ConnectionErrorsTotal` in the connection-handler error path with a classified `error_type` label
- [ ] `internal/redis/client.go` increments `RedisOperationsTotal{command,result}` on every Redis call
- [ ] `cmd/proxy/main.go` sets `TLSCertExpiryTimestampSeconds` at startup and on every config reload
- [ ] `curl -s http://localhost:9090/metrics` shows the three new metric names
- [ ] `monitoring/prometheus/slo_recording_rules.yml` exists and `promtool check rules` reports zero errors
- [ ] `monitoring/prometheus/prometheus.yml` includes `slo_recording_rules.yml` in `rule_files`
- [ ] All twelve base recording rules (3 SLIs × 4 windows) exist
- [ ] All nine burn-rate recording rules (3 SLIs × 3 windows) exist
- [ ] All three budget-remaining rules exist
- [ ] `monitoring/alertmanager/rules/slo_alerts.yml` exists and `promtool check rules` reports zero errors
- [ ] Six burn-rate alerts (fast + slow per SLI) defined
- [ ] `JA4proxyHighBlockingRate` alert exists with `ja4proxy_dial_current >= 50` and `for: 5m`
- [ ] `JA4ProxyHighBlockRate` (5% threshold observation alert) exists with `for: 5m`
- [ ] Alertmanager inhibit rule for `JA4proxyAttackCampaignDetected` → `JA4proxyHighBlockingRate` exists
- [ ] Every alert has a `runbook_url` annotation pointing to a file that exists in `docs/runbooks/`
- [ ] `monitoring/grafana/dashboards/slo_overview.json` exists, is valid JSON, has three rows
- [ ] FP-rate panel uses short-form action label values (`block|ban|tarpit|rate_limit`)
- [ ] All four runbooks exist with Step 1–4 diagnostic commands (no placeholder text in the diagnostic steps; placeholders permitted only in the Escalation section)
- [ ] Runbook hot-reload commands target the production deployment forms (systemd / docker / podman / kubectl), **not** `pgrep -f proxy.py`
- [ ] `make validate-slo-rules` and `make slo-report` targets added at the bottom of `Makefile`
- [ ] §"SLO review cadence" section preserved with the 4-week baseline period defined
- [ ] `CHANGELOG.md` entry written

## Verify

```bash
# 1 — metrics build and register
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./internal/metrics/...

# 2 — rules parse
promtool check rules monitoring/prometheus/slo_recording_rules.yml
promtool check rules monitoring/alertmanager/rules/slo_alerts.yml

# 3 — dashboard JSON parses
python3 -c 'import json; json.load(open("monitoring/grafana/dashboards/slo_overview.json"))'

# 4 — runbooks linked from alerts exist
grep -hE 'runbook_url:' monitoring/alertmanager/rules/slo_alerts.yml | \
  awk -F'"' '{print $2}' | xargs -I{} test -f {} && echo OK
```

---

## Out of scope — handed to other phases

| Concern | Phase that owns it |
|---|---|
| Renaming `ja4_*` metrics in `proxy.py` | **dropped — Python proxy is deprecated** |
| Alerting on `ja4proxy_tls_cert_expiry_timestamp_seconds` (cert expiry < 30 days) | [Phase 64](PHASE_64.md) §6.1 |
| Cross-DC SLI aggregation | [Phase 88](PHASE_88.md) |
| Capacity-planning consumers of the latency baseline | [Phase 86](PHASE_86.md) |

The `ja4proxy_tls_cert_expiry_timestamp_seconds` gauge is the **only**
cross-phase dependency in the 61–64 cluster. Phase 64's alert rule
(`tls_alerts.yml`) gates on `absent_over_time(...)` so the alert is safe
to land in either order.

If you find yourself editing `proxy.py` or any Python metrics file, stop —
that work was deliberately removed from this phase in the 2026-04-09 rewrite.
