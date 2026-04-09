# Phase 63 — Implementation Notes

> Branch: `claude/phase-63-slos`
> Author agent: Claude (Opus 4.6)
> Date: 2026-04-09

## Review-fix addendum (post external SRE review, 2026-04-09)

External SRE/architect review returned `APPROVE WITH FIXES`. Three blockers
fixed in-branch:

1. **B1+B2 — `classifyConnError` collapsed three error sources into one
   label.** The previous switch returned `"redis_timeout"` for *any*
   `i/o timeout` or `context.DeadlineExceeded`, including client-side idle
   reads at `cmd/proxy/main.go:278` and backend dial timeouts at
   `cmd/proxy/main.go:413`. The Step-1 runbook query
   (`topk by (error_type)`) would have pointed on-call at Redis when the
   real cause was usually a client closing or upstream backend overload.
   **Fix:** `classifyConnError` now takes a `source` argument
   (`"client_read"` / `"backend_dial"` / `"redis"`) and returns a
   source-aware label. New label set: `client_read_timeout`,
   `client_read_error`, `backend_dial_timeout`, `backend_dial_error`,
   `backend_refused`, `redis_timeout`, `redis_error`, `connection_refused`,
   `oom`, `timeout`, `unknown`. Recording rules don't filter on
   `error_type` (they `sum()` everything), so the relabeling is backwards-
   compatible. The metric Help comment in `internal/metrics/metrics.go` was
   updated and the `slo_availability.md` runbook now has a label-meaning
   table and per-label diagnostic blocks.

2. **B3 — `tls_parse_error` was double-counted.** The TLS parse failure
   path at `main.go:324` incremented
   `ja4proxy_connection_errors_total{error_type="tls_parse_error"}` and
   then *fell through* to score the connection without a JA4, where it was
   ALSO counted in `ja4proxy_connections_total` (the SLI good term).
   Result: a single TLS parse failure counted as both good and bad, biasing
   the availability ratio optimistically. **Fix:** removed the increment.
   TLS parse failures are not availability errors — the connection is still
   handled and the policy pipeline still produces a decision. Spikes show
   up in `ja4proxy_signal_total` instead. Documented in the runbook.

3. **New unit test — `cmd/proxy/classify_conn_error_test.go`** with 14
   table-driven cases covering: nil, client-read timeout (real
   `net.OpError` with `Timeout()=true`), client-read deadline-exceeded,
   client-read generic error, backend timeout, backend connection refused,
   backend no-route, backend generic error, Redis timeout, Redis deadline-
   exceeded, Redis generic error, OOM, unknown-source timeout, unknown-
   source other. All pass.

Non-blocking findings addressed:

- **N9 (FP-rate alert asymmetry):** Added an inline comment to
  `JA4ProxyHighBlockRate` in `slo_alerts.yml` explaining why no `dial ≥ 50`
  guard is needed (the ratio collapses naturally at dial=0).
- **N4 (latency SLI scope):** already documented at `slo_latency.md:10`,
  no change required.
- **N1, N2, N3, N6, N7:** explicit deferrals; tracked below in the
  original "Deferred" section.

Tests: `GOROOT=/snap/go/current go test ./...` — all 17 Go packages pass.

## What landed

The four SLIs from PHASE_63.md are now computable end-to-end:

| SLI | Source metric (added by this phase) | Recording rule prefix |
|---|---|---|
| Availability | `ja4proxy_connection_errors_total{error_type}` | `job:ja4proxy_availability:` |
| Latency p99 < 10 ms | (existing) `ja4proxy_pipeline_duration_seconds_bucket{le="0.01"}` | `job:ja4proxy_latency_p99_good:` |
| Redis correctness | `ja4proxy_redis_operations_total{command,result}` | `job:ja4proxy_redis_correctness:` |
| FP rate | (existing) `ja4proxy_connections_total{action=~...}` | `job:ja4proxy_false_positive_rate:` |

## Cross-phase contract — Phase 64

The gauge `ja4proxy_tls_cert_expiry_timestamp_seconds` is **emitted by
Phase 63 and consumed by Phase 64**. Phase 64 owns the alert rule
(`tls_alerts.yml`) that fires on `now() - tls_cert_expiry_timestamp_seconds
> 30 days` and gates on `absent_over_time(...)` so the alert is safe to
land in either order.

The contract is:

- Metric name: `ja4proxy_tls_cert_expiry_timestamp_seconds`
- Type: `gauge`
- Unit: Unix epoch seconds (float64)
- Set by: `cmd/proxy/main.go::updateTLSCertExpiryGauge`, called from
  `main()` at startup and from `proxy.reload()` on every config reload.
- Source of cert path: env var `JA4PROXY_TLS_CERT_FILE` (PEM file). If
  the env var is empty the gauge is left at its default (0).
- Failure modes: file missing, PEM decode error, x509 parse error — all
  log a warning and leave the gauge unchanged.

If Phase 64 needs the cert path from a config field instead of an env
var, that change can be made additively without breaking this contract.

## Why env var instead of a config field

The Go production proxy is a passthrough proxy that does **not** terminate
TLS — there is no listener TLS cert in `internal/config`. Adding a new
config field would have required editing `internal/config/*.go`, which is
not in this phase's owned-files list. An env var is hot-reloadable in the
same way (re-read on SIGHUP via `proxy.reload()`) and keeps the change
strictly within the owned files.

## Files modified / created

Modified:
- `internal/metrics/metrics.go` — three new vars, registered.
- `internal/metrics/metrics_test.go` — five new tests.
- `internal/redis/client.go` — instrumented every method.
- `cmd/proxy/main.go` — `classifyConnError`, `updateTLSCertExpiryGauge`,
  three new instrumentation call sites, env-var read at startup and on
  reload.
- `Makefile` — added `validate-slo-rules`, `slo-report`, `test-phase-63`.
- `monitoring/prometheus/prometheus.yml` — added
  `slo_recording_rules.yml` to the `rule_files` list. (This file is not
  in the owned-files list but the spec mandates the addition; the change
  is one line and tightly scoped.)
- `CHANGELOG.md` — Phase 63 entry prepended.

Created:
- `internal/redis/client_metrics_test.go` — tests for the redis instrumentation.
- `monitoring/prometheus/slo_recording_rules.yml`
- `monitoring/alertmanager/rules/slo_alerts.yml`
- `docs/runbooks/slo_availability.md`
- `docs/runbooks/slo_latency.md`
- `docs/runbooks/slo_redis_correctness.md`
- `docs/runbooks/slo_fp_rate.md`
- `docs/phases/PHASE_63_notes.md` (this file)

## Deferred / not done

- **Grafana dashboard JSON** (`monitoring/grafana/dashboards/slo_overview.json`)
  was listed in the spec under Step 4, but the previous version of PHASE_63
  is referenced as the source of the panel JSON ("see git history"). That
  history was not available to this run, and inventing the panel JSON
  blind would create a maintenance burden. The recording rules and alerts
  are sufficient for SRE response; the dashboard can be added in a follow-up
  PR using the recording rules from Step 2 as the only data source.
- **Alertmanager inhibit rule for `JA4proxyAttackCampaignDetected`** — the
  spec adds this to `monitoring/alertmanager/alertmanager.yml`, which is
  outside this phase's owned files. The rule is documented in the
  `slo_fp_rate.md` runbook so the operator can add it manually until a
  future phase touches that file.
- `promtool` is not installed in the local sandbox — YAML structural
  validation only (the documented Phase 14e precedent).

## Test results

```
GOROOT=/snap/go/current go test ./...    # all packages PASS
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q
```

See the final report for full results.

## Verification

```bash
$ grep -r 'ja4proxy_connection_errors_total\|ja4proxy_redis_operations_total\|ja4proxy_tls_cert_expiry_timestamp_seconds' \
       internal/ cmd/ monitoring/ | wc -l
```

The three metric names appear in their definition file, the instrumentation
sites, both rule files, and the test files.
