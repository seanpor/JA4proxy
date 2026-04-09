# Phase 63 — Implementation Notes

> Branch: `claude/phase-63-slos`
> Author agent: Claude (Opus 4.6)
> Date: 2026-04-09

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
