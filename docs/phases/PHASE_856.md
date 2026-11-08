<!--
title: Alertmanager & Prometheus Telemetry Integration Smoke Tests
audience: developer
last_reviewed: 2026-10-29
phase: 856
-->

# Alertmanager & Prometheus Telemetry Integration Smoke Tests

> **Size:** SMALL
> **Dependencies:** [855]
> **Branch:** `phase-856-telemetry-integration`

---

## Goal

Provide automated integration tests verifying that Prometheus metrics emitted by `cmd/ja4pd` (`internal/metrics`) and `cmd/ja4-tap` (`internal/tap/metrics.go`) adhere to OpenMetrics exposition standards, and that all Alertmanager recording and alert rules evaluate cleanly without label mismatches.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Uses standard `promtool` and Go unit test helpers (`internal/metrics/exposition_test.go`). Does not require running live external monitoring clusters.
- **Clear Bounds:** Focuses strictly on `deploy/monitoring/` rule completeness and `internal/metrics/` OpenMetrics validation.

---

## Scope

### In Scope
1. **Rule Validation Completeness**:
   - Ensure all rule files under `deploy/monitoring/alertmanager/rules/` and `deploy/monitoring/prometheus/` are tracked and validated cleanly by `make lint-observability` (`promtool check rules` and `amtool check-config`).
2. **OpenMetrics Invariant Suite (`internal/metrics/exposition_test.go`)**:
   - Iterate over registered collectors and metric families across `internal/metrics` and `internal/tap`:
     - Assert metric names follow Prometheus naming conventions (`^ja4proxy_[a-z0-9_]+$`).
     - Assert counter metrics end strictly with `_total`.
     - Assert metric descriptions (HELP strings) are non-empty.
     - Assert label names match `^[a-z_][a-z0-9_]*$`.
3. **Smoke Gate Integration**:
   - Integrated into `make test` / `make test-go`.

### Out of Scope
- Grafana dashboard layout edits or visual alerting routing setup.

---

## Acceptance Criteria
- [ ] Automated tests in `internal/metrics/exposition_test.go` verify OpenMetrics text exposition and naming standards across all proxy and tap metrics.
- [ ] Promtool and amtool linting passes cleanly across all rule files via `make lint-observability`.
- [ ] `go test ./internal/metrics/...` and `make preflight` pass 100% green.
