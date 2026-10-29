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

Provide automated integration smoke tests verifying that Prometheus metrics emitted by `cmd/ja4pd` and `cmd/ja4-tap` (`internal/metrics`) adhere to OpenMetrics exposition standards, and that all Alertmanager recording and alert rules evaluate without syntax errors or label mismatches.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Uses standard `promtool` and Go unit test helpers. Does not require running live external monitoring clusters.
- **Clear Bounds:** Focuses strictly on `deploy/monitoring/prometheus/` and `internal/metrics/`.

---

## Scope

### In Scope
1. **Rule Validation Automation (`make lint-observability`)**:
   - Verify all `.rules.yml` and `.yml` files in `deploy/monitoring/` pass `promtool check rules` and `amtool check-config`.
2. **OpenMetrics Invariant Suite (`internal/metrics/exposition_test.go`)**:
   - Assert all metric names follow Prometheus naming conventions (e.g. `_total` suffix on counters).
   - Assert metric descriptions (HELP strings) and labels are valid.
3. **Smoke Gate Integration**:
   - Integrated into `make test-unit`.

### Out of Scope
- Grafana dashboard layout edits or visual alerting routing setup.

---

## Acceptance Criteria
- [ ] Automated tests verify OpenMetrics text exposition and naming standards.
- [ ] Promtool and amtool linting passes cleanly across all rule files.
- [ ] `make test-unit` and `make preflight` pass 100% green.
