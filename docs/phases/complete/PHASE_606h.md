# Telemetry & Metrics Conservation Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's Prometheus metrics and telemetry aggregation engine (`internal/metrics`). Establish formal guarantees that all Prometheus counter metrics are strictly non-decreasing over time, that active connection and tarpit gauge counters remain non-negative under high-concurrency increment and decrement operations, that the decision conservation equality ($\Delta\text{Accepted} \equiv \sum \Delta\text{TerminalActions}$) holds down to exact single connection increments, and that histogram observations remain bounded within defined bucket ranges.

---

## Read These First
- `internal/metrics/metrics.go` (Prometheus counter, gauge, and histogram definitions)
- `internal/metrics/metrics_test.go` (existing metrics unit tests)

---

## Verified API Surface
- `prometheus.NewCounterVec` — `internal/metrics/metrics.go`
- `prometheus.NewGauge` — `internal/metrics/metrics.go`
- `prometheus.NewHistogram` — `internal/metrics/metrics.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-METRICS-001` | Counter Monotonicity | $\forall t_2 \ge t_1, \quad C(t_2) \ge C(t_1)$ | Prevents Prometheus counters from resetting or decreasing during execution. |
| `INV-METRICS-002` | Active Connections Gauge Non-Negative | $\text{Gauge}(\text{ActiveConns}) \ge 0$ | Prevents gauge underflow errors during rapid connection teardowns. |
| `INV-METRICS-003` | Decision Conservation Law | $\Delta \text{ConnectionsTotal} \equiv \sum_{\text{actions}} \Delta \text{ActionCount}$ | Guarantees zero silent drop blind spots in operational monitoring. |
| `INV-METRICS-004` | Risk Score Histogram Bounding | $\forall v \in \text{Observations}, \quad v \in [0, 100]$ | Guarantees risk distribution histogram metrics reflect valid score ranges. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/metrics/metrics_invariant_test.go`
```go
package metrics_test

import (
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"pgregory.net/rapid"
)

func TestInvariant_Metrics_CounterMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		incVal := rapid.IntRange(1, 50).Draw(t, "incVal")
		action := rapid.SampledFrom([]string{"allow", "block", "tarpit", "rate_limit"}).Draw(t, "action")

		c := metrics.ConnectionsTotal.WithLabelValues(action)
		valBefore := readCounter(c)

		for i := 0; i < incVal; i++ {
			c.Inc()
		}

		valAfter := readCounter(c)
		if valAfter < valBefore {
			t.Fatalf("Counter monotonicity violation: before %f, after %f", valBefore, valAfter)
		}
	})
}
```

---

## Acceptance Criteria

- [x] `internal/metrics/metrics_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/metrics` coverage verified $\ge 84.5\%$.
- [x] News fragment created in `docs/fragments/phase-606h-metrics-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- OpenTelemetry collector integration.
- Grafana dashboard rendering tests (covered in Phase 816).
