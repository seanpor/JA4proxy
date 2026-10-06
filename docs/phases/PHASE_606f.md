# Security Scoring & Telemetry Conservation Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's security decision logic and Prometheus telemetry metrics (`internal/security`, `internal/metrics`, and `cmd/ja4pd`). Establish formal mathematical guarantees that action deciders enforce monotonic score and dial transitions, decision caches adhere strictly to capacity bounds, and the Telemetry Conservation Law holds across 100% of processed connections.

---

## Read These First
- `internal/security/action_decider.go` (`ActionDecider.Decide`)
- `internal/security/decision_cache.go` (`DecisionCache`)
- `internal/security/property_test.go` (existing Phase 62 property tests)
- `internal/metrics/metrics.go` (Prometheus counters and gauges)
- `cmd/ja4pd/main.go` (`handleConn` metric increment points)

---

## Verified API Surface
- `NewActionDecider(thresholds)` — `internal/security/action_decider.go:66`
- `(*ActionDecider).Decide(score, dial int)` — `internal/security/action_decider.go:66`
- `NewDecisionCache(limit, allowTTL, blockTTL)` — `internal/security/decision_cache.go`
- `ja4proxy_connections_accepted_total` — `internal/metrics/metrics.go`
- `ja4proxy_connections_total{action}` — `internal/metrics/metrics.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-SEC-001` | ActionDecider Score Monotonicity | $s_1 > s_2 \implies \text{Severity}(\text{Decide}(s_1, d)) \ge \text{Severity}(\text{Decide}(s_2, d))$ | Guarantees higher threat scores never result in weaker security enforcement actions. |
| `INV-SEC-002` | ActionDecider Dial Monotonicity | $d_1 > d_2 \implies \text{Severity}(\text{Decide}(s, d_1)) \le \text{Severity}(\text{Decide}(s, d_2))$ | Guarantees increasing safety dial values relaxes mitigation strictly monotonically. |
| `INV-SEC-003` | DecisionCache Capacity Upper Bound | $\text{CacheEntries} \le \text{Capacity}$ | Prevents high-cardinality IP scans from causing unbounded memory growth in decision caches. |
| `INV-TELEMETRY-001` | Telemetry Conservation Law | $\Delta\text{Accepted} \equiv \sum \Delta\text{ConnectionsTotal} + \sum \Delta\text{ConnectionErrors}$ | Guarantees zero silent connection drops; every accepted connection terminates in an audited outcome. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/security/scorer_invariant_test.go`
```go
package security_test

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/security"
	"pgregory.net/rapid"
)

var actionSeverity = map[string]int{
	"allow":    0,
	"tarpit":   1,
	"block":    2,
	"drop":     3,
}

func TestInvariant_Security_ActionDeciderScoreMonotonicity(t *testing.T) {
	decider := security.NewActionDeciderDefault()

	rapid.Check(t, func(t *rapid.T) {
		dial := rapid.IntRange(0, 100).Draw(t, "dial")
		score1 := rapid.IntRange(0, 100).Draw(t, "score1")
		score2 := rapid.IntRange(0, 100).Draw(t, "score2")

		if score1 > score2 {
			act1 := decider.Decide(score1, dial)
			act2 := decider.Decide(score2, dial)
			if actionSeverity[act1] < actionSeverity[act2] {
				t.Fatalf("Score monotonicity violated for dial %d: score %d gave %s, score %d gave %s",
					dial, score1, act1, score2, act2)
			}
		}
	})
}
```

### Step 2: Create `cmd/ja4pd/telemetry_invariant_test.go`
```go
package main

import (
	"net"
	"testing"
	"time"

	prometheus "github.com/prometheus/client_model/go"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func getCounterValue(counter metrics.CounterMetric) float64 {
	var m prometheus.Metric
	_ = counter.Write(&m)
	return m.GetCounter().GetValue()
}

func TestInvariant_Telemetry_ConservationLaw(t *testing.T) {
	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()
	cfg.Proxy.Upstream = echoAddr

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go p.serveOnListener(listener)

	// Baseline telemetry snapshot
	accepted0 := getCounterValue(metrics.ConnectionsAcceptedTotal)

	// Send 50 mixed connections
	hello := tlsfixture.Build(tlsfixture.Spec{})
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			continue
		}
		_, _ = conn.Write(hello)
		_ = conn.Close()
	}

	time.Sleep(200 * time.Millisecond)

	accepted1 := getCounterValue(metrics.ConnectionsAcceptedTotal)
	deltaAccepted := accepted1 - accepted0

	if deltaAccepted != 50 {
		t.Fatalf("Telemetry conservation violated: expected 50 accepted connections, got %f", deltaAccepted)
	}
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-SEC-001` | Swap block and tarpit threshold checks in `action_decider.go` | Score monotonicity test fails severity comparison |
| `INV-SEC-002` | Reverse dial logic operator in `action_decider.go` | Dial monotonicity test fails severity comparison |
| `INV-SEC-003` | Comment out LRU eviction call in `decision_cache.go` | Capacity upper bound test detects size exceeding capacity |
| `INV-TELEMETRY-001` | Comment out `ConnectionsAcceptedTotal.Inc()` in `cmd/ja4pd/main.go` | Conservation law test detects missing accepted counts |

---

## Test Commands

- **Run Security Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/security -run '^TestInvariant_Security_'`
- **Run Telemetry Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4pd -run '^TestInvariant_Telemetry_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/security` Baseline:** 90.6%
- **Target Coverage:** $\ge 95.0\%$

---

## Acceptance Criteria

- [ ] Invariant test files created and all 4 invariants passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package `internal/security` coverage verified $\ge 95.0\%$.
- [ ] Mutation check table verified.
- [ ] News fragment created in `docs/fragments/phase-606f-security-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Management API authorization (covered in Phase 606g).
- Redis sliding-window metrics (covered in Phase 606d).
