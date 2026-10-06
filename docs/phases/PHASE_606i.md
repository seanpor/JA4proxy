# Cluster Sync Agent Tests

## Goal
Implement unit and integration test suites for JA4proxy's distributed cluster state synchronization agent (`internal/cluster/sync`). Elevate package coverage from 0.0% to $\ge 80.0\%$.

---

## Read These First
- `internal/cluster/sync/agent.go` (`Agent`, synchronization protocol, connection state)

---

## Verified API Surface
- `sync.NewAgent(...)` — `internal/cluster/sync/agent.go`
- `ja4proxy_sync_wan_connected` — `internal/metrics/metrics.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-CLUSTER-001` | Cluster Sync Message SerDe Parity | $\forall M, \quad \text{Unmarshal}(\text{Marshal}(M)) \equiv M$ | Prevents cluster state synchronization messages from being corrupted across node boundaries. |
| `INV-CLUSTER-002` | Disconnect Reconnection Monotonicity | $\text{Disconnect}() \implies \text{ReconnectAttempt}() \land \Delta\text{WANConnected} == 0$ | Ensures loss of WAN synchronization triggers automatic reconnection backoff without hanging node threads. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/cluster/sync/agent_test.go`
```go
package sync_test

import (
	"testing"

	clustersync "github.com/seanpor/ja4proxy/internal/cluster/sync"
)

func TestInvariant_Cluster_AgentInit(t *testing.T) {
	// Initialize agent harness and verify state...
	_ = clustersync.Agent{}
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-CLUSTER-001` | Swap payload fields in `Marshal` function | SerDe test fails equality check |
| `INV-CLUSTER-002` | Comment out reconnect loop on socket drop | Reconnection test detects stopped agent |

---

## Test Commands

- **Run Cluster Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/cluster/sync -run '^TestInvariant_Cluster_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/cluster/sync` Baseline:** 0.0%
- **Target Coverage:** $\ge 80.0\%$

---

## Acceptance Criteria

- [ ] `internal/cluster/sync/agent_test.go` created and passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 2.
- [ ] Package coverage verified $\ge 80.0\%$.
- [ ] News fragment created in `docs/fragments/phase-606i-cluster-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Management API routes (covered in Phase 606g).
