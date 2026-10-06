# Cluster Sync Agent Tests

## Goal
Implement comprehensive unit and integration test suites for JA4proxy's distributed cluster state synchronization agent (`internal/cluster/sync`). Elevate package coverage from 0.0% to $\ge 80\%$.

---

## Scope
1. **Target Package**: `internal/cluster/sync`.
2. **New Test Files**: `internal/cluster/sync/agent_test.go`.

---

## Test Strategy
- `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/cluster/sync`

---

## Acceptance Criteria
- [ ] `internal/cluster/sync/agent_test.go` implemented and passing.
- [ ] `internal/cluster/sync` statement coverage $\ge 80\%$.
