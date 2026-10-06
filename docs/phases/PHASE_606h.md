# QUIC Initial Decoder Invariants & Coverage

## Goal
Implement property-based invariant test suites and expand statement coverage for JA4proxy's QUIC Initial packet decoding engine (`internal/quic/`). Elevate package coverage from 55.5% to $\ge 85\%$.

---

## Scope
1. **Target Package**: `internal/quic/` (`decoder.go`, `crypto.go`, `keylog.go`, `ja4q.go`).
2. **New Test Files**: `internal/quic/quic_invariant_test.go`.
3. **Key Invariants**:
   - `DecodeInitial` order-independence over CRYPTO frames.
   - Bounded LRU cache eviction via `ActiveCount` / `FlushEvicted`.
   - JA4Q regex grammar enforcement across mutated initial parameters.

---

## Test Strategy
- `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/quic -run '^TestInvariant_QUIC_'`

---

## Acceptance Criteria
- [ ] `internal/quic/quic_invariant_test.go` implemented and passing.
- [ ] `internal/quic` statement coverage $\ge 85\%$.
