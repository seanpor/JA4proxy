# TLS Hot-Path Zero-Allocation & Strict Allocation Budget Enforcement

## Goal
Establish strict memory allocation budgets and zero-allocation assertions for high-throughput TLS parsing and JA4 computation on the Go proxy connection hot path. Guard against memory bloat and garbage collection latency spikes under high connection rates.

## Scope
1. **Target Surface:** `internal/tls` (`parser.go`, `ja4.go`, `hello_info.go`).
2. **Allocation Characterization:** Profile existing allocations in `ParseClientHello` (currently ~8 allocs/op, 464 B/op) and `ComputeJA4` (currently ~41 allocs/op, 864 B/op).
3. **Allocation Reduction / Pooling:**
   - Optimize slice allocations during ClientHello extension parsing and cipher suite extraction.
   - Reuse buffers or utilize stack-allocated scratch space where possible.
4. **Automated Budget Gate:**
   - Add unit/benchmark tests asserting hard upper limits on `allocs/op` (e.g. `testing.AllocsPerRun`).
   - If a future change introduces extraneous heap allocations to `ParseClientHello` or `ComputeJA4`, test fails in standard `go test`.

## Implementation Plan
1. **Characterization Tests:**
   - Write `TestParseClientHello_AllocBudget` and `TestComputeJA4_AllocBudget` asserting current upper bounds.
2. **Hot-Path Optimization:**
   - Eliminate unnecessary string/slice allocations in `parseExtensions` and `formatJA4`.
   - Use stack arrays or a sync.Pool for extension ID collection when slice size is small (standard TLS handshakes).
3. **Budget Hardening:**
   - Lock down tight thresholds: `ParseClientHello` <= 3 allocs/op (or 0 for reusable buffer parser), `ComputeJA4` <= 15 allocs/op.
4. **Verification:**
   - Ensure all existing TLS tests (`ja4_test.go`, `parser_test.go`, `invariant_test.go`, fuzz tests) remain 100% green.
   - Run benchmarks to verify latency reduction and reduced GC pressure.

## Test Strategy
- `internal/tls/alloc_budget_test.go`: Use `testing.AllocsPerRun` to measure allocations across 1,000 iterations with standard browser fixtures (Chrome, Firefox, Safari, Bot).
- Full regression suite `go test -race ./...` to guarantee thread safety is preserved.

## Acceptance Criteria
- `alloc_budget_test.go` added and passing.
- Allocation count per handshake parsing reduced or strictly bounded by test assertions.
- Zero regressions in existing JA4 fingerprint computation accuracy (tested against corpus).
- `make preflight` passes 100% green.

## Out of Scope
- Proxy protocol smuggling logic (handled in Phase 851b).
- Server connection pooling (handled in Phase 851c).
