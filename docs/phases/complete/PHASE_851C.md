# Server Connection Saturation & Tarpit Bounding Benchmarks

## Goal
Establish high-concurrency benchmarks and capacity invariant tests for connection admission, listener overflow handling, and tarpit concurrency limits in `internal/server`. Guard against goroutine leaks, listener stalling, and unbounded memory consumption under aggressive connection floods.

## Scope
1. **Target Surface:** `internal/server` (`server.go`, `tarpit.go`, `forward.go`).
2. **Invariants to Verify:**
   - **Tarpit Concurrency Ceilings (JA4PROXY-2026-0013):** Global and per-IP tarpit limits (`maxConcurrent`, `maxPerIP`) must never be exceeded under concurrent load.
   - **Tarpit Overflow Action Invariance:** Under overflow conditions, connections must execute the configured action (`block` drops, `allow` forwards) without acquiring tarpit slots or leaking goroutines.
   - **Listener Loop Non-Blocking Invariance (JA4PROXY-2026-0119):** Admission check overflow and tarpit saturation must never block or stall the listener accept loop.
   - **Goroutine Bounding Under Load (JA4PROXY-2026-0009 / JA4PROXY-2026-0116):** Closed connections, aborted handshakes, and timeout expirations must cleanly release goroutines back to baseline.

## Implementation Plan
1. **Author Benchmark & Concurrency Suite:** Create `internal/server/saturation_bench_test.go`:
   - `BenchmarkTarpit_ConcurrentCapacity`: Measures throughput and allocation cost when tarpit slots are saturated.
   - `BenchmarkServer_AdmitConn_Throughput`: Measures admission throughput under connection floods.
   - `TestTarpit_StrictConcurrencyBounds`: Exercises concurrent goroutines attempting to enter tarpit, asserting that active tarpit slots never exceed configured caps.
   - `TestTarpit_OverflowBlockNoGoroutineLeak`: Asserts that rejected overflow connections terminate immediately without goroutine accumulation.
2. **Execution & Profiling:** Verify `go test -race -v -run TestTarpit_StrictConcurrencyBounds ./internal/server`.

## Test Strategy
- Unit tests & benchmarks run natively via Go toolchain.
- Race detector validation (`go test -race ./internal/server`).
- Full preflight gate (`make preflight`) validation.

## Acceptance Criteria
- [ ] `internal/server/saturation_bench_test.go` authored with concurrency tests and benchmarks.
- [ ] Concurrency assertions confirm active tarpit slots never exceed configured ceilings.
- [ ] Overflow handling runs without goroutine leaks.
- [ ] `make lint-phases` and `make preflight` pass 100% green.
