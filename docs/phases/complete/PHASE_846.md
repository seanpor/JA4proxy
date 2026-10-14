# Phase 846: Go Proxy Core 90%+ Coverage, Invariant Hardening & Continuous Fuzzing

## Goal
Elevate the Go proxy core test suite (`internal/security`, `cmd/ja4pd`, `internal/server`, `internal/tls`) to **90%+ statement coverage**, implement mathematically sound property/invariant tests, and introduce comprehensive continuous fuzzing to make the production proxy bulletproof against adversarial attacks.

## Context & Motivation
As JA4proxy approaches feature completeness, the central proxy routing engine must meet the highest standard of test rigor. Currently:
- Overall Go test coverage is ~63.6%, with some components (like `cmd/ja4p`) showing misleading 0% statement coverage due to sub-process test execution.
- While individual modules (`internal/wizard` at 88.3%, `internal/tls` at ~85%) have strong unit test coverage, critical integration paths through `cmd/ja4pd/main.go`, `internal/server/forward.go`, and `internal/security/pipeline.go` have coverage gaps under complex fault conditions.
- Production transparent inline proxies require strict invariant verification:
  1. *Hard-Block Invariant*: A banned IP or CIDR block must never be forwarded, under any concurrency, load, or auxiliary outage.
  2. *Protocol Invariant*: Malformed TLS frames, smuggling attempts, and non-TLS bytes on TLS listeners must unconditionally fail-closed.
  3. *Resource Invariant*: Buffer pools and worker queues must be strictly bounded with zero leaks.

## Scope & Implementation Guardrails

### 1. In-Process Proxy & CLI Testing (Isolation & Concurrency Safety)
- Refactor `cmd/ja4pd/main.go` and `cmd/ja4p/main.go` to expose in-process entry points:
  `Run(ctx context.Context, cfg *config.Config, reg prometheus.Registerer, stdout, stderr io.Writer) error`
- **Isolation Guardrails to Prevent Process State Pollution:**
  - **Metric Registry Isolation:** Avoid global `prometheus.DefaultRegisterer`. Tests supply a dedicated `prometheus.NewRegistry()` per test instance to prevent `AlreadyRegisteredError` panics.
  - **Port Collision Prevention:** In-process test instances bind to dynamically allocated loopback ports (`:0`) or in-memory network pipes (`net.Pipe()`).
  - **Signal Isolation:** Dedicated signal channels passed via context or config; never hijack global `signal.Notify` during parallel test runs.
  - **Goroutine Leak Gate:** All in-process tests must register `defer goleak.VerifyNone(t)` to assert zero leaked background workers, tarpit goroutines, or drain handlers.

### 2. Invariant & Property-Based Testing
- Use `pgregory.net/rapid` or `testing/quick` with **structured generational grammars** (generating structurally valid TLS envelopes with mutated headers/payloads rather than purely uniform random noise) to verify:
  - Invariant 1: `IsBanned(ip) => Action == "block"` (Zero false negatives on bans).
  - Invariant 2: `IsMalformed(hello) => Dropped == true` (Zero leak on corrupted protocol frames).
  - Invariant 3: `NumAllocatedBuffers <= MaxConnections` (Zero memory leak).
- Enforce deterministic seed logging so any property failure prints an actionable reproduction command.
- Bound iteration counts ($N \le 500$ in standard CI) to keep runtime within seconds.

### 3. Continuous Native Go Fuzzing & Resource Bounds
- Add native fuzz targets (`go test -fuzz`):
  - `FuzzParseClientHello`: Mutated ClientHello byte streams (truncated extensions, oversized SNIs, GREASE ciphers, nested extensions).
  - `FuzzReassembleClientHello`: Multi-record TLS fragmentation fuzzing.
  - `FuzzPROXYProtocolV1V2`: PROXY protocol parsing with adversarial header lengths, binary TLVs, and local command injections.
  - `FuzzSecurityPipeline`: Concurrent connection contexts with randomized signal maps and threshold boundaries.
- **Resource Bounds & Fail-Closed Guardrails:**
  - Cap test input processing: if `len(data) > 64*1024`, reject immediately to prevent runner memory ballooning.
  - Clamped memory allocation: never allocate memory based on unverified lengths parsed from input payloads.
  - Time-box fuzzing in standard CI (`-fuzztime=30s`). Minify newly uncovered crash artifacts into `testdata/fuzz/` to run as deterministic unit tests.
  - **Zero Fail-Open Patches:** Any crash or panic identified by fuzzers must be remediated with explicit **FAIL-CLOSED** drops and metric increments, never silent catch-all suppresses.

### 4. Targeted Coverage Elevation to 90%+
- Add unit tests for uncovered branches in:
  - `internal/server/forward.go` (zero-window tarpit handling, half-close propagation, deadline expirations).
  - `internal/security/pipeline.go` (decision cache eviction, multi-DC sync edge cases, DNS enrichment timeout branches).

## Test Strategy
- Measure code coverage with `go test -coverprofile=coverage.txt ./...`.
- `internal/security`, `internal/tls`, and `internal/server` must achieve >= 90% statement coverage.
- Continuous fuzzing targets must run cleanly without panics or memory corruption.
- `goleak.VerifyNone(t)` must pass across all in-process tests.

## Acceptance Criteria
- [ ] Go proxy core packages (`internal/security`, `internal/tls`, `internal/server`) achieve >= 90% test coverage.
- [ ] Property/invariant test suite passing in CI with deterministic seeds.
- [ ] Native Go fuzz tests added with 30s CI budget and allocation bounds.
- [ ] `cmd/ja4pd` and `cmd/ja4p` coverage accurately reported > 85% via isolated `Run()` harnesses.
- [ ] Zero goroutine leaks verified via `goleak`.
