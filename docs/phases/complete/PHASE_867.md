---
phase: 867
title: "Deep Review & Architectural Audit of Performance Testing Harnesses"
status: IN_PROGRESS
size: MEDIUM
created: 2026-11-07
audience: [developer, operations, performance-engineering]
---

# Deep Review & Architectural Audit of Performance Testing Harnesses

## Goal

Conduct a comprehensive, ground-truth architectural review of all performance testing harnesses, load generators, micro/macro benchmarks, and metrics collection pipelines in JA4proxy. Identify critical protocol framing violations, verdict blindness (e.g. HTTP 403 treated as allowed connections), concurrency and queueing theory pathologies (Coordinated Omission, tick drops under Little's Law, ephemeral socket exhaustion in `TIME_WAIT`), inverted CI regression gates, and dead zombie scripts from the deleted Python proxy era. Deliver an actionable, high-fidelity modernization blueprint for future load, stress, and soak capabilities.

## Scope

1. **Exhaustive Inventory of All 24 Performance Components**:
   - **Go Micro-Benchmarks**:
     - `cmd/ja4pd/bench_test.go` (`BenchmarkPipeline_Allow`, `BenchmarkPipeline_Score`)
     - `internal/tls/bench_test.go` (`BenchmarkClientHelloParse`, `BenchmarkJA4Compute`, `BenchmarkClientHelloParseAdversarial`)
     - `internal/quic/bench_test.go` (`BenchmarkComputeJA4Q`, `BenchmarkParseClientHelloFeatures`, `BenchmarkParseCRYPTOFrames`, `BenchmarkDeriveInitialKey`, `BenchmarkDecryptInitial`)
     - `internal/server/saturation_bench_test.go` (`BenchmarkServer_AdmitConn`)
     - `internal/security/pentest_tranco_benchmark_test.go`, `internal/security/rule_fuzz_test.go`, `internal/security/event_payload_test.go`, `internal/security/tap_consumer_test.go`
     - `internal/cache/cache_fuzz_test.go`, `internal/tap/packet_fuzz_test.go`, `internal/webhook/dispatch_fuzz_test.go`, `internal/redis/pubsub_fuzz_test.go`
   - **Go Macro Load Generator**:
     - `internal/test/bench/ja4bench.go` & `cmd/ja4p/main.go` (`ja4p test benchmark`)
   - **Shell & Orchestration Scripts**:
     - `scripts/bench-hostnative.sh`, `scripts/run-benchmark.sh`, `scripts/basic_perf_test.sh`, `scripts/perf-matrix.sh`, `scripts/export_ci_benchmark_textfile.sh`
   - **Python Performance & Load Runners**:
     - `scripts/benchmark.py`, `scripts/benchmark_comparison.py`, `scripts/load_test.py`, `scripts/tls-traffic-generator.py`, `scripts/nightly_benchmark_gate.py`, `scripts/tap_benchmark.py`, `scripts/bench-tls-backend.py`
     - `tests/performance/test_bench_go_proxy.py`, `tests/performance/benchmark_phase26.py`, `tests/performance/benchmark_parallel_signals.py`
   - **CI & Makefile Targets**:
     - `.github/workflows/nightly-benchmark.yml`, `Makefile` (`bench`, `bench-micro`, `bench-macro`, `bench-hostnative`, `bench-all`, `test-go-perf`, `perf-test`)

2. **Protocol Fidelity, Concurrency & Queueing Theory Audit**:
   - **Protocol Framing & Wire Mismatch**: Audit `ja4bench.go` negotiating ALPN `h2` while transmitting raw ASCII HTTP/1.1 requests (RFC 7540 / RFC 9113 violations).
   - **Verdict Corruption**: Audit `res.Record` logic in `ja4bench.go` where HTTP 403 Forbidden responses are treated as allowed connections (`allowed=true`) because no socket transport error occurred.
   - **The Inverted `RateLimited` Gate Paradox**: Audit `ja4bench.go` setting `RateLimited` on achieving $\ge 90\%$ offered rate while `scripts/nightly_benchmark_gate.py` treats `rate_limited == true` as a CI failure.
   - **Coordinated Omission & Queueing Theory**: Apply Little's Law ($L = \lambda W$) and audit single-buffered `time.Ticker` tick-dropping behavior during proxy pauses, resulting in artificially truncated tail latency distributions (p95/p99 masking).
   - **Network Stack & Socket Exhaustion**: Analyze ephemeral port exhaustion ($T_{exhaust} = N_{ports} / \text{CPS}$) and Linux `TIME_WAIT` behavior under continuous connection churn.
   - **The Token-Bucket Lock Contention**: Audit `scripts/benchmark.py` where `time.sleep()` is held under `self.lock`, causing worker thread serialization.
   - **Mock Blindness & PGO Distortion**: Audit in-memory Redis stubs in micro-benchmarks and analyze how synthetic handshake-only profiles distort Go Profile-Guided Optimization (`default.pgo`).

3. **Zombie Artifact & Legacy Drift Taxonomy**:
   - Identify all dead scripts and tests comparing against the deleted Python proxy (`proxy.py`), importing deleted Python packages (`src.security.pipeline`, `src.tap.capture`), or binding obsolete ports (`18082`, `18080`, `8082`).

4. **Strategic Architecture Recommendations**:
   - Deliver a formal 6-dimension capabilities matrix (Micro-benchmarks, Connection Churn/CPS, Persistent Throughput/Data-plane, HTTP/2 Multiplexing, QUIC/UDP, Soak/Leaks).
   - Propose a sequenced, numbered implementation roadmap (Phases 868 through 871) for remediation.

## Implementation Plan

1. **Step 1 — Codebase Dissection & Forensic Inventory**:
   - Inspect all 24 performance components.
   - Author validation test `scripts/audit_harness_inventory.py` to ensure all 24 components are cataloged with validated classifications (`ACTIVE`, `ZOMBIE`, `FLAWED`, `BROKEN`).
2. **Step 2 — Controlled Benchmark Execution & Micro-Baseline Capture**:
   - Execute the entire Go micro-benchmark suite natively (`GOROOT=/snap/go/current go test -bench=. -run=^$ -benchmem ./...`) and tabulate real execution times (ns/op, B/op, allocs/op).
   - Verify Python scripts under containerized Python 3.15 runtime via explicit import assertions.
3. **Step 3 — Mathematical Derivations & Truthfulness Analysis**:
   - Calculate closed-loop maximum throughput bounds, Coordinated Omission impact, and `TIME_WAIT` exhaustion curves.
   - Document the `RateLimited` logic collision between `ja4bench.go` and `nightly_benchmark_gate.py`.
4. **Step 4 — Author the Definitive Performance Audit Report**:
   - Publish `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` satisfying all 10 strict acceptance criteria gates.
5. **Step 5 — Phase Close-Out Preparation**:
   - Commit news fragment in `docs/fragments/phase-867-performance-harness-review.md`.
   - Validate roadmap via `make lint-phases`, `make preflight`, and `bash scripts/close-phase.sh`.

## Test Strategy

- Go micro-benchmarks: native execution across all internal packages (`cmd/ja4pd/`, `internal/tls/`, `internal/quic/`, `internal/server/`, `internal/security/`, `internal/cache/`, `internal/tap/`, `internal/webhook/`, `internal/redis/`).
- Python container validation: runtime module import checks inside `ja4proxy-tools`.
- Audit script verification: automated validation script testing the completed report.

## Strict Acceptance Criteria Gates

| Gate ID | Area | Strict Acceptance Criterion | Precise Verification Command | Expected Output / Invariant |
|---|---|---|---|---|
| **GATE-1** | **Machine-Verified Exhaustive Inventory** | Every performance harness, benchmark file, script, and workflow (all 24 components across Go, Python, Shell, CI) is cataloged in `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` with: Path, Language, Target Component, Operational Status (`ACTIVE`, `ZOMBIE`, `FLAWED`, `BROKEN`), and Network Topology. Validated by automated inventory auditor. | `python3 -c "import re, os; f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); matches=re.findall(r'\| \x60([^\x60]+)\x60 \|', f); paths=[m for m in matches if '/' in m]; assert len(paths) >= 24, f'Found {len(paths)}'; [assert os.path.exists(p), f'Missing {p}' for p in paths]; print(f'Validated {len(paths)} components')"` | Exits 0; confirms $\ge 24$ valid files exist on disk and are formally cataloged. |
| **GATE-2** | **Mathematical Truthfulness & Queueing Proof** | `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` contains formal mathematical proofs and architectural analyses for: (1) Closed-loop throughput bound $\lambda_{max} = W / \bar{R}$, (2) Coordinated Omission percentile distortion, (3) Ephemeral port exhaustion $T_{exhaust} = N_{ports} / \text{CPS}$, and (4) `GoodBlocked` reachability under TCP RST vs HTTP 403. | `python3 -c "f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); reqs=['\\\\lambda', 'Coordinated Omission', 'TIME_WAIT', 'GoodBlocked', '403 Forbidden']; missing=[r for r in reqs if r not in f]; assert not missing, f'Missing proofs: {missing}'; print('Queueing proofs verified')"` | Exits 0; all 5 mathematical and protocol concepts formally derived and verified. |
| **GATE-3** | **Protocol & Inversion Collision Audit** | Audit explicitly analyzes: (1) ALPN `h2` negotiation paired with ASCII HTTP/1.1 wire requests in `ja4bench.go:320-336`, and (2) The `RateLimited` logic collision between `ja4bench.go:102` ($\ge 0.9 \times \text{Offered}$) and `nightly_benchmark_gate.py:82-86` (fails CI when true). | `python3 -c "f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); assert 'ALPN' in f and 'RFC 7540' in f and 'RateLimited' in f and 'nightly_benchmark_gate.py' in f; print('Protocol & inversion audit verified')"` | Exits 0; report documents wire protocol framing mismatch and CI inversion bug. |
| **GATE-4** | **Full Go Micro-Benchmark Baseline** | Execute all micro-benchmarks across all packages in the repository and record reproducible baseline metrics (ns/op, B/op, allocs/op) in the review report. | `GOROOT=/snap/go/current go test -bench=. -run=^$ -benchmem ./cmd/ja4pd/ ./internal/tls/ ./internal/quic/ ./internal/server/ ./internal/security/ ./internal/cache/ ./internal/tap/ ./internal/webhook/ ./internal/redis/` | Exits 0 across all 9 packages; tabular results populated in report. |
| **GATE-5** | **Legacy Zombie Code Audit** | Document concrete line numbers and files for all references to deleted `proxy.py`, obsolete ports (`18082`, `18080`, `8082`), deleted packages (`src.security.pipeline`, `src.tap.capture`), and lock-holding `time.sleep` in `scripts/benchmark.py`. | `python3 -c "f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); assert 'proxy.py' in f and '18082' in f and 'benchmark_comparison.py' in f and 'self.lock' in f; print('Zombie audit verified')"` | Exits 0; zombie artifacts explicitly identified with remediation targets. |
| **GATE-6** | **Runtime Container-Strict Verification** | Validate syntax and runtime module imports inside `ja4proxy-tools` (Python 3.15) for all active Python performance scripts. | `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools python3 -c "import scripts.load_test, scripts.nightly_benchmark_gate, tests.performance.test_bench_go_proxy; print('Container imports OK')"` | Exits 0; verifies container-strict importability without missing dependency failures. |
| **GATE-7** | **6-Dimension Capability Matrix** | Review report includes a structured evaluation matrix comparing current state vs production requirements across: (1) Micro-benchmarks, (2) Connection Churn / CPS, (3) Persistent Connection / Data Plane Throughput, (4) HTTP/2 Multiplexing, (5) QUIC / UDP, (6) Soak & Concurrency Leaks. | `python3 -c "f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); dims=['Micro-benchmarks', 'Connection Churn', 'Data Plane Throughput', 'HTTP/2 Multiplexing', 'QUIC / UDP', 'Soak & Concurrency Leaks']; missing=[d for d in dims if d not in f]; assert not missing, f'Missing dimensions: {missing}'; print('Capability matrix complete')"` | Exits 0; all 6 performance dimensions evaluated. |
| **GATE-8** | **Sequenced Modernization Roadmap** | Propose structured follow-up phases (Phases 868–871) detailing: Modernized Go load generator (`ja4bench` v2 with open-loop Poisson arrival & HTTP status parsing), zombie script deprecation, nightly CI gate realignment, and high-concurrency soak harness. | `python3 -c "f=open('docs/reports/PERFORMANCE_HARNESS_REVIEW.md').read(); assert 'Phase 868' in f and 'Phase 869' in f and 'Phase 870' in f and 'Phase 871' in f; print('Roadmap sequenced')"` | Exits 0; 4 distinct sequential follow-up phases defined. |
| **GATE-9** | **Manifest & Documentation Health** | Manifest tracks Phase 867; `make lint-phases` exits 0 with 0 violations; news fragment created under `docs/fragments/`. | `make lint-phases && test -f docs/fragments/phase-867-performance-harness-review.md && docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest tests/unit/test_changelog_fragments.py` | Exits 0; manifest passes and changelog fragment validation succeeds. |
| **GATE-10** | **Preflight Gate Cleanliness** | Codebase passes complete lint and test gates without regressions. | `make preflight` | `make lint`, `make scan`, and `make test` all exit 0. |

## Out of Scope

- Rewriting or deleting load generator implementations in this review phase (remediation will be executed in follow-up Phases 868 through 871).
- Multi-day live soak execution (harness architecture is audited; long soak execution runs belong to dedicated soak execution cycles).
