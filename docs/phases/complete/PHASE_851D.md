# Phase 851d: Security Filter Rule Evaluation Fuzzing & Invariants

## Goal
Implement native Go fuzz testing (`testing.F`) and rapid property-based invariant test suites for `internal/security` rule evaluation, matcher totality, and verdict determination. Guarantee that malformed or adversarial rule definitions, metadata inputs, and policy trees cannot induce panics, evaluation crashes, infinite loops, or unexpected fail-open actions.

## Scope
- Author `internal/security/rule_fuzz_test.go` with Go native fuzz tests (`testing.F`) targeting:
  - Policy rule evaluation (`CheckBypasses`, `CheckHardBlocks`, `Score`, `Decide`).
  - SNI sanitization and DGA scoring algorithms.
  - Threat feed / CIDR line parsing totality (`BuildRanger`).
- Property-based tests verifying deterministic evaluation, rule monotonicity invariants, and strict fail-closed/default-action fallback behaviors.
- Benchmarks for high-throughput rule evaluation under saturated and worst-case rule trees.

## Implementation Details
1. **Rule Evaluation & Component Fuzzing:**
   - `FuzzSNIAnalyzer`: Fuzzes arbitrary SNI hostnames, long labels, unprintable ASCII, and invalid domain structures; verifies score bounds `[0, 100]` and `dgaConfidence` bounds `[0.0, 1.0]`.
   - `FuzzBuildRanger`: Fuzzes `cidr`, `ipset`, and `spamhaus` line parsers against corrupt prefixes, oversized lines, and invalid CIDR masks; guarantees parser totality with zero panics.
   - `FuzzEffectiveThresholdAndDecider`: Fuzzes `EffectiveThreshold` and `ActionDecider.Decide` across extreme integers; ensures monitor mode (`dial=0`) strictly produces `allow`.
   - `FuzzRiskScorer`: Fuzzes weighted signal aggregation; verifies `TotalScore` clamping `[0, 100]` and deterministic action derivation.
   - `FuzzPipelineBypassesAndHardBlocks`: Fuzzes `CheckBypasses` and `CheckHardBlocks` with corrupted IPs, JA4/JA4X fingerprints, ALPNs, and country codes; ensures non-empty reasons on match and zero panics.
2. **Rapid Property-Based Invariant Tests:**
   - `TestProperty_ActionDecider_Monotonicity`: Proves that increasing risk scores strictly results in non-decreasing action severity across arbitrary dial values.
   - `TestProperty_RiskScorer_Clamping`: Proves that `TotalScore` is bounded in `[0, 100]` regardless of negative, zero, or extreme signal weights and scores.
3. **Smoke Fuzz Target Integration:**
   - Added all 5 new fuzz targets to `make test-go-fuzz-smoke` in `Makefile`.

## Performance Benchmarks
Measured on Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz:
- `BenchmarkPipelineCheckBypasses`: **2.82 ns/op** (0 B/op, 0 allocs/op) — over 350M bypass evaluations/sec.
- `BenchmarkCounterfactuals`: **247.1 ns/op** (0 B/op, 0 allocs/op) — zero-alloc dial sensitivity sweep.
- `BenchmarkRuleEvaluation`: **935.3 ns/op** (648 B/op, 16 allocs/op) — composite signal scoring and decision.
- `BenchmarkSNIAnalyzer`: **1066 ns/op** (331 B/op, 3 allocs/op) — full RFC validation and DGA analysis.

## Security & Reliability Assessment
- **Fuzzing Results:** Over 500,000 generated inputs executed with 0 panics, 0 crashes, and 0 memory corruption instances.
- **Fail-Open / Fail-Closed Verification:** Malformed CIDRs, unparsable IPs, and corrupted JA4 strings are safely rejected or processed without invalid privilege escalations.
- **Thread Safety:** All new fuzz and property test cases pass under `go test -race`.

## Acceptance Criteria
- [x] `internal/security/rule_fuzz_test.go` exists with 5 native Go fuzz targets and 2 Rapid property tests.
- [x] All fuzz tests execute cleanly under `go test -fuzz`.
- [x] All property tests pass 100 iterations.
- [x] Benchmarks added and characterized in documentation.
- [x] `make test-go-fuzz-smoke` updated.
- [x] `make preflight` exits 0.
