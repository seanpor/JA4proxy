# Phase 36: Go Test Quality & Parity Gaps

## Overview

This phase addresses critical gaps in the Go test suite identified during the Phase 15 review. The Go implementation lacks proper test coverage for real-world certificate handling, cross-language parity verification, and fixture-based testing.

## Gaps Identified

### Gap 1: JA4 Fixture Parity Test Broken (Critical)

**Location:** `internal/tls/ja4_test.go:753-784`

**Issue:** The `TestJA4_FixturesParity` test has a **hardcoded empty expected map** instead of reading from the existing JSON fixture file (`tests/fixtures/clienthello/known_ja4.json`).

**Evidence:**
- Fixtures exist: `tests/fixtures/clienthello/*.bin` (4 binary fixtures)
- Expected JA4 values exist: `tests/fixtures/clienthello/known_ja4.json`
- Test incorrectly skips because `expected` map is empty in source code

**Impact:** The most important parity test (Go JA4 output vs Python JA4 output) never runs.

**Fix Required:**
1. Modify `TestJA4_FixturesParity` to read from `known_ja4.json` instead of using hardcoded map
2. Add path resolution to find fixtures relative to test file location

---

### Gap 2: JA4X Missing Real Certificate Tests (Critical)

**Location:** `internal/tls/ja4x_test.go`

**Issue:** The Go JA4X tests only test:
- Empty inputs
- Invalid DER bytes
- Pipeline integration (whitelist/blacklist)

**Missing:**
- Test with **real X.509 certificate** to verify JA4X hash computation works correctly
- No verification against known-good JA4X fingerprints from Python implementation
- No test comparing Go-extracted JA4X vs Python reference implementation

**Python Has:** `tests/unit/security/test_ja4x.py` generates real certs using `cryptography` library and verifies hash format.

**Fix Required:**
1. Add test with real DER-encoded certificate (can use hardcoded test cert or generate one)
2. Verify JA4X format: `{12hex}_{12hex}_{12hex}`
3. Add sentinel value verification for missing issuer/subject/SAN

---

### Gap 3: No Cross-Language JA4X Parity Test (Medium)

**Issue:** No integration test verifies Go JA4X matches Python JA4X for identical certificates.

**Python Has:** `tests/unit/security/test_ja4x.py` - unit tests with known certs

**Fix Required:**
1. Create test that parses same DER certificate in Go and Python
2. Verify hash outputs match exactly
3. Add to integration test suite `tests/integration/test_go_python_parity.py`

---

### Gap 4: JA4T, JA4S, JA4L, JA4H Fingerprints Not in Go (Medium)

**Issue:** Go implementation missing extended fingerprint family that Python has:

| Fingerprint | Python Location | Go Status |
|-------------|-----------------|-----------|
| JA4T | `internal/tls/ja4t_test.go` | Exists ✅ |
| JA4S | `tests/unit/tap/test_ja4s.py` | Missing |
| JA4L | `tests/unit/tap/test_ja4l.py` | Missing |
| JA4H | `tests/unit/tap/test_ja4h.py` | Missing |
| JA4SSH | `tests/unit/tap/test_ja4ssh.py` | Missing |

**Fix Required:**
1. Implement JA4S, JA4L, JA4H in Go
2. Add unit tests mirroring Python test coverage
3. Add integration parity tests

---

### Gap 5: Benchmark Coverage Gaps (Low)

**Location:** `internal/tls/bench_test.go`

**Current Benchmarks:**
- `BenchmarkClientHelloParse` - parsing
- `BenchmarkJA4Compute` - JA4 computation
- `BenchmarkClientHelloParseAdversarial` - adversarial inputs

**Missing:**
- No benchmark for JA4X extraction
- No benchmark for pipeline (full decision flow)
- No comparison benchmarks vs Python implementation
- No memory/allocation profiling

**Fix Required:**
1. Add `BenchmarkJA4X` benchmark
2. Add `BenchmarkPipeline` for end-to-end decision
3. Document baseline performance numbers

---

### Gap 6: Adversarial Test Coverage (Low)

**Location:** Various

**Issue:**
- TLS parser has adversarial tests (`TestParseClientHello_AdversarialInputs`)
- No equivalent adversarial fuzzing for JA4X extraction
- No fuzzing tests for pipeline decision logic

**Fix Required:**
1. Add fuzzing tests for JA4X with malformed certificates
2. Consider integrating with `go-fuzz` or similar

---

## Implementation Steps (TDD)

### Step 1: Fix Fixture Parity Test
- [ ] Modify `TestJA4_FixturesParity` to read JSON fixture file
- [ ] Verify test runs against existing 4 fixtures
- [ ] Add additional fixtures if needed

### Step 2: Add Real Certificate JA4X Tests
- [ ] Add test with hardcoded DER certificate
- [ ] Verify JA4X format correctness
- [ ] Test sentinel values for missing fields

### Step 3: Add Cross-Language JA4X Parity
- [ ] Add integration test comparing Go vs Python JA4X
- [ ] Document known-good test certificates

### Step 4: Extended Fingerprint Family (Optional)
- [ ] Implement JA4S, JA4L, JA4H in Go
- [ ] Add unit tests
- [ ] Add parity tests

### Step 5: Benchmark Coverage (Optional)
- [ ] Add JA4X benchmark
- [ ] Add pipeline benchmark
- [ ] Document baseline numbers

---

## Success Criteria

- [ ] `TestJA4_FixturesParity` runs and passes against all 4 fixtures
- [ ] Go JA4X tests include real certificate parsing
- [ ] Cross-language JA4X parity verified
- [ ] All Go tests pass: `GOROOT=/snap/go/current go test ./...`
- [ ] Zero skips due to missing fixtures (unless genuinely unavailable)

---

## Dependencies

- Phase 15 (completed) - Go rewrite with JA4X pipeline

---

## Notes

This phase improves confidence in Go implementation correctness by ensuring:
1. JA4 fingerprints match Python exactly (via fixtures)
2. JA4X extraction works with real certificates
3. Extended fingerprint family has parity across implementations
