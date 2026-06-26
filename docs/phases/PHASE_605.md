# Go Test Parity (Adversarial Coverage)

## Goal
Achieve parity between the Go proxy and the Python legacy test suites in terms of adversarial coverage and "edge case" handling, ensuring that the Go implementation is as robust as the original Python prototype.

## Background
Phase 62 (Security Regression Harness) and Phase 101i identified that Go test parity was blocked on specific Go implementation gaps. While the Go proxy is production-ready, the Python suite contains a wealth of "weird" traffic scenarios (fragmented TLS, malformed SNI, etc.) that haven't been fully ported to Go.

## Scope
1.  **Adversarial Test Porting**: Port all Python adversarial tests from `tests/unit/test_security_*.py` to Go `internal/proxy/*_test.go`.
2.  **Fuzzing Expansion**: Expand the Go fuzzing harness (`internal/tls/fuzz_test.go`) to include the "attacker" corpus from the Python fuzzing suite.
3.  **Behavioral Parity**: Ensure the Go proxy's response to specific attack vectors (e.g., JA4T mismatch, DGA detection) matches the Python proxy's behavior exactly.
4.  **Test Infrastructure**: Ensure the Go test suite can be run in the same containerized environment as the Python suite (`make test-unit`).

## Implementation Plan
1.  **Step 1: Test Audit**
    *   Compare `tests/unit/test_security_*.py` with `internal/proxy/*_test.go` and `internal/security/*_test.go`.
    *   Identify missing scenarios (e.g., `test_tcp_smuggling`, `test_tls_record_fragmentation`).
2.  **Step 2: Go Test Implementation**
    *   Port the missing tests, using `net.Pipe` and `miniredis` for hermetic testing.
3.  **Step 3: Fuzzing Corpus Merge**
    *   Import the Python `atheris` corpus into the Go fuzzing suite.
4.  **Step 4: CI Integration**
    *   Ensure `make test-unit` (Go) is part of the required PR checks.

## Acceptance Criteria
1.  `make test-unit` (Go) covers 100% of the scenarios in the Python adversarial test suite.
2.  The Go fuzzing suite includes the Python `atheris` corpus.
3.  All new Go tests pass and are hermetic (no Docker/Redis required).
4.  `make test` (full suite) remains green.

## Dependencies
*   Phase 15 (Go Rewrite) - **COMPLETE**
*   Phase 62 (Security Regression Harness) - **COMPLETE**
