# Phase 15 Detailed Work Plan: Go Rewrite Improvements

## 1. Overview
Phase 15 successfully ported the core proxy to Go, delivering 10-50x throughput improvements. This work plan addresses the remaining "additive improvements" identified in `PHASE_15c.md` to achieve full feature parity with Python.

## 2. Implementation Steps (TDD)

### Step 1: Lua Script Embedding
**Goal:** Prevent runtime file-read failures and simplify the compiled binary.
*   **Task:** Refactor `internal/redis/lua.go` to use Go's `//go:embed` directive instead of `os.ReadFile`.
*   **Action:** Move `sliding_window.lua` into the `internal/redis/` package (or reference its path correctly relative to the go file).
*   **TDD:** 
    1. Write a test `TestLuaScriptLoaded` that asserts the embedded script string is not empty.
    2. Implement the embed directive.
    3. Verify tests pass.

### Step 2: JA4X Implementation in Go
**Goal:** Bring the Go proxy to full parity with Phase 16 (which added JA4X to Python).
*   **Task:** Implement JA4X (X.509 certificate fingerprinting) in `internal/security/ja4x.go`.
*   **Algorithm:** Extract the leaf certificate from the TLS record, calculate SHA-256 hashes of the issuer, subject, and SAN. Format: `{issuer_hash}_{subject_hash}_{san_hash}`.
*   **TDD:** 
    1. Copy test certificates from Python's `tests/unit/security/test_ja4x.py` to Go's test fixtures.
    2. Write `TestExtractJA4X` verifying hashes match known outputs.
    3. Implement `ja4x.go`.

### Step 3: Go Pipeline Integration
**Goal:** Wire JA4X into the Go scoring pipeline.
*   **Task:** Update `internal/security/pipeline.go` to populate `JA4X` in the connection context.
*   **Task:** Implement JA4X whitelist/blacklist bypass checks.
*   **TDD:** Update `../../internal/security/pipeline_test.go` to inject a blocked JA4X fingerprint and verify the connection is dropped/scored accordingly.

## 3. Validation
*   Run the full Go test suite: `go test -v -race -cover ./...`
*   Verify no performance regressions by running `go test -bench . ./internal/...`.