<!--
title: High-Concurrency Soak & Resource Leak Verification
audience: developer
last_reviewed: 2026-10-29
phase: 854
-->

# High-Concurrency Soak & Resource Leak Verification

> **Size:** SMALL
> **Dependencies:** [853]
> **Branch:** `phase-854-concurrency-soak-testing`

---

## Goal

Provide automated tooling and regression tests to verify that the Go proxy (`cmd/ja4pd`) and TAP sensor (`cmd/ja4-tap`, `internal/tap`) do not suffer from memory leaks, file descriptor leaks, or goroutine accumulation under sustained connection churning and continuous high-concurrency traffic.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL (with bounded, containerized harness and build tag)**.
- **Why it fits:** Rather than an unbounded multi-day soak test requiring dedicated bare-metal clusters (which would be COMPLEX / LARGE), Phase 854 defines a deterministic, time-bounded (60s) leak verification test in Go using `go.uber.org/goleak` and deterministic resource cleanup checks.
- **Protection Against CI Slowdowns:** Both test suites use the `//go:build soak` directive so normal `make test` runs in seconds. The dedicated target `make test-soak` executes the soak harness on demand or in nightly CI.
- **Junior Dev Friendliness:** Clear boundaries, standard Go testing tools (`testing.T`, `goleak`, and sub-process load generation), and no non-deterministic percentage thresholds.

---

## Scope

### In Scope
1. **Proxy Goroutine Leak Invariant Suite (`cmd/ja4pd/soak_leak_test.go`)**:
   - Gated with `//go:build soak`.
   - Wrap client-server connection lifecycles with `defer goleak.VerifyNone(t)`.
   - Verify that 1,000 rapidly opened and abruptly aborted/rst TCP/TLS handshakes leave zero lingering goroutines.
2. **TAP Sensor Memory & Stream Invariant Verification (`internal/tap/soak_test.go`)**:
   - Gated with `//go:build soak`.
   - Ingest 10,000 synthetic fragmented packets through `ProcessPacket` in a tight loop.
   - Deterministically assert structural cleanup invariants: `sensor.ActiveStreams() == 0` after timeout flush, buffer pool reuse, and verify residual memory does not grow unbounded after `runtime.GC()`.
3. **Automated Soak Test Target in Makefile**:
   - Add `make test-soak` executing `$(GO) test -v -tags=soak -timeout=180s ./cmd/ja4pd ./internal/tap`.

### Out of Scope
- Multi-day bare metal soak runs (managed by SRE capacity runbooks).

---

## Implementation Plan

1. **Step 1: Remote Lease & Manifest Registration**
   - Claim `phase-854-concurrency-soak-testing`.
   - Mark Phase 854 `IN_PROGRESS` in manifest.
2. **Step 2: Implement Leak & Soak Tests**
   - `cmd/ja4pd/soak_leak_test.go` with `//go:build soak` and `goleak`.
   - `internal/tap/soak_test.go` with `//go:build soak` and deterministic stream cleanup assertions.
3. **Step 3: Makefile Target & Verification**
   - Add `test-soak` recipe to `Makefile`.
   - Verify `make test` ignores soak tests (fast path), while `make test-soak` executes cleanly.
4. **Step 4: Closeout**
   - Move phase doc to `docs/phases/complete/PHASE_854.md`.
   - Update manifest (`COMPLETE`), news fragment, `make preflight`, PR, auto-merge.

---

## Acceptance Criteria
- [x] `cmd/ja4pd/soak_leak_test.go` verifies zero goroutine leaks on 500 aborted TLS connections via `goleak`.
- [x] `internal/tap/soak_test.go` verifies bounded stream table cleanup and zero memory leakage over 10,000 packets.
- [x] Soak tests tagged with `//go:build soak`; normal `make test` completes without running soak tests.
- [x] `make test-soak` target added to Makefile and passes cleanly.
- [x] `make preflight` passes 100% green.
