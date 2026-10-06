<!--
title: Invariant Testing Handbook
audience: developer
last_reviewed: 2026-10-06
phase: 606-0
-->

# JA4proxy Invariant Testing Handbook

This document defines the mandatory methodology and conventions for invariant testing across Go and Python components in JA4proxy.

---

## 1. What an Invariant Is

An **invariant** is a property that must hold true across **all valid state transitions, inputs, or configurations** of a component. Unlike example-based unit tests (which verify specific input/output pairs), invariant tests verify mathematical and behavioral safety guarantees.

* **Use Invariants for:** State machines, byte parsers, rate limiters, memory layout identity, circuit breaker exact boundaries, and cryptographic fingerprint consistency.
* **Use Example Tests for:** Specific CVE regression checks, known-answer test (KAT) vectors, and API contract status codes.

---

## 2. Tool Choice & Banned Libraries

* **`pgregory.net/rapid`**: Standard property testing engine for Go. Generates structured inputs and shrinks failing inputs to minimal counterexamples.
* **Native `func FuzzXxx(f *testing.F)`**: Standard fuzzer for raw, untrusted byte parsers. Seed corpus must be committed under `testdata/fuzz/`.
* **`pytest` + `hypothesis`**: Standard property engine for Python.
* 🚫 **`testing/quick` is BANNED**: `testing/quick` lacks shrinking, seed reproduction, and structured generators. Do not use it for new code.

---

## 3. The Non-Vacuity Rule

A property test guarded by `if err != nil { return }` passes vacuously if 100% of generated inputs trigger an error.

* **Rule:** Properties over parsed structures MUST use valid-by-construction generators (such as `tlsfixture.GenSpec()`) or assert a minimum non-zero success rate.

---

## 4. The "Make It Fail First" Rule

Before registering an invariant in `docs/testing/invariants.yaml`:

1. Introduce a deliberate bug in production code (e.g. swap `>` to `>=` or remove GREASE filtering).
2. Run the invariant test and verify it fails (turns RED).
3. Revert the production code bug.
4. Record the verified mutation in the `mutation_check` field of `docs/testing/invariants.yaml`.

---

## 5. Time & Determinism

* 🚫 **`time.Sleep` for synchronization is strictly BANNED**: It creates flaky tests and slow CI pipelines.
* **Use `testing/synctest`**: Go 1.26 `synctest.Test(t, func(t *testing.T){ ... })` runs inside a fake-time bubble. `time.Sleep` advances time instantaneously without real-world waiting.
* **Socket Constraint:** `synctest` bubbles stall/deadlock on real OS TCP listeners (`net.Listen`, `net.Dial`). Use `net.Pipe()` for in-memory streams inside `synctest` bubbles.
* **Redis Time:** Use `miniredis.FastForward(d)` or pass timestamps explicitly.

---

## 6. Goroutine Leak Detection

New leak invariants must execute `goleak` verification at the top of the test function:

```go
defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
```

`IgnoreCurrent()` snapshots existing background goroutines (Prometheus, logging hooks) so only goroutines spawned *during the test* are checked. If background workers spawn child routines, use `goleak.IgnoreTopFunction(...)`.

---

## 7. Zero-Skip & Platform-Specific Tests

JA4proxy operates under a strict **Zero-Skip Policy**.

* 🚫 Do NOT call `t.Skip()` or `pytest.skip()` for OS-specific behavior.
* Use Go build tags (`//go:build linux`) to isolate platform-specific test files.

---

## 8. Prometheus & Global State Isolation

Tests asserting Prometheus metrics:

* MUST NOT call `t.Parallel()`.
* MUST measure **deltas** before and after the operation (`after - before == want`), never absolute counter values.

---

## 9. Execution Budgets & Reproduction

* Any invariant test taking > 2 seconds must check `testing.Short()` and scale down iterations.
* Local deep runs: `go test -rapid.checks=10000 ./...`
* Failure reproduction: `go test -rapid.seed=<seed_value>`

---

## 10. Naming & Registry Protocol

Every invariant MUST be registered in `docs/testing/invariants.yaml` and follow the exact naming scheme:

* **Go:** `TestInvariant_<Area>_<Property>` or `FuzzInvariant_<Area>_<Property>`
* **Python:** `test_invariant_<area>_<property>`
* **Allowed Areas:** `TLS`, `QUIC`, `Splice`, `Resource`, `Redis`, `Tap`, `Security`, `Telemetry`, `Config`, `Mgmt`.

---

## 11. Bug Finding & Resolution Protocol

When an invariant test uncovers a genuine bug in production code:

1. **Do NOT fix it in the test PR**, and do not weaken the invariant to make it pass.
2. Register the finding: `python3 scripts/findings_register.py add ...` (allocates `JA4PROXY-YYYY-NNNN` ID and opens a GitHub issue).
3. If keeping the failing test in main before a fix lands, log an exception in `docs/security/EXCEPTIONS.md` with the finding ID.
