<!--
title: JA4proxy — Testing Strategy
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# JA4proxy — Testing Strategy

This document outlines the testing methodology and quality gates for JA4proxy.

---

## ⚖️ Testing Principles

1.  **Tests Define Correctness:** The test suite is the specification. Any logic change must be backed by a test.
2.  **Failure Modes Must be Tested:** Verify "fail open" and "fail closed" behaviors explicitly.
3.  **No External Dependencies:** All external APIs (AbuseIPDB, etc.) must be mocked.
4.  **Asymmetric Testing:** Always test that "good" traffic passes and "bad" traffic is blocked.

---

## 🧪 Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| **Unit** | `tests/unit/` | Isolation tests for functions and classes. |
| **Integration** | `tests/integration/` | Multi-module tests with a real Redis instance. |
| **Chaos** | `tests/chaos/` | Verifies resilience when Redis or APIs are slow/down. |
| **Adversarial** | `tests/adversarial/` | Fuzzing and evasion attempt testing. |
| **Performance** | `tests/performance/` | Throughput and latency benchmarks. |

---

## ⚙️ CI/CD Quality Gates

Every Pull Request must pass the following gates:

1.  **Static Analysis:** `make lint-all` (Go & Python).
2.  **Security Scan:** `make scan` (CVEs and static security checks).
3.  **Functionality:** 100% of Unit and Integration tests must pass.
4.  **Coverage:** Minimum **80%** line coverage for new Go code.
5.  **Test Ratio:** Maintain a minimum **1.2:1** test-to-code line ratio.

---

## 🏗 Regression Testing (Phase 121d)

When remediating a security finding, you **must** add a regression test:
- **File Name:** `pentest_{finding_id}_regression_test.go`
- **Requirement:** The test must fail before the fix and pass after.
- **Verification:** Run `make verify-findings-green` to validate all finding-backed tests.

---

## 🚀 Phase Completion Gate

A development phase is only considered COMPLETE when:
- [ ] All feature requirements are implemented.
- [ ] Unit, Integration, and Regression tests pass.
- [ ] No high/medium `gosec` or `govulncheck` findings remain.
- [ ] Documentation (Phase Doc, Manifest, Operations) is updated.
