---
phase: 806
title: "management/tests/ — remove dead-module test references"
status: PROPOSED
created: 2026-07-22
audience: [developer]
---

# management/tests/ — remove dead-module test references

> **STATUS: PROPOSED — small, mechanical. First of three phases (806/807/808)
> closing a gap found while scoping [[PHASE_801]]: `management/tests/` (760
> tests) is completely excluded from `make test` — `pyproject.toml`'s
> `testpaths = ["tests"]` never sees it.

## Goal

Of the 35 tests currently failing in `management/tests/`, 8 (all in
`test_phase_122_security_review.py`) fail with `ModuleNotFoundError` /
`FileNotFoundError` against modules that no longer exist:
`src.tap.enforcement_bridge`, `src.security.health`, and `proxy.py` (the
deleted Python proxy). Remove or rewrite these before [[PHASE_807]] tackles
the remaining, real failures — no point debugging schema drift in the same
pass as deleting tests for code that isn't there anymore.

## Plan

1. For each of the 8 failing tests in `test_phase_122_security_review.py`,
   confirm what replaced the module it references (Go equivalents already
   exist per project history — e.g. TAP enforcement now lives in
   `internal/tap/` per the Phase 316 Go rewrite) and either:
   - delete the test if its Go equivalent already has coverage, or
   - port the assertion to the Go test suite if it doesn't.
2. Re-run `management/tests/test_phase_122_security_review.py` — 0 failures
   (whatever remains, if anything, should be real Python-side coverage).

## Acceptance criteria

- [ ] No test in `management/tests/` references a deleted module.
- [ ] `management/tests/test_phase_122_security_review.py` passes in full
      (or is removed entirely if every case moved to Go).
- [ ] Failure count in `management/tests/` drops from 35 to 27 (the
      remainder is [[PHASE_807]]'s scope).
