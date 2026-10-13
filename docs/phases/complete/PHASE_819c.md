---
phase: 819c
title: "Repair test-go-perf and Load Test Harness"
status: PROPOSED
size: MEDIUM
created: 2026-10-13
audience: [developer, operations]
---

# Repair test-go-perf and Load Test Harness

> **STATUS: PROPOSED — plan for junior developer execution.**
>
> Split from original Phase 819b. This phase addresses **F6** (test-go-perf port mismatch) and **F7** (load-test harness bit-rot and undefined variables).

## Goal

Restore truthfulness to `test-go-perf` and `scripts/load_test.py` so they correctly test the Go proxy on real exposed ports without skipping or crashing.

## Scope of Work (Junior Dev Checklist)

1. **Fix `test-go-perf` Port Mismatch & Drop Obsolete Python Proxy Comparison**:
   - In `tests/performance/test_bench_go_proxy.py`:
     - Update default `GO_PROXY_PORT` from `18082` to `8080` or dynamically resolve from `HOST_PORT_DIRECT`.
     - Remove obsolete `test_go_vs_python_throughput_ratio` test (the Python proxy was deprecated and deleted; testing ratios against non-existent Python proxy causes port confusion).
2. **Repair `scripts/load_test.py`**:
   - Fix undefined `LOAD_TEST_*` environment variable defaults.
   - Ensure stdout output captures summary throughput and error counts.
   - Run under container-strict Python via `$(TOOLS_RUN)` or Docker tools image rather than host Python.
3. **Verification**:
   - Run `tests/performance/test_bench_go_proxy.py` via `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest tests/performance/test_bench_go_proxy.py`.
   - Ensure tests execute and report honest pass/fail rather than skipping.

## Acceptance Criteria
- `test_bench_go_proxy.py` passes against active proxy or skips explicitly when no daemon is up.
- No obsolete references to comparing against deleted Python proxy.
- `make lint` passes.
