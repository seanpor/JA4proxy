# Python 3.10/3.11 Benchmark Baseline

> **Note:** The project targets Python 3.11 in Dockerfiles, but the local development
> machine runs Python 3.10.12. This baseline captures actual local performance on the
> hot-path scoring and CIDR lookup code paths. Docker-based measurements will reflect
> Python 3.11. The primary purpose is to establish a before/after comparison point for
> the Python 3.14 upgrade.

Captured: 2026-04-04  
Environment: Python 3.10.12 (local), Linux 6.17.9, Intel Core i9-9900K  
Command: `python3 -m pytest tests/performance/ -v -s`

---

## Test Suite Summary

| Result | Count |
|--------|-------|
| Passed | 32    |
| Skipped (require live Go proxy) | 4 |
| Failed | 0     |
| Total duration | ~2.4s |

---

## Hot-Path Scoring Benchmarks (`test_bench_pipeline.py`)

| Test | n iterations | p50 | p99 | Limit |
|------|-------------|-----|-----|-------|
| `RiskScorer.score()` — 10 signals | 10,000 | 6.5 µs | 21.2 µs | < 100 µs |
| `RiskScorer.score()` — empty signals | 10,000 | — | 2.4 µs | < 20 µs |
| `ActionDecider.decide()` — normal | 10,000 | 1.33 µs | 1.54 µs | < 10 µs |
| `ActionDecider.decide()` — dial=0 | 10,000 | — | 0.20 µs | < 5 µs |
| Tarpit cap check — 500 concurrent | — | 0.001 ms | 0.003 ms | < 1 ms |
| Allow bypass path p99 | — | — | 3.8 µs | < 500 µs |
| Full scoring path p99 | — | — | 11.4 µs | < 1,000 µs |

All tests **PASSED** comfortably within their acceptance limits.

---

## CIDR Lookup Benchmarks (`test_bench_cidr_lookup.py`)

| Test | Trie size | Iterations | p50 | p99 | Max | Limit |
|------|-----------|------------|-----|-----|-----|-------|
| IPv4 CIDR trie lookup | 100,000 entries | 5,000 | 0.36 µs | 0.79 µs | 26.84 µs | < 10 µs |
| Full pipeline blocklist check | 50,000 entries | 5,000 | 0.62 µs | 0.88 µs | 21.38 µs | < 15 µs |

Both tests **PASSED**.

---

## Backup Hot-Path Non-Regression (`test_hot_path_non_regression.py`)

All 11 tests passed. These verify that backup operations do not interfere with the
connection-handling hot path. No timing numbers are printed by default.

---

## Backup Runtime Benchmarks (`test_runtime_benchmark.py`)

All 12 tests passed. These simulate small/medium/large dataset backup throughput and
verify memory efficiency. No absolute timing numbers are surfaced to stdout.

---

## Skipped Tests (Go proxy benchmarks, `test_bench_go_proxy.py`)

These 4 tests require a live Go proxy binary and are skipped in local runs:

- `test_go_proxy_connection_throughput`
- `test_go_vs_python_throughput_ratio`
- `test_go_proxy_p99_latency`
- `test_go_proxy_sustained_load`

---

## Key Numbers for Phase 67 Comparison

When Phase 67 (python:3.14.0-slim) benchmark results are captured, compare against:

| Metric | Python 3.10 baseline | Python 3.14 target | Expected gain |
|--------|---------------------|-------------------|---------------|
| `RiskScorer.score()` p99 (10 signals) | 21.2 µs | ≤ 19 µs | ≥ 10% |
| `ActionDecider.decide()` p99 | 1.54 µs | ≤ 1.4 µs | ≥ 10% |
| Allow bypass p99 | 3.8 µs | ≤ 3.4 µs | ≥ 10% |
| Full scoring path p99 | 11.4 µs | ≤ 10.3 µs | ≥ 10% |

> The 25–35% CPU improvement estimate (from Python 3.14 tail-call interpreter and JIT)
> is measured in CPU-bound workloads. I/O-bound paths (waiting on Redis, network) will
> show smaller improvements. The scoring loop is CPU-bound and expected to show
> meaningful gains.
