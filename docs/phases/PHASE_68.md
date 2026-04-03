# Phase 68 — Python 3.14 Hot Path Optimizations

## Overview

With the base image upgraded to Python 3.14 (Phase 67), this phase extracts additional
performance by making the hot path code JIT-friendly and integrating `uvloop` as the
asyncio event loop on Linux.

Both changes are additive: if either causes a test failure, it can be reverted
independently. Neither changes externally-visible behaviour.

**Expected additional gain on top of Phase 67:** ~10–25% on CPU-bound paths (JIT
warm-up) and ~30–100% on I/O throughput (uvloop).

---

## Prerequisites

- Phase 67 complete: all containers on `python:3.14.0-slim`, full test suite passes.
- Phase 67 benchmark baseline captured in `reports/benchmark/python314-stage1.md`.

---

## Background: How the 3.14 JIT Works

Python 3.14's copy-and-patch JIT compiles bytecode to machine code after a function
has been called ~50 times. It works best on functions that:

1. **Have no `try/except` wrapping the inner loop body** — `try/except` prevents JIT
   compilation of the entire loop. Move exception handling outside the loop or replace
   with `dict.get()` with a default.

2. **Use monomorphic call sites** — if a variable is always the same type (e.g., always
   `int`, always `str`), the JIT can eliminate dynamic type checks. Avoid mixing types
   in hot paths.

3. **Call module-level functions, not methods on changing objects** — method dispatch
   involves attribute lookup on `__dict__`; module-level functions avoid this.

4. **Are called frequently from a hot loop** — `RiskScorer.score()`, `JA4Generator.generate_ja4()`,
   and the Phase 65 `parse_client_hello()` are all called on every connection.

---

## Work Plan

### A — JIT-Friendly Refactor: `RiskScorer.score()`

In `src/security/risk_scorer.py`, find the signal aggregation loop. Replace
`try/except KeyError` inside the loop with `dict.get()`:

```python
# BEFORE — try/except blocks the JIT
for signal in signals:
    try:
        weight = self._weights[signal.category]
        score += signal.score * weight
    except KeyError:
        score += signal.score  # default weight = 1

# AFTER — JIT can compile this loop
for signal in signals:
    weight = self._weights.get(signal.category, 1.0)
    score += signal.score * weight
```

If `self._weights` is rebuilt on every call (e.g., from config), cache it as an instance
attribute set once at `__init__` and updated on config reload. The JIT treats a stable
dict reference as monomorphic.

Confirm all 2687+ tests still pass after this change.

### B — JIT-Friendly Refactor: `JA4Generator`

In `proxy.py` (or wherever `JA4Generator` lives after Phase 65), the GREASE filter
and sort operations run in a loop per connection. Ensure:

1. `_GREASE_VALUES` is a module-level `frozenset` (Phase 65 should have done this —
   verify and fix if not).
2. The filter comprehension uses a local reference to `_GREASE_VALUES`, not `self.*`:
   ```python
   # Cache module-level name as a local to avoid global lookup in loop
   _grease = _GREASE_VALUES
   filtered = [c for c in cipher_suites if c not in _grease]
   ```
3. No `try/except` inside the sort or hash computation.

### C — `uvloop` Integration

`uvloop` is a drop-in asyncio event loop backed by libuv (C). It typically gives
2–4× throughput on I/O-heavy workloads by eliminating Python-level overhead from
`epoll` dispatch.

Add to `requirements.txt`:
```
uvloop>=0.21.0; sys_platform == "linux" and python_version >= "3.14"
```

In `proxy.py` `main()`, install the event loop policy before `asyncio.run()`:

```python
def main() -> None:
    _install_event_loop()
    asyncio.run(_main())

def _install_event_loop() -> None:
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logger.info("event_loop=uvloop")
    except ImportError:
        logger.info("event_loop=asyncio_default")
```

Add config toggle in `config/proxy.yml`:
```yaml
runtime:
  event_loop: "uvloop"    # uvloop | default
  # uvloop: libuv-backed asyncio event loop; 2-4x I/O throughput on Linux.
  # Requires uvloop package. Falls back to default if unavailable.
  # Default: uvloop (if installed), default otherwise.
```

If `uvloop` does not have a Python 3.14 wheel at upgrade time, skip this step and
log a note in `reports/benchmark/python314-stage2.md` with the target version to
watch.

### D — Benchmark Validation

```bash
make bench 2>&1 | tee reports/benchmark/python314-stage2.md
```

Compare against `reports/benchmark/python314-stage1.md` (Phase 67 baseline). Document:

| Metric | Phase 67 (3.14 base) | Phase 68 (JIT + uvloop) | Change |
|--------|---------------------|------------------------|--------|
| Bypass path (ms) | | | |
| Scoring path (ms) | | | |
| Full ALLOW (ms) | | | |
| Throughput (conn/s) | | | |

The JIT warm-up effect means the first ~50 connections per process are at 3.14 baseline
speed; measurements should be taken after warm-up.

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `src/security/risk_scorer.py` | Remove try/except from scoring inner loop |
| `proxy.py` | Install uvloop policy in main(); verify GREASE frozenset |
| `requirements.txt` | Add uvloop conditional dependency |
| `config/proxy.yml` | Add `runtime.event_loop` config key |
| `reports/benchmark/python314-stage2.md` (new) | After-optimization benchmark |
| `docs/phases/manifest.yaml` | Add Phase 68 |
| `CLAUDE.md` | Add Phase 68 to phase index |
| `CHANGELOG.md` | Phase 68 entry |

---

## Acceptance Criteria

- [ ] `RiskScorer.score()` inner loop has no `try/except`; uses `dict.get()` instead
- [ ] `_GREASE_VALUES` is a module-level `frozenset` (not rebuilt per call)
- [ ] `uvloop` integrated with graceful `ImportError` fallback; logs which loop is active
- [ ] `runtime.event_loop` config key present in `config/proxy.yml` with comment
- [ ] Full test suite passes: 2687+ tests, 0 failures
- [ ] Scoring path improves by ≥ 5% vs Phase 67 baseline (JIT refactor alone)
- [ ] Throughput improves by ≥ 20% vs Phase 67 baseline (uvloop contribution)
- [ ] `reports/benchmark/python314-stage2.md` committed with before/after table
- [ ] `CHANGELOG.md` entry for Phase 68

---

## What This Does Not Cover

- Free-threaded build — Phase 69.
- Analytics container — Phase 70.
- Replacing `pytricia` with a pure-Python trie — not worth it; C extension already fast.
- `io_uring` asyncio backend — no stable Python API yet; monitor for Python 3.15+.
