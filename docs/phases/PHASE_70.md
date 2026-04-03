# Phase 70 — Analytics Upgrade & Subinterpreter Experiment

## Overview

Two independent workstreams, both small enough to complete together:

1. **Analytics container upgrade to Python 3.14** — the analytics node was held back
   during Phase 67 because `numpy`/`scipy` wheel availability needed verification. This
   phase completes the upgrade once that is confirmed.

2. **Subinterpreter worker pool (optional experiment)** — Python 3.14 stabilises the
   `interpreters` module (PEP 554/684). Each subinterpreter has its own GIL, making this
   a middle ground between multi-process (expensive IPC) and free-threading (shared memory,
   no GIL). This phase implements it as an opt-in, feature-flagged alternative to the
   `ThreadPoolExecutor` introduced in Phase 69, and measures whether it has any advantage
   for this workload.

The subinterpreter experiment is explicitly marked optional. If it shows no measurable
gain over `ThreadPoolExecutor`, the code is removed rather than maintained.

---

## Prerequisites

- Phase 67 complete (base image knowledge).
- Confirmation that `numpy ≥ 2.0`, `pandas ≥ 2.0`, `scipy ≥ 1.13` have Python 3.14
  wheels on PyPI (check `reports/python314-compat.md` from Phase 66).
- Phase 69 complete (or skipped/deferred) — the subinterpreter experiment only makes
  sense after understanding whether `ThreadPoolExecutor` in the free-threaded build
  already achieves the throughput target.

---

## Work Plan

### A — Analytics Container Upgrade

Update `src/analytics/Dockerfile`:

```dockerfile
FROM python:3.14.0-slim as base   # was python:3.11.11-slim
```

Build and run the analytics-specific test suite:

```bash
docker compose -f docker-compose.poc.yml build analytics
python3 -m pytest tests/ -k "analytics" -v
```

If any scipy/numpy call raises a deprecation warning promoted to error under 3.14, fix
the call site in `analytics/`. Document any fixes in `CHANGELOG.md`.

If wheels are not yet available for any analytics dependency, this step is deferred and
documented. The analytics container stays on 3.11 until wheels ship; nothing else in
this phase is blocked.

### B — Subinterpreter Pool (Optional)

Write `src/tls/interpreter_pool.py`:

```python
"""
SubinterpreterPool — a drop-in replacement for ThreadPoolExecutor for TLS parsing.

Each subinterpreter has its own GIL. This means:
- Parsing runs concurrently (multiple GILs in parallel)
- numpy/scipy in the caller's interpreter are unaffected
- No shared mutable state between interpreters (each gets its own module namespace)

Requires Python 3.14+ with the `interpreters` stdlib module.
Falls back silently to ThreadPoolExecutor if `interpreters` is unavailable.
"""
import sys

def create_pool(workers: int):
    try:
        import interpreters          # Python 3.14+
        return _SubinterpreterPool(workers)
    except ImportError:
        from concurrent.futures import ThreadPoolExecutor
        return ThreadPoolExecutor(max_workers=workers,
                                  thread_name_prefix="tls-parser")
```

The `_SubinterpreterPool` class must implement the same interface as `ThreadPoolExecutor`
(specifically `submit()` returning a `Future` and `shutdown()`).

Add config toggle in `config/proxy.yml`:
```yaml
runtime:
  tls_parser_model: "thread_pool"    # thread_pool | interpreter_pool
  # thread_pool: ThreadPoolExecutor (Phase 69 default). Recommended.
  # interpreter_pool: experimental subinterpreter pool (Python 3.14+ only).
  #   Each interpreter has its own GIL. Falls back to thread_pool if unavailable.
  #   Enable only to compare performance; collect data before relying on this.
```

### C — Subinterpreter Benchmark Comparison

Run the benchmark with each parser model and record results:

```bash
# thread_pool baseline (from Phase 69)
cat reports/benchmark/python314-stage3-freethreaded.md

# interpreter_pool
PROXY_TLS_PARSER_MODEL=interpreter_pool make bench \
  | tee reports/benchmark/python314-stage4-interpreters.md
```

Compare throughput and latency. If `interpreter_pool` is within 5% of `thread_pool`,
the added complexity is not justified — remove `src/tls/interpreter_pool.py` and
document the finding. If it shows measurable gain (e.g., better tail latency due to GIL
isolation), keep it as the non-default option with a note explaining when to use it.

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `src/analytics/Dockerfile` | 3.11.11-slim → 3.14.0-slim |
| `src/tls/interpreter_pool.py` (new, optional) | Subinterpreter pool implementation |
| `config/proxy.yml` | Add `runtime.tls_parser_model` key (optional) |
| `reports/benchmark/python314-stage4-interpreters.md` (new, optional) | Benchmark comparison |
| `docs/phases/manifest.yaml` | Add Phase 70 |
| `CLAUDE.md` | Add Phase 70 to phase index |
| `CHANGELOG.md` | Phase 70 entry |

---

## Acceptance Criteria

### Analytics Upgrade (required)

- [ ] `src/analytics/Dockerfile` updated to `python:3.14.0-slim`
- [ ] Analytics Docker image builds successfully
- [ ] Analytics tests pass: `python3 -m pytest tests/ -k analytics`
- [ ] Any deprecated scipy/numpy API calls fixed in `analytics/`

### Subinterpreter Experiment (optional — only if Phase 69 complete)

- [ ] `src/tls/interpreter_pool.py` implemented with `ThreadPoolExecutor` fallback
- [ ] `runtime.tls_parser_model` config key added with comment
- [ ] Benchmark comparison committed to `reports/benchmark/`
- [ ] Decision documented: keep or remove `interpreter_pool` based on benchmark data

### Common

- [ ] Full test suite passes: 2687+ tests, 0 failures
- [ ] `README.md` states Python ≥ 3.14 requirement (update from any 3.11 reference)
- [ ] `CHANGELOG.md` entry for Phase 70

---

## What This Does Not Cover

- TAP container free-threading — deferred pending proxy Phase 69 results.
- `io_uring` asyncio backend — no stable Python API; revisit for Python 3.15+.
- PyPy or GraalPy — PyPy 3.14 does not yet exist; revisit when available.
- Cython hot path compilation — escalation path if 3.14t still does not reach throughput
  target; not in scope here.
