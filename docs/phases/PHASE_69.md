# Phase 69 — Free-Threaded Python Proxy

## Overview

Python 3.14 ships a free-threaded build (`python:3.14t-slim`) that removes the GIL.
This phase switches the proxy container to that build and replaces the `ProcessPoolExecutor`
(cross-process IPC via pickle) with a `ThreadPoolExecutor` (shared memory, no serialisation
cost). The estimated saving is 0.7–1.5ms per connection — the IPC overhead measured in
Phase 65 — which at 1000 conn/s recovers 700ms–1500ms of CPU per second.

**This phase is conditional.** If the Phase 67 benchmark showed throughput ≥ 600 conn/s
already, skip this phase and mark it `DEFERRED`. Free-threading adds code complexity
(thread safety audit, new Docker image tag); if the gain is marginal relative to that
cost, deferral is correct.

**Only the proxy container changes.** The TAP container is a candidate too (packet
reassembly is CPU-bound), but that is a separate follow-on if the proxy result is
positive. Analytics and management containers must stay on the standard GIL build
because `numpy`/`scipy` link against BLAS with their own threading model.

---

## Prerequisites

- Phase 67 complete (base image on 3.14).
- Phase 67 gate decision documented: throughput < 600 conn/s, therefore Phase 69 is
  warranted.
- Phase 65 pure-Python TLS parser complete (removes the memory-isolation justification
  for `ProcessPoolExecutor` — a bounded pure-Python parser in a thread has the same
  memory guarantee as in a process).

---

## Background: Why ProcessPoolExecutor → ThreadPoolExecutor Is Now Safe

Phase 28a introduced `ProcessPoolExecutor` to isolate Scapy's TLS parser: Scapy can
consume unbounded memory on adversarial inputs, and a crash in a worker process does
not kill the main event loop. The cost is cross-process IPC (pickle serialisation +
OS pipe) on every connection.

Phase 65 replaced Scapy with a hand-rolled pure-Python parser (`src/tls/parser.py`)
that:
- Makes a single linear pass over the input buffer — O(N), statically bounded
- Returns `None` on any parse error without raising
- Cannot recurse and cannot allocate beyond the input size

With that parser in place:
- Memory isolation is no longer the primary motivation for a separate process
- A `ThreadPoolExecutor` running `parse_client_hello()` provides parallelism with zero
  IPC overhead, shared memory, and identical failure isolation (a thread that returns
  `None` is the fail-open path)
- Under the GIL (3.14 standard build), `ThreadPoolExecutor` is not faster for
  CPU-bound work. Under free-threading (3.14t), it is — threads run truly in parallel
  on multiple cores.

---

## Work Plan

### A — Thread Safety Audit

Before switching to free-threading, audit all module-level mutable state in the hot path
for GIL reliance. Document findings in `docs/security/THREAD_SAFETY_AUDIT.md`.

Files to audit:

| File | Object | Current protection | Action needed |
|------|--------|--------------------|---------------|
| `proxy.py` | `_GREASE_VALUES` | frozenset (immutable) | None |
| `proxy.py` | `VALID_JA4_PATTERN` | compiled regex (immutable) | None |
| `src/security/risk_scorer.py` | `_weights` dict | GIL-protected dict read | Add `threading.Lock` around writes; reads from immutable snapshot |
| `src/cache/local_cache.py` | `_store` dict | `asyncio.Lock` | Change to `threading.Lock` — asyncio locks are not thread-safe |
| `src/security/blocklists.py` | pytricia trie | read-only after init | None (verify no writes on hot path) |
| `src/config/loader.py` | config dict | `asyncio.Lock` on reload | Change to `threading.RLock` |

For each mutable shared object: either confirm it is protected by `threading.Lock` /
`threading.RLock`, or confirm it is immutable (frozenset, tuple, compiled regex,
`types.MappingProxyType`).

**Rule:** `asyncio.Lock` is **not** thread-safe — it only serialises coroutines in the
same event loop thread. In a free-threaded environment with multiple OS threads, any
mutable state guarded only by `asyncio.Lock` is a data race.

### B — Switch `docker/Dockerfile` to Free-Threaded Build

```dockerfile
FROM python:3.14t-slim   # was python:3.14.0-slim
```

Only `docker/Dockerfile` (the main proxy image) changes. All other containers stay on
`python:3.14.0-slim`.

Rebuild the image. Install pytricia from source if needed (same gcc step as Phase 67).

### C — Replace `ProcessPoolExecutor` with `ThreadPoolExecutor`

In `proxy.py`, wherever `ProcessPoolExecutor` is used for TLS parsing:

```python
# BEFORE
from concurrent.futures import ProcessPoolExecutor
self._executor = ProcessPoolExecutor(max_workers=cfg.parser_workers)
...
result = await loop.run_in_executor(self._executor, _parse_tls_task, raw_bytes)

# AFTER
from concurrent.futures import ThreadPoolExecutor
self._executor = ThreadPoolExecutor(max_workers=cfg.parser_workers,
                                    thread_name_prefix="tls-parser")
...
result = await loop.run_in_executor(self._executor, parse_client_hello, raw_bytes)
```

Add config key:
```yaml
runtime:
  tls_parser_workers: 4   # number of parser threads; default = cpu_count()
  # Each thread handles one TLS ClientHello parse. With free-threaded Python,
  # threads run in parallel on multiple cores. With GIL Python, threads yield
  # to each other — no parallelism, but no IPC overhead either.
```

If Phase 65's pure-Python parser eliminated the executor entirely (i.e., `parse_client_hello`
is called synchronously in the event loop), this step is a no-op — document that and
skip to step D.

### D — Parity and Race Condition Validation

Run the full test suite with thread contention:

```bash
# Run tests with 4× concurrency to surface races
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py \
    -n 4 --timeout=120 -q
```

Run the Phase 65 parity harness if both proxies are running:

```bash
make parity-check
```

No test regressions. No data races (no non-deterministic test failures across 5 runs).

### E — Benchmark Validation

```bash
make bench 2>&1 | tee reports/benchmark/python314-stage3-freethreaded.md
```

Compare against Phase 68 (`reports/benchmark/python314-stage2.md`). Required: throughput
ceiling ≥ 600 conn/s.

Record also: IPC-related latency (bypass path should drop by 0.7–1.5ms if
`ProcessPoolExecutor` was still in use before this phase).

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `docker/Dockerfile` | `python:3.14.0-slim` → `python:3.14t-slim` |
| `proxy.py` | ProcessPoolExecutor → ThreadPoolExecutor (if applicable) |
| `src/cache/local_cache.py` | asyncio.Lock → threading.Lock on _store |
| `src/config/loader.py` | asyncio.Lock → threading.RLock on config dict |
| `config/proxy.yml` | Add `runtime.tls_parser_workers` key |
| `docs/security/THREAD_SAFETY_AUDIT.md` (new) | Audit findings |
| `reports/benchmark/python314-stage3-freethreaded.md` (new) | Benchmark results |
| `docs/phases/manifest.yaml` | Add Phase 69 |
| `CLAUDE.md` | Add Phase 69 to phase index |
| `CHANGELOG.md` | Phase 69 entry |

---

## Acceptance Criteria

- [x] `docs/security/THREAD_SAFETY_AUDIT.md` committed; all mutable shared state
      either immutable or guarded by `threading.Lock` / `threading.RLock`
- [x] `docker/Dockerfile` uses `python:3.14t-slim`
- [x] `docker build` succeeds for the proxy image
- [x] `asyncio.Lock` replaced with `threading.Lock` in `local_cache.py` and
      `config/loader.py` (or confirmed that the GIL was the only guard and the free-
      threaded build now exposes a race that is fixed)
- [x] Full test suite passes: 2687+ tests, 0 failures, deterministic across 5 runs
- [x] `make parity-check` passes (pipeline decisions unchanged)
- [x] Throughput ceiling ≥ 600 conn/s in benchmark
- [x] IPC latency saving documented (bypass path latency delta vs Phase 68)
- [x] `reports/benchmark/python314-stage3-freethreaded.md` committed
- [x] `CHANGELOG.md` entry for Phase 69

---

## What This Does Not Cover

- TAP container free-threading — a follow-on if proxy results justify it.
- Analytics and management containers — these must stay on GIL build.
- `interpreters` subinterpreter API — Phase 70 (experimental, optional).
- Replacing `asyncio` with `concurrent.futures` entirely — larger architectural change.
