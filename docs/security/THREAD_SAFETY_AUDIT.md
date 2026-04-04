# Thread Safety Audit — JA4proxy Hot Path

**Phase**: 69 (Free-Threaded Python Proxy)  
**Date**: 2026-04-04  
**Scope**: All mutable shared state on the connection hot path in `proxy.py`,
`src/cache/local_cache.py`, and `src/config/loader.py`.

---

## Summary

This audit was conducted to prepare the proxy for Python 3.14 free-threaded mode
(`python:3.14t-slim`, GIL disabled). Under the GIL, apparent thread safety is an
accident of implementation; without the GIL every mutable shared-state access must be
explicitly protected.

**Result**: The hot path is safe as-is for the following reasons:

1. Module-level constants (`_GREASE_VALUES`, `VALID_JA4_PATTERN`) are immutable —
   no lock needed.
2. `LocalCache` and its `LRUCache` instances use no locks and are **asyncio-only** —
   single-threaded from the event loop's perspective. Under free-threaded Python,
   `LRUCache` would need a `threading.Lock` if accessed from multiple threads. The
   proxy runs one asyncio event loop per process and `LRUCache` is only accessed from
   coroutines on that loop, so no change is needed here.
3. `ConfigLoader` uses no locks on the config dict — `_config` is replaced atomically
   by reference assignment (`self._config = new_config`), which is an atomic operation
   in CPython. Under free-threaded Python this is still safe for reads (no torn reads
   on dict references) but a `threading.RLock` would be safer for future modifications.
4. `ProcessPoolExecutor` **was replaced** with `ThreadPoolExecutor` (phase-69) —
   eliminates IPC overhead and is safe for free-threaded Python since the TLS parsing
   work (`_parse_tls_task`) is stateless (pure function, no shared mutable state).

---

## Audit Table

| File | Object | Type | Current protection | Thread-safe under free-threading? | Action taken |
|------|--------|------|-------------------|----------------------------------|--------------|
| `proxy.py` | `_GREASE_VALUES` | `frozenset[int]` | Immutable — no lock needed | Yes — frozensets are immutable | None needed |
| `proxy.py` | `VALID_JA4_PATTERN` | `re.Pattern` (compiled regex) | Immutable — no lock needed | Yes — compiled regex objects are read-only after creation | None needed |
| `proxy.py` | `ProxyServer.executor` | `ThreadPoolExecutor` | Set once in `__init__`, read-only after | Yes — executor is thread-safe by design | Replaced ProcessPoolExecutor → ThreadPoolExecutor (zero-IPC) |
| `proxy.py` | `ProxyServer.active_connections` | `int` counter | asyncio event loop (single-threaded context) | Not safe under free-threading — would need `threading.Lock` or `asyncio.Lock` if called from threads | Deferred — not currently called from threads |
| `src/cache/local_cache.py` | `LRUCache._data` | `OrderedDict` | asyncio event loop only (no explicit lock) | Not safe under free-threading — OrderedDict ops are not atomic | No change — proxy uses single asyncio loop; not called from threads |
| `src/cache/local_cache.py` | `LocalCache._dial` | `int` | asyncio event loop only | Atomic in CPython (integer assignment); safe | None needed |
| `src/config/loader.py` | `ConfigLoader._config` | `dict` | asyncio event loop; replaced atomically | Dict reference replacement is atomic in CPython; safe for reads | None needed |
| `src/config/loader.py` | `ConfigLoader._callbacks` | `list` | asyncio event loop only | Not safe under free-threading if callbacks are added from threads | No change — callbacks only added at startup |
| `src/config/loader.py` | `ConfigLoader._reload_count` | `int` | asyncio event loop only | Atomic in CPython | None needed |

---

## Lock Changes

No `asyncio.Lock` instances were found protecting shared mutable state in
`src/cache/local_cache.py` or `src/config/loader.py`. Therefore the
`asyncio.Lock → threading.Lock` migration described in the phase plan does not apply
to this codebase.

**Rationale**: `LocalCache` and `ConfigLoader` were designed for single-threaded asyncio
use. They contain no locking primitives — their "thread safety" comes from running
exclusively within the asyncio event loop, where cooperative scheduling prevents
concurrent access. This design is correct for the current deployment model (one event
loop per process).

---

## ProcessPoolExecutor → ThreadPoolExecutor Migration

**Before (Phase 28a):**
```python
self.executor = ProcessPoolExecutor(max_workers=min(4, os.cpu_count() or 1))
```

**After (Phase 69):**
```python
self.executor = ThreadPoolExecutor(
    max_workers=min(4, os.cpu_count() or 1),
    thread_name_prefix="tls-parser",
)
```

**Why**: Under free-threaded Python (GIL disabled), `ProcessPoolExecutor` incurs
serialisation overhead (pickle/unpickle across process boundary) with no safety benefit.
`ThreadPoolExecutor` achieves zero-IPC parallel execution. The `_parse_tls_task` function
is a pure stateless function (reads bytes, returns a dict) — safe to call from any thread.

**Tests**: All 2906 tests pass after this change. The key assertion in
`tests/unit/test_proxy_server.py::TestAnalyzeTLSHandshake::test_tls_record_calls_scapy`
continues to pass because it mocks `run_in_executor` and only asserts the executor
object is passed through — not its concrete type.

---

## Recommendations for Full Free-Threading Readiness

If the proxy is deployed with `python:3.14t-slim` and the event loop is replaced by a
multi-threaded execution model, the following additional changes would be required:

1. **`LRUCache._data`**: Protect all `get()` / `set()` / `delete()` calls with
   `threading.Lock()`. The lock can be a `threading.Lock` (not `RLock`) since no
   method calls another method recursively.
2. **`LocalCache._dial`**: Wrap read/write in a `threading.Lock()` if the dial can be
   updated from a background thread (e.g. pub/sub callback running in a thread pool).
3. **`ConfigLoader._config`**: Add a `threading.RLock` around `_config` assignment and
   `get()` reads if the config can be reloaded from a thread other than the event loop.
4. **`ProxyServer.active_connections`**: Use `threading.Lock` or `asyncio.Lock` if
   incremented/decremented from multiple threads.

None of the above are required in the current single-event-loop deployment model.
