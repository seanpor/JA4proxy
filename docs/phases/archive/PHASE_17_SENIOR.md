# PHASE 17 — Technical Analysis (Senior Dev)

> The step-by-step implementation is in [PHASE_17_JUNIOR.md](PHASE_17_JUNIOR.md) (same directory).
> This document covers root cause, fix rationale, versioning constraints, and
> guidance for future maintainers.

---

## Problem Summary

`make test` inside Docker reports `Passed: 0` and `OVERALL RESULT: TESTS TIMED OUT`
after all ~1583 tests pass in ~35 s. The container then hangs for ~265 s before
the 300 s `timeout` kills it.

---

## Root Cause Analysis

### Where the hang is NOT

The original diagnosis (now recorded as incorrect) was that the hang occurred in
Python 3.11's interpreter shutdown phase — the GC finalising orphaned `asyncio.Task`
objects after pytest exited. A `pytest_sessionfinish(trylast=True)` hook with
`os._exit()` was added to bypass interpreter teardown. **It did not fix the hang.**

### Where the hang actually is

The hang is **inside pytest**, before `pytest_sessionfinish` is ever called.

Evidence: pytest's built-in terminal reporter also uses `pytest_sessionfinish` to
print "N passed in Xs". That line never appears in the results file, which means
`pytest_sessionfinish` never fires — the hang must precede it.

In pytest 7.4.3, `pytest_sessionfinish` hooks are called from
`Session.finish()`, which runs *after* `SetupState.__exit__()`. That teardown
phase processes all session-scoped fixture finalizers. The hang is in there.

### The hang mechanism

pytest-asyncio 0.21.1 creates a `_function_scoped_runner` fixture per async test.
Its finalizer calls `runner.__exit__()` → `Runner.close()`.

In Python 3.11, `asyncio.Runner.close()` was tightened:

```python
_cancel_all_tasks(loop)
loop.run_until_complete(loop.shutdown_asyncgens())
loop.run_until_complete(loop.shutdown_default_executor())
loop.close()
```

`_cancel_all_tasks` calls:
```python
loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))
```

If a task does not complete promptly after cancellation, this `run_until_complete`
blocks indefinitely.

### Which tasks are orphaned

`ASNClassifier._init_tor_list()` (called lazily on first `signals()` invocation):

```python
asyncio.create_task(self._tor_refresh_loop(refresh_interval))
```

`_tor_refresh_loop` is a `while True` loop that sleeps `refresh_interval` seconds
(default 3600) per iteration. It catches `asyncio.CancelledError` and breaks, so in
principle it should cancel promptly. In practice, with 1583+ async tests each running
in their own event loop, the cumulative volume of orphaned tasks causes
`_cancel_all_tasks` to take longer than the 300 s wall.

Additional long-lived background task creators in the codebase:
- `../../src/security/blocklists.py`: `asyncio.create_task(self._refresh_loop(feed_cfg))`
- `../../src/security/dns_enrichment.py`: `asyncio.create_task(self._worker_with_restart(i))`

These are not currently implicated but follow the same pattern and should be added
to `_no_real_network` if they ever cause similar symptoms.

---

## Fix Rationale

### Fix 1: `PYTHONUNBUFFERED=1` (already applied)

This was a separate, compounding symptom. Python inside Docker defaults to
block-buffered stdout. The "N passed in Xs" summary line from pytest was buffered in
userspace and never flushed to the `tee` pipe before the process was killed, causing
`Passed: 0` in the results file even when all tests had passed.

Setting `PYTHONUNBUFFERED=1` in `deploy/docker/Dockerfile.test` and `deploy/docker/docker-compose.poc.yml`
eliminates the buffering. This does not fix the hang itself — it only fixes the
misleading output.

### Fix 2: Patch `_tor_refresh_loop` in `_no_real_network`

The `_no_real_network` session fixture already patches `_refresh_tor_list` (the HTTP
download) to a no-op. It must also patch `_tor_refresh_loop` so that
`asyncio.create_task(self._tor_refresh_loop(...))` creates a task that completes
immediately rather than sleeping 3600 s.

The patch is applied at the class level via `unittest.mock.patch`, which means it
intercepts the method lookup on every `ASNClassifier` instance across all tests for
the entire session. Chaos tests that specifically exercise loop behaviour
(`tests/chaos/test_asn_chaos.py`) apply their own `patch.object(instance, ...)` which
takes precedence — they are unaffected.

### Fix 3: `tryfirst=True` on `pytest_sessionfinish`

The `os._exit()` call in `pytest_sessionfinish` is the correct safety net for
interpreter-level hangs. The problem is its ordering.

With `trylast=True`, our hook runs *after* every other `pytest_sessionfinish` hook,
including pytest's internal cleanup. Since the hang occurs inside that cleanup, the
hook never reaches `os._exit()`.

With `tryfirst=True`, our hook runs at the *start* of session-finish — after all
tests and their function-scope fixture teardowns, but before session-scope fixture
teardown and plugin cleanup. `os._exit()` then fires before anything can block.

**Side effect on JUnit XML:** pytest's `--junitxml` plugin also uses
`pytest_sessionfinish`. With `tryfirst=True` our hook may preempt it, leaving the
JUnit XML file incomplete or absent. This is acceptable: the per-test verbose output
written to `RESULTS_FILE` via `tee` is the authoritative record. JUnit XML is
supplementary for CI tools that consume it; if that becomes important, the JUnit
plugin's ordering can be investigated separately.

---

## Versioning Constraints

These fixes are specific to:
- **Python 3.11** — stricter `asyncio.Runner.close()` teardown
- **pytest 7.4.3** — session fixture teardown ordering
- **pytest-asyncio 0.21.1** — `_function_scoped_runner` lifecycle

If any of these are upgraded, re-test the Docker hang scenario. Specifically:
- pytest-asyncio ≥ 0.23 changed the default asyncio mode to `auto` and reworked
  runner lifecycle — the orphaned task problem may be resolved upstream, making
  `_tor_refresh_loop` patching unnecessary.
- Python 3.12 further tightened `asyncio` shutdown; the problem could recur or
  disappear depending on task scheduling changes.

---

## Notes for Future Maintainers

**Adding new background task creators:** If a new module spawns long-lived asyncio
tasks via `create_task()`, add its refresh/loop method to `_no_real_network` using
the same `), patch(` pattern. The existing `_noop` coroutine is reused:

```python
with patch("src.security.new_module.NewClass._refresh_loop", new=_noop), \
     patch("src.security.asn_classifier.ASNClassifier._refresh_tor_list", new=_noop), \
     patch("src.security.asn_classifier.ASNClassifier._tor_refresh_loop", new=_noop):
    yield
```

**The `os._exit()` call must stay.** It is a safety net for future hangs that occur
*after* session teardown rather than before it. Removing it would re-expose the
original interpreter-shutdown hang that the `trylast=True` hook was written to prevent.

**Do not add `pyproject.toml` to the Docker image.** The test suite runs in STRICT
asyncio mode — every async test has an explicit `@pytest.mark.asyncio` marker.
Mounting `pyproject.toml` into the container would switch asyncio mode to `auto`
(our `pyproject.toml` sets `asyncio_mode = "auto"` for local development) and could
silently alter test behaviour in Docker vs local runs.

**Why not fix the source code instead?** The correct long-term fix is for
`ASNClassifier` (and similar classes) to accept a shutdown event or task group so
background loops are properly cancelled by the caller rather than orphaned. That
requires interface changes across the pipeline and is deferred. The session-level
patch is a pragmatic workaround that keeps the test suite runnable without altering
production behaviour.
