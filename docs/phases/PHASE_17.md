# PHASE 17 — Fix Docker Test Container Hang

## Status: IN PROGRESS

### What Is Already Done

| Fix | File(s) | Status |
|-----|---------|--------|
| Add `PYTHONUNBUFFERED=1` | `docker/Dockerfile.test`, `docker-compose.poc.yml` | ✅ Done |
| Patch `_tor_refresh_loop` in `_no_real_network` | `tests/conftest.py` | ❌ Not done |
| Change `pytest_sessionfinish` to `tryfirst=True` | `tests/conftest.py` | ❌ Not done |

**Start here.** Read the root cause analysis below so you understand *why* each fix is
needed, then implement the two remaining changes in `tests/conftest.py`.

---

## Problem Description

`make test` (inside the Docker test container) shows all tests passing in ~35 s, then
the container hangs for ~265 s until `timeout 300` kills it. The run reports
`Passed: 0` and `OVERALL RESULT: TESTS TIMED OUT`.

```
tests/unit/security/test_threat_tier.py::...::test_max_gdpr_durations_allowed PASSED [100%]
✗ Tests timed out after 300 seconds

Test Statistics:
  ✓ Passed: 0          ← summary line was never written (buffer lost on kill)
  ⏱ Duration: unknown

✗ OVERALL RESULT: TESTS TIMED OUT
real    5m0.032s
```

---

## Root Cause Analysis

### Where the hang is NOT

The original plan (now recorded as incorrect) claimed the hang was in Python 3.11's
interpreter shutdown phase — i.e., after pytest fully exited, the GC was trying to
finalize orphaned `asyncio.Task` objects. A `pytest_sessionfinish(trylast=True)` hook
with `os._exit()` was added to bypass this. **It did not fix the hang.**

### Where the hang actually is

The hang is **inside pytest**, before `pytest_sessionfinish` is ever called.
Evidence:

1. The terminal reporter prints "N passed in Xs" inside its own `pytest_sessionfinish`
   hook. That line never appears in the results file, so `pytest_sessionfinish` never
   runs.

2. The hang must therefore be in **session fixture teardown**, which in pytest 7.4.3
   runs as part of `SetupState.__exit__()` — called after all tests complete but
   before any `pytest_sessionfinish` hooks fire.

### The actual hang mechanism

pytest-asyncio 0.21.1 creates a `_function_scoped_runner` fixture for each async test.
This fixture's teardown calls `runner.__exit__()` → `Runner.close()`.

In **Python 3.11**, `asyncio.Runner.close()` does:

```python
_cancel_all_tasks(loop)                              # cancels pending tasks
loop.run_until_complete(loop.shutdown_asyncgens())   # closes async generators
loop.run_until_complete(loop.shutdown_default_executor())  # waits for thread pool
loop.close()
```

The `_cancel_all_tasks(loop)` step calls:

```python
loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))
```

If any task does not finish promptly after cancellation, this `run_until_complete`
blocks indefinitely.

### Which tasks are orphaned

`ASNClassifier._init_tor_list()` (called on first `signals()` invocation) does:

```python
asyncio.create_task(self._tor_refresh_loop(refresh_interval))
```

`_tor_refresh_loop` sleeps for `refresh_interval` seconds (default 3600 s) in a loop.
It does catch `asyncio.CancelledError` and breaks — so it *should* be fast to cancel.
However, in Python 3.11 the combination of:

- many such tasks across 1583+ tests
- pytest-asyncio's `_function_scoped_runner` lifecycle
- Python 3.11's stricter asyncio cleanup behaviour

causes the runner teardown to block long enough to hit the 300 s wall.

Similar long-lived task creators also present:
- `blocklists.py`: `asyncio.create_task(self._refresh_loop(feed_cfg))`
- `dns_enrichment.py`: `asyncio.create_task(self._worker_with_restart(i))`

### Secondary issue: summary line never flushed (ALREADY FIXED)

The Docker test container previously did not set `PYTHONUNBUFFERED=1`. Python inside
Docker uses block-buffered stdout. The "N passed in Xs" summary line was buffered but
never flushed to `tee` before the process was killed, causing `Passed: 0` even when
all tests actually passed.

**This is fixed.** `docker/Dockerfile.test` and `docker-compose.poc.yml` both set
`PYTHONUNBUFFERED=1`.

---

## Files to Change

| File | Change |
|------|--------|
| `tests/conftest.py` | Patch `_tor_refresh_loop` → `_noop` in `_no_real_network` fixture |
| `tests/conftest.py` | Change `pytest_sessionfinish` hook to `tryfirst=True` |

---

## Implementation Guide

### Fix 2: Patch `_tor_refresh_loop` in `_no_real_network` (conftest.py)

**File:** `tests/conftest.py`

**Find** the `_no_real_network` session fixture (~line 153). It currently patches only
`_refresh_tor_list` (the HTTP download function). It must **also** patch
`_tor_refresh_loop` so that `asyncio.create_task(self._tor_refresh_loop(interval))`
creates a task that returns immediately instead of sleeping for 3600 s.

```python
# BEFORE — only patches the download, not the loop
@pytest.fixture(autouse=True, scope="session")
def _no_real_network():
    """Prevent real HTTP calls to torproject.org during the test session.
    ...
    """
    async def _noop(*args, **kwargs):
        pass

    with patch(
        "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
        new=_noop,
    ):
        yield


# AFTER — patches both the download AND the long-running loop
@pytest.fixture(autouse=True, scope="session")
def _no_real_network():
    """Prevent real HTTP calls and long-running background loops during tests.

    ASNClassifier._refresh_tor_list downloads the Tor exit node list on first
    use. ASNClassifier._tor_refresh_loop sleeps 3600 s between refreshes and
    creates an orphaned asyncio Task that blocks pytest teardown in Python 3.11.

    Both are patched to async no-ops. Chaos tests that need to exercise real
    refresh logic use patch.object on the specific instance instead.
    """
    async def _noop(*args, **kwargs):
        pass

    with patch(
        "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
        new=_noop,
    ), patch(
        "src.security.asn_classifier.ASNClassifier._tor_refresh_loop",
        new=_noop,
    ):
        yield
```

### Fix 3: Change `pytest_sessionfinish` to `tryfirst=True` (conftest.py)

**File:** `tests/conftest.py`

**Find** the `pytest_sessionfinish` hook (~line 292). Change `trylast=True` to
`tryfirst=True`.

**Why:** The existing `trylast=True` hook never fires because the hang occurs *before*
pytest reaches session-finish hooks. Changing to `tryfirst=True` ensures `os._exit()`
fires as soon as pytest begins its session-finish phase — after all tests and their
function-scope fixture teardowns complete, but before any session-scope fixture teardown
or plugin cleanup that might hang.

Note on JUnit XML: the `--junitxml` report is written by a built-in pytest plugin that
also uses `pytest_sessionfinish`. With `tryfirst=True` our hook may run before the
JUnit writer. This is acceptable — the per-test verbose output written to `RESULTS_FILE`
via `tee` already contains full pass/fail detail; the JUnit XML is supplementary.

```python
# BEFORE
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus) -> None:
    ...

# AFTER
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus) -> None:
    ...
```

---

## Acceptance Criteria

- [ ] `time make test` (inside Docker) completes in ≤ 60 s (test run ~35 s + overhead)
- [ ] The results file contains the "N passed" summary line (not `Passed: 0`)
- [ ] Exit code from `make test` is 0
- [ ] No tests change from PASSED to FAILED as a result of these changes
- [ ] All 1583+ local tests still pass: `python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py`

---

## What Was Already Tried (and why it did not work)

| Attempt | Why it failed |
|---------|--------------|
| `pytest_sessionfinish(trylast=True)` + `os._exit()` | Hook never reached — hang occurs before session-finish hooks fire |

---

## Notes for Implementer

- Chaos tests that specifically test `_tor_refresh_loop` behaviour
  (`tests/chaos/test_asn_chaos.py`) patch the method themselves via
  `patch.object(instance, ...)` — they are unaffected by the session-level patch.
- If additional background loops are found to create orphaned tasks in future
  phases, add them to the `_no_real_network` patch list using the same pattern.
- The `os._exit()` safety net is still correct and should be kept. It handles
  any *future* hang that might occur after session teardown.
- Do **not** add `pyproject.toml` to the Docker image or docker-compose volumes.
  The tests run correctly in STRICT asyncio mode (all async tests have explicit
  `@pytest.mark.asyncio` markers). Adding pyproject.toml would change asyncio
  mode to AUTO and potentially affect test behaviour.
- Verify the fix by running `make test` (not just local pytest) since the hang
  only manifests inside the Docker container.
