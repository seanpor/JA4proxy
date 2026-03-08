# PHASE 17 — Fix Docker Test Container Hang

## Status: OPEN

---

## Problem Description

`make test` shows all 1174 tests passing in ~35s, then the Docker container hangs
for ~265s until `timeout 300` kills it. The run reports `Passed: 0` and
`OVERALL RESULT: TESTS TIMED OUT`.

### Observed symptoms

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

`_tor_refresh_loop` sleeps for `refresh_interval` seconds (default 3600s) in a loop.
It does catch `asyncio.CancelledError` and breaks — so it *should* be fast to cancel.
However, it appears that in Python 3.11 the combination of:

- many such tasks across 1174 tests
- pytest-asyncio's `_function_scoped_runner` lifecycle
- Python 3.11's stricter asyncio cleanup behavior

causes the runner teardown to block long enough to hit the 300s wall.

Similar long-lived task creators also present:
- `blocklists.py`: `asyncio.create_task(self._refresh_loop(feed_cfg))`
- `dns_enrichment.py`: `asyncio.create_task(self._worker_with_restart(i))`

### Secondary issue: missing PYTHONUNBUFFERED

The Docker test container does not set `PYTHONUNBUFFERED=1`. Python inside Docker
uses block-buffered stdout. The "1174 passed in Xs" summary line is buffered but
never flushed to `tee` before the process is killed, causing `Passed: 0` in the
summary even when all tests actually passed.

---

## Files to Change

| File | Change |
|------|--------|
| `docker/Dockerfile.test` | Add `ENV PYTHONUNBUFFERED=1` |
| `docker-compose.poc.yml` | Add `PYTHONUNBUFFERED: "1"` to test service environment |
| `tests/conftest.py` | Patch `_tor_refresh_loop` → `_noop` in `_no_real_network` fixture |
| `tests/conftest.py` | Change `pytest_sessionfinish` hook to `tryfirst=True` |

---

## Acceptance Criteria

- [ ] `time make test` completes in ≤ 60s (test run ~35s + overhead)
- [ ] Results file contains "1174 passed" summary line
- [ ] Exit code from `make test` is 0
- [ ] No tests change from PASSED to FAILED as a result of these changes

---

## Fix Details

### 1. Add PYTHONUNBUFFERED (Dockerfile.test and docker-compose.poc.yml)

`Dockerfile.test`:
```dockerfile
ENV PYTHONUNBUFFERED=1
```

`docker-compose.poc.yml` test service environment:
```yaml
environment:
  - PYTHONUNBUFFERED=1
```

### 2. Patch `_tor_refresh_loop` in `_no_real_network` (conftest.py)

The `_no_real_network` session fixture currently only patches `_refresh_tor_list`
(the HTTP download). It must also patch `_tor_refresh_loop` so that
`asyncio.create_task(self._tor_refresh_loop(interval))` creates a task that
completes immediately rather than sleeping for 3600s.

```python
# Before
with patch(
    "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
    new=_noop,
):
    yield

# After
with patch(
    "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
    new=_noop,
), patch(
    "src.security.asn_classifier.ASNClassifier._tor_refresh_loop",
    new=_noop,
):
    yield
```

Update the fixture docstring to accurately describe what is patched (it currently
says it patches both, which was aspirational not actual).

### 3. Change `pytest_sessionfinish` to `tryfirst=True` (conftest.py)

The existing `trylast=True` hook never fires because the hang precedes it.
Changing to `tryfirst=True` ensures `os._exit()` fires as soon as pytest begins
its session-finish phase — after all tests and their function-scope fixture
teardowns complete, but before any session-scope fixture teardown or plugin
cleanup that might hang.

The JUnit XML written by `--junitxml` is produced by pytest's built-in junitxml
plugin, which also uses `pytest_sessionfinish`. With `tryfirst=True` our hook
may run before the JUnit writer. This is acceptable: the per-test verbose output
(in RESULTS_FILE via `tee`) already contains full pass/fail detail; the JUnit XML
is supplementary.

```python
# Before
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    ...

# After
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    ...
```

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
