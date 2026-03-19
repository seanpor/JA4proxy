# PHASE 17 — Fix Docker Test Container Hang

## Status: IN PROGRESS

### What Is Already Done

| Fix | File(s) | Status |
|-----|---------|--------|
| Add `PYTHONUNBUFFERED=1` | `docker/Dockerfile.test`, `docker-compose.poc.yml` | ✅ Done |
| Patch `_tor_refresh_loop` in `_no_real_network` | `tests/conftest.py` | ❌ Not done |
| Change `pytest_sessionfinish` to `tryfirst=True` | `tests/conftest.py` | ❌ Not done |

**Two small edits to `tests/conftest.py` are all that remain.**
The root cause analysis is below if you want to understand why, but you do not need
to read it to make the changes.

---

## Step-by-Step: What to Do

### Prerequisites

No Redis, no Docker, no running services needed. You only need:
- The repo checked out
- Python dependencies installed (`pip install -r requirements.txt -r requirements-test.txt`)

---

### Step 1 — Make Fix 2 (patch `_tor_refresh_loop`)

**Open** `tests/conftest.py` and find the `_no_real_network` fixture.

To jump straight to it:
```bash
grep -n "_no_real_network" tests/conftest.py
```

You will see a block that looks like this:

```python
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
```

Change it to this (add a **comma** and a second `patch(...)` call — the comma between
two context managers in a `with` statement is standard Python):

```python
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

> **Note on the comma:** `with A, B:` is how Python applies two context managers at
> once. It is equivalent to `with A: with B:` but on one line. The comma is important
> — do not put `with` before the second `patch(...)`.

**Verify Step 1:**
```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -q
```
All tests must still pass. If any test that was passing before now fails, something
went wrong — check your edit.

---

### Step 2 — Make Fix 3 (change `tryfirst=True`)

Still in `tests/conftest.py`. Find the `pytest_sessionfinish` hook:
```bash
grep -n "pytest_sessionfinish" tests/conftest.py
```

You will see:
```python
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus) -> None:
```

Change `trylast=True` to `tryfirst=True`:
```python
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus) -> None:
```

That is the entire change — one word on one line.

**Verify Step 2:**
```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -q
```
All tests must still pass.

---

### Step 3 — Verify in Docker

The hang only manifests inside Docker (the local pytest run exits cleanly already).
Build and run the Docker test suite to confirm the fix:

```bash
# Build the test image (only needed once, or after Dockerfile changes)
docker compose -f docker-compose.poc.yml build test

# Run the tests — should complete in under 60 s
time docker compose -f docker-compose.poc.yml run --rm test
```

**What success looks like:**
```
... 1583 passed in 35s ...
✓ Passed: 1583
✓ OVERALL RESULT: PASSED
real    0m40.123s      ← well under the 5-minute timeout
```

**What failure still looks like** (if the fix did not work):
```
✗ OVERALL RESULT: TESTS TIMED OUT
real    5m0.032s
```

---

### Step 4 — Commit

```bash
git add tests/conftest.py
git commit -m "fix(tests): patch _tor_refresh_loop to prevent Docker test hang"
```

---

## Acceptance Criteria

- [ ] `time docker compose -f docker-compose.poc.yml run --rm test` completes in ≤ 60 s
- [ ] The results output contains "N passed" (not `Passed: 0`)
- [ ] Exit code from the Docker run is 0
- [ ] `python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py` still shows 1583+ passed locally
- [ ] No test that was passing before is now failing

---

## Root Cause Analysis

*(Background reading — you do not need this to make the changes.)*

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

### Why `tryfirst=True` helps

With `trylast=True`, the `os._exit()` hook never fires because the hang precedes the
entire session-finish phase. Changing to `tryfirst=True` means `os._exit()` fires at
the very start of session-finish — after all tests and their function-scope fixture
teardowns, but before any session-scope teardown that might hang.

Note: the `--junitxml` report is written by a pytest built-in that also uses
`pytest_sessionfinish`. With `tryfirst=True` our hook may run before the JUnit writer,
meaning the XML file might be incomplete. This is acceptable — the per-test verbose
output written to `RESULTS_FILE` via `tee` contains the full pass/fail record.

### Fix 1 (PYTHONUNBUFFERED) — already done

Python inside Docker uses block-buffered stdout by default. The "N passed in Xs"
summary line was buffered and never flushed to `tee` before the process was killed,
causing `Passed: 0` even when all tests passed. Setting `PYTHONUNBUFFERED=1` in
`docker/Dockerfile.test` and `docker-compose.poc.yml` fixed this.

---

## Notes for Future Maintainers

- Chaos tests that specifically test `_tor_refresh_loop` behaviour
  (`tests/chaos/test_asn_chaos.py`) patch the method themselves via
  `patch.object(instance, ...)` — they are unaffected by the session-level patch.
- If additional background loops are found to create orphaned tasks, add them to the
  `_no_real_network` patch list using the same `), patch(` pattern.
- The `os._exit()` call is intentional and must stay. It is the safety net for any
  *future* hang that occurs after session teardown rather than before it.
- Do **not** add `pyproject.toml` to the Docker image or docker-compose volumes.
  The tests run in STRICT asyncio mode (all async tests have explicit
  `@pytest.mark.asyncio` markers). Adding pyproject.toml would switch asyncio mode
  to AUTO and could silently change test behaviour.
