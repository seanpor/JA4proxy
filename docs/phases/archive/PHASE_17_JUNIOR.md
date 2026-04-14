# PHASE 17 — Implementation Guide (Junior Dev)

> If you want to understand *why* these changes work, read
> [PHASE_17_SENIOR.md](PHASE_17_SENIOR.md) after you are done.
> You do not need it to complete this task.

---

## What You Are Fixing

`make test` inside Docker passes all tests but then hangs for ~4 minutes before
timing out and reporting `Passed: 0`. You are making two small edits to
`tests/conftest.py` to stop the hang.

## What Is Already Done

| Fix | Status |
|-----|--------|
| Add `PYTHONUNBUFFERED=1` to Dockerfile and docker-compose | ✅ Done — do not touch |
| Patch `_tor_refresh_loop` in `_no_real_network` | ❌ **You need to do this** |
| Change `pytest_sessionfinish` to `tryfirst=True` | ❌ **You need to do this** |

---

## Prerequisites

No Redis, no Docker, no running services needed for local verification.
You only need:
- The repo checked out
- Python dependencies installed:
  ```bash
  pip install -r requirements.txt -r requirements-test.txt
  ```

---

## Step 1 — Patch `_tor_refresh_loop`

**File:** `tests/conftest.py`

Find the fixture with this command:
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

Replace it with this:

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

> **The comma:** `with A, B:` is standard Python for applying two context managers
> at once. Do not add a second `with` keyword before the new `patch(...)` — it is
> joined to the first by a comma.

**Verify — run the test suite locally:**
```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -q
```
All tests must pass. If anything that was green before is now red, your edit has
a mistake — recheck the comma and indentation.

---

## Step 2 — Change `tryfirst=True`

Still in `tests/conftest.py`. Find the hook:
```bash
grep -n "pytest_sessionfinish" tests/conftest.py
```

You will see:
```python
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus) -> None:
```

Change `trylast=True` to `tryfirst=True`. That is the entire change — one word:
```python
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus) -> None:
```

**Verify — run the test suite locally again:**
```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -q
```
All tests must still pass.

---

## Step 3 — Verify in Docker

The hang only happens inside Docker. Build the test image and run it:

```bash
# Build (only needed the first time, or after Dockerfile changes)
docker compose -f deploy/docker/docker-compose.poc.yml build test

# Run — should complete in under 60 s
time docker compose -f deploy/docker/docker-compose.poc.yml run --rm test
```

**Success looks like:**
```
... 1583 passed in 35s ...
✓ Passed: 1583
✓ OVERALL RESULT: PASSED
real    0m40.123s
```

**Still broken looks like:**
```
✗ OVERALL RESULT: TESTS TIMED OUT
real    5m0.032s
```

If it still times out, go back and check both edits are saved correctly.

---

## Step 4 — Commit

```bash
git add tests/conftest.py
git commit -m "fix(tests): patch _tor_refresh_loop to prevent Docker test hang"
```

---

## Acceptance Criteria

- [ ] `time docker compose -f deploy/docker/docker-compose.poc.yml run --rm test` completes in ≤ 60 s
- [ ] Results output contains "N passed" (not `Passed: 0`)
- [ ] Exit code from the Docker run is 0
- [ ] `python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py` shows 1583+ passed locally
- [ ] No previously passing test is now failing
