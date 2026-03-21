# Phase 17 Detailed Work Plan: Docker Test Container Hang

## 1. Overview
The test suite passes successfully but the Docker container hangs for ~4 minutes before timing out. The root cause has been identified as a lingering background thread in the testing mock network (`_tor_refresh_loop`) and Pytest's session teardown behavior. 

## 2. Implementation Steps

### Step 1: Patch `_tor_refresh_loop`
**Goal:** Ensure the mock background loop terminates cleanly when the test session ends.
*   **Task:** Modify `tests/conftest.py`. Locate the mock `_no_real_network` fixture/patch.
*   **Action:** Ensure that the Tor refresh loop or any other background `asyncio` task spawned by the test fixtures is properly cancelled during the fixture's `yield` teardown phase.
*   **Code Example:**
    ```python
    @pytest.fixture(autouse=True)
    def stop_background_loops():
        yield
        # Code to patch/cancel the loop
    ```

### Step 2: Prioritize Session Finish
**Goal:** Ensure cleanup hooks run before other blocking teardowns.
*   **Task:** Modify `pytest_sessionfinish` hook in `tests/conftest.py`.
*   **Action:** Add the `@pytest.hookimpl(tryfirst=True)` decorator to ensure it executes immediately when the session finishes, aggressively terminating any lingering mock threads.

### Step 3: Validation
*   **Action:** Run `make test` inside the Docker container.
*   **Expectation:** The tests should execute (~35s) and the container should exit with code `0` immediately, instead of hanging for the 300s timeout.