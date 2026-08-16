- **Failing tests now say why they failed (Phase 823)**: `tests/conftest.py`
  ended the pytest session with `os._exit()` inside Docker, which terminates the
  process *before* pytest's terminal reporter writes the `FAILURES` section and
  short summary. Every Python test in this project runs in a container, so
  **every failure printed `F` and nothing else** — no traceback, no assertion
  message. It survived because the exit code stayed correct: CI went red, just
  uninformatively. The guard was not gratuitous (asyncio teardown hanging the
  container), so the fix was chosen by measurement, not assumption: `trylast=True`
  — the obvious minimal fix — **does not work**, because the terminal reporter's
  own `sessionfinish` runs in the same phase and ordering alone does not decide
  the winner; and the hang itself no longer reproduces on the current
  pytest/pytest-asyncio/base image (1864 unit tests in xdist *and* serial, plus
  751 management tests, all exiting cleanly in seconds without it). The hook is
  therefore deleted rather than reordered. `tests/unit/test_pytest_reporting.py`
  runs real pytest subprocesses to assert the assertion message is visible in
  both modes, and an AST guard — verified to fail on reintroduction — stops
  `os._exit()` coming back. Rescued from the `handoff-to-deepseek` branch, where
  it had been written as Phase 816 and never entered `manifest.yaml`; 816 was
  later taken by an unrelated phase, hence the renumber.
