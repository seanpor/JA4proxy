"""
Phase 823 — a failing test must print its traceback and assertion message.

WHY THIS EXISTS
---------------
`tests/conftest.py` used to end the session with:

    @pytest.hookimpl(tryfirst=True)
    def pytest_sessionfinish(session, exitstatus):
        if os.path.exists("/.dockerenv") and not os.environ.get("PYTEST_XDIST_WORKER"):
            sys.stdout.flush(); sys.stderr.flush()
            os._exit(int(exitstatus))

`os._exit()` terminates the process immediately — before pytest's terminal
reporter writes the FAILURES section and short test summary. Every Python test
in this project runs inside a container, so **every** failure printed `F` and
nothing else: no traceback, no assertion message.

It hid in plain sight because the exit code was still correct, so CI went red —
just uninformatively. It cost real debugging time on more than one occasion.

The guard itself was reasonable (asyncio teardown hanging the container), but
Phase 823 re-measured and could not reproduce the hang on the current
pytest / pytest-asyncio / base image, so the hook was removed outright.

These tests run a real pytest subprocess so they assert on actual reporter
output rather than on how the code is written.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFTEST = REPO / "tests" / "conftest.py"

MARKER = "PROBE-MARKER-12345"

_FAILING_TEST = f'''
def test_deliberate_failure():
    assert False, "{MARKER}"
'''


def _run_pytest(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    """Run a deliberately failing test in a subprocess, inheriting our conftest."""
    testfile = tmp_path / "test_probe_failure.py"
    testfile.write_text(textwrap.dedent(_FAILING_TEST))
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(testfile), "-p", "no:cacheprovider", *extra],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=180,
    )


@pytest.mark.parametrize(
    "extra, label",
    [
        ((), "serial"),
        (("-n", "2", "--dist=loadfile"), "xdist"),
    ],
    ids=["serial", "xdist"],
)
def test_failure_output_includes_assertion_message(tmp_path, extra, label):
    """The whole point: a failure must say WHY it failed."""
    result = _run_pytest(tmp_path, *extra)
    combined = result.stdout + result.stderr

    assert result.returncode != 0, f"probe test should have failed ({label})"
    assert MARKER in combined, (
        f"[{label}] the assertion message was not printed. A failing test must "
        f"report its message, not just 'F'.\n"
        f"--- stdout ---\n{result.stdout[-2000:]}\n"
        f"--- stderr ---\n{result.stderr[-2000:]}"
    )


def test_failure_output_includes_a_failures_section(tmp_path):
    """pytest's FAILURES banner must survive session teardown."""
    result = _run_pytest(tmp_path)
    combined = result.stdout + result.stderr
    assert "FAILURES" in combined or "short test summary" in combined, (
        "neither the FAILURES section nor the short test summary was emitted — "
        "something is terminating the session before the reporter runs.\n"
        f"{combined[-2000:]}"
    )


def test_conftest_does_not_reintroduce_os_exit():
    """Source guard: os._exit() in a sessionfinish hook truncates reporting.

    Complements the behavioural tests above, which cannot run in every
    environment. Note `trylast=True` was tried during Phase 823 and does NOT
    fix the truncation — the terminal reporter's own sessionfinish runs in the
    same phase and ordering alone does not decide the winner. So do not
    "restore" the hook with trylast believing it is safe.
    """
    import ast

    tree = ast.parse(CONFTEST.read_text(encoding="utf-8"))
    offending = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_exit"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    ]
    assert not offending, (
        "tests/conftest.py calls os._exit() again — this truncates pytest's "
        f"FAILURES output inside Docker (phase-823). Line(s): {offending}"
    )
