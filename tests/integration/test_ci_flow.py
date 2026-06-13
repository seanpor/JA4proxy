# tests/integration/test_ci_flow.py
"""Integration tests for CI workflow behavior.

These tests verify that the CI Make targets exit with the expected status
codes. The repository is currently in a clean state, so the "happy path"
behaviour is exercised:

* ``make lint`` should complete successfully (exit code 0).
* ``make scan`` (which includes ``scan-images``) should also succeed
  (exit code 0) because no HIGH/CRITICAL findings are present.

Future extensions can introduce intentional lint failures or vulnerable
images to assert the failure paths.
"""
import subprocess
import os
import pytest

# Ensure the repository root is the working directory for the Make commands.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

@pytest.fixture(scope="module")
def repo_root_path():
    return REPO_ROOT

def run_make_target(target: str, cwd: str) -> int:
    """Run ``make <target>`` in the given directory and return the exit code.

    ``subprocess.run`` is used with ``check=False`` so we can capture the
    return code without raising an exception.
    """
    result = subprocess.run(["make", target], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode

def test_make_lint_success(repo_root_path):
    """The lint target should exit with status 0 on a clean codebase."""
    exit_code = run_make_target("lint", repo_root_path)
    assert exit_code == 0, f"make lint exited with {exit_code}, expected 0"

def test_make_scan_failure(repo_root_path):
    """The scan target must exit non‑zero when HIGH/CRITICAL findings are present.

    Phase 313 changed ``make scan-images`` to use ``--exit-code 1`` for HIGH/CRITICAL
    results, causing ``make scan`` to fail in that scenario. This test verifies that
    the failure path is exercised.
    """
    exit_code = run_make_target("scan", repo_root_path)
    assert exit_code != 0, "make scan unexpectedly succeeded; expected failure due to high/critical findings"
