"""Parity tests: ja4proxy-cli policy commands vs scripts/ja4proxy-policy.py.

Skipped if Go toolchain not available or if binary fails to compile.
Tests assert matching exit codes (not message text) for policy YAML inputs.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PYTHON_SCRIPT = os.path.join(REPO_ROOT, "scripts", "ja4proxy-policy.py")
CLI_BINARY = os.path.join(REPO_ROOT, "_build", "ja4proxy-cli")


@pytest.fixture(scope="session")
def cli_binary():
    """Compile the Go CLI binary. Skip if go toolchain not available."""
    os.makedirs(os.path.join(REPO_ROOT, "_build"), exist_ok=True)

    result = subprocess.run(
        ["go", "build", "-o", CLI_BINARY, "./cmd/ja4proxy-cli/"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "GOROOT": os.environ.get("GOROOT", "/snap/go/current")},
        timeout=120,
    )
    if result.returncode != 0:
        pytest.skip(f"Failed to compile ja4proxy-cli: {result.stderr}")
    return CLI_BINARY


VALID_MINIMAL = textwrap.dedent("""\
    meta:
      version: "1.0"
      environment: prod
      last_updated: "2026-04-01T00:00:00Z"
      last_updated_by: "ops@example.com"
    dial:
      setting: 10
      changed_by: "ops@example.com"
""")

# Tab indent — illegal YAML.
INVALID_SYNTAX = "meta:\n\tversion: '1.0'\n"

# dial.setting above the allowed maximum of 100.
INVALID_DIAL = VALID_MINIMAL.replace("setting: 10", "setting: 150")

# Unknown top-level key — should be rejected by strict schema validation.
UNKNOWN_FIELD = VALID_MINIMAL + "\nrogue_key:\n  value: true\n"

# Malformed JA4 fingerprint in the allowlist.
INVALID_JA4 = VALID_MINIMAL + textwrap.dedent("""\
    allowlist:
      fingerprints:
        - ja4: "bad_fingerprint"
          reason: "test"
          added_by: "ops@example.com"
""")


@pytest.mark.parametrize(
    "yaml_text,expected_exit",
    [
        pytest.param(VALID_MINIMAL, 0, id="valid_minimal"),
        pytest.param(INVALID_SYNTAX, 1, id="invalid_syntax"),
        pytest.param(INVALID_DIAL, 1, id="invalid_dial"),
        pytest.param(UNKNOWN_FIELD, 1, id="unknown_field"),
        pytest.param(INVALID_JA4, 1, id="invalid_ja4"),
    ],
)
def test_validate_parity(tmp_path, cli_binary, yaml_text, expected_exit):
    """Python script and Go CLI must return the same exit code for 'validate'.

    The Python script is the source of truth for expected exit codes. The Go CLI
    must match Python's exit code for each input. Message text may differ.
    """
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml_text)

    py_result = subprocess.run(
        [sys.executable, PYTHON_SCRIPT, "validate", "--file", str(policy_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=30,
    )
    go_result = subprocess.run(
        [cli_binary, "policy", "validate", "--file", str(policy_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=30,
    )

    assert py_result.returncode == expected_exit, (
        f"Python script returned {py_result.returncode}, expected {expected_exit}. "
        f"stderr: {py_result.stderr.decode(errors='replace')}"
    )
    assert go_result.returncode == py_result.returncode, (
        f"Go CLI returned {go_result.returncode}, "
        f"Python returned {py_result.returncode}. "
        f"Go stderr: {go_result.stderr.decode(errors='replace')}"
    )


def test_python_script_exists():
    """Verify the Python stopgap script is present (regression guard)."""
    assert os.path.isfile(PYTHON_SCRIPT), (
        f"Python policy script not found at {PYTHON_SCRIPT}. "
        "It should exist until Go CLI parity is confirmed."
    )


def test_python_validate_valid_exits_zero(tmp_path):
    """Standalone check: Python 'validate' exits 0 for a valid policy."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_MINIMAL)

    result = subprocess.run(
        [sys.executable, PYTHON_SCRIPT, "validate", "--file", str(policy_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"Python script returned {result.returncode} for valid policy. "
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


def test_python_validate_invalid_exits_nonzero(tmp_path):
    """Standalone check: Python 'validate' exits non-zero for an invalid policy."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(INVALID_DIAL)

    result = subprocess.run(
        [sys.executable, PYTHON_SCRIPT, "validate", "--file", str(policy_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0, (
        "Python script returned 0 for invalid policy (dial=150). "
        "Expected non-zero exit code."
    )


@pytest.mark.parametrize(
    "yaml_text,expected_exit",
    [
        pytest.param(VALID_MINIMAL, 0, id="valid"),
        pytest.param(INVALID_SYNTAX, 1, id="invalid_syntax"),
        pytest.param(INVALID_DIAL, 1, id="invalid_dial"),
    ],
)
def test_go_cli_validate_exit_codes(tmp_path, cli_binary, yaml_text, expected_exit):
    """Standalone Go CLI exit code tests (independent of Python parity)."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml_text)

    go_result = subprocess.run(
        [cli_binary, "policy", "validate", "--file", str(policy_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=30,
    )
    assert go_result.returncode == expected_exit, (
        f"Go CLI returned {go_result.returncode}, expected {expected_exit}. "
        f"stderr: {go_result.stderr.decode(errors='replace')}"
    )
