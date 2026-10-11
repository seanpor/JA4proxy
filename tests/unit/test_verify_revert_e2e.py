"""End-to-end tests for scripts/verify_revert.sh (Phase 814a).

Validates that scripts/verify_revert.sh correctly handles:
1. True two-state proofs (fails pre-fix, passes post-fix -> exit 0).
2. Decorative tests (passes pre-fix and post-fix -> exit 1 with decoration error).
3. Environment/collection/compilation crashes (exit code 4/import failure -> exit 1 with crash error).
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import pytest

SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "scripts" / "verify_revert.sh"


def _init_scratch_repo(repo_dir: pathlib.Path) -> None:
    """Initialize a clean git repository with dummy user configuration."""
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)


def test_verify_revert_e2e_true_regression(tmp_path: pathlib.Path) -> None:
    """Test that verify_revert.sh succeeds on a genuine fix + test pair."""
    _init_scratch_repo(tmp_path)

    # 1. Commit initial buggy code
    src_file = tmp_path / "app.py"
    src_file.write_text("def is_admin(user: str) -> bool:\n    return True  # BUG: everyone is admin\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial buggy code"], cwd=tmp_path, check=True)

    # 2. Fix bug and add test
    src_file.write_text("def is_admin(user: str) -> bool:\n    return user == 'admin'\n")
    test_file = tmp_path / "test_app.py"
    test_file.write_text("from app import is_admin\n\ndef test_is_admin():\n    assert not is_admin('guest')\n")
    
    docs_dir = tmp_path / "docs" / "security"
    docs_dir.mkdir(parents=True, exist_ok=True)
    findings_yaml = docs_dir / "findings.yaml"
    
    subprocess.run(["git", "add", "app.py", "test_app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "fix security bug"], cwd=tmp_path, check=True)

    fix_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    findings_yaml.write_text(f"""
findings:
  - id: JA4PROXY-2026-9999
    severity: HIGH
    status: FIXED
    closed_commit: {fix_sha}
    regression_test: test_app.py::test_is_admin
""")

    env = {**os.environ, "REPO_ROOT": str(tmp_path)}
    res = subprocess.run(
        [str(SCRIPT_PATH), "JA4PROXY-2026-9999"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Expected 0, got {res.returncode}. Output:\n{res.stdout}\n{res.stderr}"
    assert "TWO-STATE PROOF HOLDS for JA4PROXY-2026-9999" in res.stdout


def test_verify_revert_e2e_decorative_test_failure(tmp_path: pathlib.Path) -> None:
    """Test that verify_revert.sh fails when a test passes pre-fix (decoration)."""
    _init_scratch_repo(tmp_path)

    # 1. Commit initial code
    src_file = tmp_path / "app.py"
    src_file.write_text("def val(): return 1\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial code"], cwd=tmp_path, check=True)

    # 2. Add decorative test that passes anywhere
    test_file = tmp_path / "test_app.py"
    test_file.write_text("def test_tautology():\n    assert True\n")
    
    docs_dir = tmp_path / "docs" / "security"
    docs_dir.mkdir(parents=True, exist_ok=True)
    findings_yaml = docs_dir / "findings.yaml"
    
    subprocess.run(["git", "add", "test_app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add decorative test"], cwd=tmp_path, check=True)

    fix_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    findings_yaml.write_text(f"""
findings:
  - id: JA4PROXY-2026-9998
    severity: LOW
    status: FIXED
    closed_commit: {fix_sha}
    regression_test: test_app.py::test_tautology
""")

    env = {**os.environ, "REPO_ROOT": str(tmp_path)}
    res = subprocess.run(
        [str(SCRIPT_PATH), "JA4PROXY-2026-9998"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    output = res.stdout + res.stderr
    assert res.returncode != 0
    assert "the test PASSES against pre-fix code" in output or "decoration" in output


def test_verify_revert_e2e_crash_rejection(tmp_path: pathlib.Path) -> None:
    """Test that verify_revert.sh rejects collection/import crashes in pre-fix code."""
    _init_scratch_repo(tmp_path)

    # 1. Commit initial code that crashes on import when test runs
    src_file = tmp_path / "app.py"
    src_file.write_text("import non_existent_module_xyz  # Crash on import\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial broken code"], cwd=tmp_path, check=True)

    # 2. Fix code to valid import
    src_file.write_text("def check(): return True\n")
    test_file = tmp_path / "test_app.py"
    test_file.write_text("import app\ndef test_check(): assert app.check()\n")
    
    docs_dir = tmp_path / "docs" / "security"
    docs_dir.mkdir(parents=True, exist_ok=True)
    findings_yaml = docs_dir / "findings.yaml"
    
    subprocess.run(["git", "add", "app.py", "test_app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "fix import and add test"], cwd=tmp_path, check=True)

    fix_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    findings_yaml.write_text(f"""
findings:
  - id: JA4PROXY-2026-9997
    severity: MEDIUM
    status: FIXED
    closed_commit: {fix_sha}
    regression_test: test_app.py::test_check
""")

    env = {**os.environ, "REPO_ROOT": str(tmp_path)}
    res = subprocess.run(
        [str(SCRIPT_PATH), "JA4PROXY-2026-9997"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    output = res.stdout + res.stderr
    assert res.returncode != 0
    assert "expected 1 for assertion failure" in output or "Environment crash" in output
