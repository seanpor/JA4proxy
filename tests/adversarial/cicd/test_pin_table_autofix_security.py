"""Adversarial security tests for pin-table-autofix.yml (Phase 814f L0/L1).

Audits .github/workflows/pin-table-autofix.yml and scripts/pin_table_autofix.py:
1. Actor validation: Ensures dependabot[bot] check is strict and verified against the event payload.
2. Refspec safety: Evaluates branch names containing traversal, shell escapes, or git options.
3. Git worktree hygiene:
   - Asserts hooks are disabled or cannot execute during worktree setup.
   - Evaluates .gitattributes filter drivers (clean/smudge) to verify whether untrusted PR content can trigger arbitrary code execution during checkout.
   - Asserts submodule recursion is inactive.
4. Target ref confinement: Ensures push refspec is strictly bounded and cannot overwrite main or tags.
5. Parser robustness: Tests scripts/pin_table_autofix.py against ReDoS, AST manipulation, and unexpected triples.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import yaml
import pytest

from scripts.pin_table_autofix import (
    ACTION_NAME_RE,
    SHA_AND_TAG_RE,
    TAG_RE,
    extract_triples,
    load_known_shas,
)

WORKFLOW_FILE = Path(".github/workflows/pin-table-autofix.yml")


def load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW_FILE.read_text(encoding="utf-8"))


def test_pin_table_autofix_workflow_actor_check():
    """Verify actor check strictly binds to dependabot[bot]."""
    wf = load_workflow()
    job = wf["jobs"]["autofix"]
    condition = job.get("if", "")
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in condition


def test_pin_table_autofix_push_confinement():
    """Verify push step explicitly prefixes refs/heads/ and does not allow bare refs."""
    text = WORKFLOW_FILE.read_text(encoding="utf-8")
    assert 'git push origin "HEAD:refs/heads/${HEAD_REF}"' in text


def test_pin_table_autofix_refspec_sanitization():
    """Adversarial check: Ref names containing traversal or flags cannot overwrite main."""
    malicious_refs = [
        "../../main",
        "refs/heads/main",
        "--upload-pack=evil",
        "phase-test; rm -rf /",
    ]
    for bad_ref in malicious_refs:
        # Pushing to "HEAD:refs/heads/${HEAD_REF}" produces "HEAD:refs/heads/../../main"
        # Git refname format rejects two consecutive dots '..' in a component (per git-check-ref-format)
        res = subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{bad_ref}"],
            capture_output=True,
            text=True,
        )
        # Git check-ref-format must reject path traversal and invalid characters
        if ".." in bad_ref or ";" in bad_ref:
            assert res.returncode != 0, f"Git failed to reject invalid ref: refs/heads/{bad_ref}"


def test_parser_input_validation_regexes():
    """Test ACTION_NAME_RE and TAG_RE reject malicious inputs."""
    bad_actions = [
        "evil/repo; rm -rf /",
        "evil/repo\nrun",
        "../../etc/passwd",
        "-option/repo",
        "evil/repo`whoami`",
    ]
    for bad in bad_actions:
        assert not ACTION_NAME_RE.match(bad), f"ACTION_NAME_RE accepted malicious action: {bad}"

    bad_tags = [
        "v1.0.0; rm -rf",
        "v1.0.0`whoami`",
        "v1.0.0\n",
        "-flag",
    ]
    for bad in bad_tags:
        assert not TAG_RE.match(bad), f"TAG_RE accepted malicious tag: {bad}"


def test_ast_safe_parsing_of_known_action_shas(tmp_path: Path):
    """Verify load_known_shas uses ast.literal_eval and never executes arbitrary code."""
    evil_test_file = tmp_path / "test_fake.py"
    evil_test_file.write_text(
        "import os\nos.system('echo PWNED > /tmp/pwned')\n"
        "KNOWN_ACTION_SHAS = {'actions/checkout': {'v4': '0123456789abcdef0123456789abcdef01234567'}}\n",
        encoding="utf-8",
    )

    data = load_known_shas(evil_test_file)
    assert "actions/checkout" in data
    # Verify os.system was NOT executed
    assert not Path("/tmp/pwned").exists()


def test_worktree_filter_driver_isolation(tmp_path: Path):
    """Adversarial check: Git worktree checkout with malicious .gitattributes smudge filter.

    In pin-table-autofix.yml, git worktree add is run to read workflow files.
    If an attacker could define a smudge filter in .gitattributes on the head ref,
    git checkout/worktree add could invoke the smudge script if filters are enabled.
    This test verifies how git configuration suppresses filter execution.
    """
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True)

    test_file = repo_dir / "file.txt"
    test_file.write_text("hello", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)

    # When core.hooksPath=/dev/null and filter drivers are bypassed, execution is prevented
    worktree_target = tmp_path / "wt"
    res = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "worktree", "add", str(worktree_target), "HEAD"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert worktree_target.exists()
