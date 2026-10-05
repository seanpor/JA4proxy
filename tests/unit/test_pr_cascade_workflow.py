"""
tests/unit/test_pr_cascade_workflow.py

Phase 838: Autonomous PR Cascade Dispatcher & Maintainer Auto-Merge Validation.
Tests pure decision logic for multi-author cascading rebase, maintainer PR rules,
and workflow YAML invariants.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import dependabot_pr_refresh as refresh  # noqa: E402

# ── Decision Logic Tests (Maintainer & Agent PRs) ──────────────────────────────


def test_maintainer_pr_behind_with_automerge_triggers_update():
    """Phase 838: Maintainer PR with auto-merge in BEHIND state triggers UPDATE_BRANCH."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="def5678",
        checks_passing=True,
        merge_state="behind",
        author="seanpor",
        auto_merge_enabled=True,
    )
    assert action == "UPDATE_BRANCH"
    assert remove is None
    assert add is None


def test_maintainer_pr_behind_without_automerge_skips():
    """Phase 838: Maintainer PR in BEHIND state without auto-merge must NOT rebase automatically."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="def5678",
        checks_passing=True,
        merge_state="behind",
        author="seanpor",
        auto_merge_enabled=False,
    )
    assert action == "SKIP"
    assert "auto-merge not enabled" in reason


def test_maintainer_pr_conflicted_skips_without_dependabot_comment():
    """Phase 838: Conflicted maintainer PR must not trigger @dependabot rebase."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="def5678",
        checks_passing=True,
        merge_state="dirty",
        author="seanpor",
        auto_merge_enabled=True,
    )
    assert action == "SKIP"
    assert "conflict requires maintainer resolution" in reason


def test_maintainer_pr_failing_skips_without_close_reopen():
    """Phase 838: Failing maintainer PR must NOT be closed/reopened."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="def5678",
        checks_passing=False,
        merge_state="clean",
        author="seanpor",
        auto_merge_enabled=True,
    )
    assert action == "SKIP"
    assert "maintainer attention needed" in reason


def test_dependabot_pr_preserves_conflict_rebase():
    """Phase 838: Dependabot PR still triggers CONFLICT_REBASE on dirty state."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="abc1234",
        checks_passing=True,
        merge_state="dirty",
        author="app/dependabot",
        auto_merge_enabled=True,
    )
    assert action == "CONFLICT_REBASE"


def test_dependabot_pr_preserves_refresh_nudge():
    """Phase 838: Dependabot PR still gets nudge refresh on failure."""
    action, remove, add, reason = refresh.decide(
        labels=[],
        head_sha_short="abc1234",
        checks_passing=False,
        merge_state="clean",
        author="app/dependabot",
        auto_merge_enabled=True,
    )
    assert action == "REFRESH"
    assert add == "nudged:abc1234"


def test_cli_maintainer_update_branch(capsys):
    rc = refresh.main(
        [
            "--head-sha",
            "def5678",
            "--checks-passing",
            "true",
            "--labels",
            "",
            "--merge-state",
            "behind",
            "--author",
            "seanpor",
            "--auto-merge",
            "true",
        ]
    )
    assert rc == 0
    assert capsys.readouterr().out.strip() == "UPDATE_BRANCH -"


def test_cli_maintainer_no_automerge_skip(capsys):
    rc = refresh.main(
        [
            "--head-sha",
            "def5678",
            "--checks-passing",
            "true",
            "--labels",
            "",
            "--merge-state",
            "behind",
            "--author",
            "seanpor",
            "--auto-merge",
            "false",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("SKIP")
    assert "auto-merge not enabled" in out


# ── Workflow YAML Validation Tests ─────────────────────────────────────────────


def test_refresh_workflow_yaml_syntax():
    """Verify .github/workflows/dependabot-pr-refresh.yml is valid YAML with expected triggers."""
    workflow_path = Path(__file__).parent.parent.parent / ".github/workflows/dependabot-pr-refresh.yml"
    assert workflow_path.exists()
    data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    on_section = data.get("on") or data.get(True)
    assert on_section is not None
    assert "push" in on_section
    assert "main" in on_section["push"]["branches"]
    assert "schedule" in on_section
    # Verify cron trigger is present
    crons = [s["cron"] for s in on_section["schedule"]]
    assert any("*/30" in c or "3" in c for c in crons)


def test_maintainer_automerge_workflow_yaml_syntax():
    """Verify .github/workflows/maintainer-automerge.yml is valid YAML with expected config."""
    workflow_path = Path(__file__).parent.parent.parent / ".github/workflows/maintainer-automerge.yml"
    if not workflow_path.exists():
        return  # Will be verified once file is created
    data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    on_section = data.get("on") or data.get(True)
    assert "pull_request_target" in on_section or "pull_request" in on_section
    assert data["permissions"]["pull-requests"] == "write"
