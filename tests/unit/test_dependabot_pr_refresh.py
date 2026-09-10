"""
tests/unit/test_dependabot_pr_refresh.py

Unit tests for scripts/dependabot_pr_refresh.py -- Phase 812 (812-D) & Phase 830.
"""
from __future__ import annotations

import sys
from pathlib import Path

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import dependabot_pr_refresh as refresh  # noqa: E402


def test_passing_checks_clean_merge_skips():
    action, remove, add, reason = refresh.decide([], "abc1234", checks_passing=True, merge_state="clean")
    assert action == "SKIP"
    assert add is None


def test_passing_checks_cleans_up_stale_nudge_label():
    action, remove, add, reason = refresh.decide(["nudged:oldsha1"], "abc1234", checks_passing=True, merge_state="clean")
    assert action == "SKIP"
    assert remove == "nudged:oldsha1"
    assert add is None


def test_failing_checks_first_time_refreshes():
    action, remove, add, reason = refresh.decide([], "abc1234", checks_passing=False)
    assert action == "REFRESH"
    assert remove is None
    assert add == "nudged:abc1234"


def test_failing_checks_same_head_sha_already_nudged_is_skipped():
    """The core anti-spam rule: a PR failing for a REAL reason must not get
    re-nudged on every subsequent unrelated main push.
    """
    action, remove, add, reason = refresh.decide(["nudged:abc1234"], "abc1234", checks_passing=False)
    assert action == "SKIP"
    assert "already refreshed" in reason


def test_failing_checks_new_head_sha_refreshes_again():
    """A genuinely new commit (real push to the PR branch, not just main
    moving) changes the head SHA, so the old nudge label no longer matches
    and it's eligible again.
    """
    action, remove, add, reason = refresh.decide(["nudged:oldsha1"], "newsha2", checks_passing=False)
    assert action == "REFRESH"
    assert remove == "nudged:oldsha1"
    assert add == "nudged:newsha2"


def test_branch_behind_triggers_update_branch():
    """Phase 830: When branch is behind main and checks are passing, cascade-rebase."""
    action, remove, add, reason = refresh.decide([], "abc1234", checks_passing=True, merge_state="behind")
    assert action == "UPDATE_BRANCH"
    assert remove is None
    assert add is None


def test_branch_behind_cleans_stale_nudge_label():
    action, remove, add, reason = refresh.decide(["nudged:oldsha1"], "abc1234", checks_passing=True, merge_state="behind")
    assert action == "UPDATE_BRANCH"
    assert remove == "nudged:oldsha1"


def test_branch_dirty_triggers_conflict_rebase():
    """Phase 830: When branch has merge conflicts, signal dependabot rebase."""
    action, remove, add, reason = refresh.decide([], "abc1234", checks_passing=True, merge_state="dirty")
    assert action == "CONFLICT_REBASE"


def test_other_labels_are_left_alone():
    action, remove, add, reason = refresh.decide(
        ["dependencies", "nudged:oldsha1", "python"], "newsha2", checks_passing=False
    )
    assert action == "REFRESH"
    assert remove == "nudged:oldsha1"
    assert add == "nudged:newsha2"


def test_cli_refresh_output_format(capsys):
    rc = refresh.main(["--head-sha", "abc1234", "--checks-passing", "false", "--labels", ""])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "REFRESH - nudged:abc1234"


def test_cli_update_branch_output_format(capsys):
    rc = refresh.main(["--head-sha", "abc1234", "--checks-passing", "true", "--labels", "", "--merge-state", "behind"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "UPDATE_BRANCH -"


def test_cli_conflict_rebase_output_format(capsys):
    rc = refresh.main(["--head-sha", "abc1234", "--checks-passing", "true", "--labels", "", "--merge-state", "dirty"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "CONFLICT_REBASE"


def test_cli_skip_output_format(capsys):
    rc = refresh.main(
        ["--head-sha", "abc1234", "--checks-passing", "false", "--labels", "nudged:abc1234"]
    )
    assert rc == 0
    assert "SKIP" in capsys.readouterr().out
