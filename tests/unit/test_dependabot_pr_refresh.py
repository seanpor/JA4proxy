"""
tests/unit/test_dependabot_pr_refresh.py

Unit tests for scripts/dependabot_pr_refresh.py -- Phase 812 (812-D).
"""
from __future__ import annotations

import sys
from pathlib import Path

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import dependabot_pr_refresh as refresh  # noqa: E402


def test_passing_checks_never_refresh():
    should, remove, add = refresh.decide([], "abc1234", checks_passing=True)
    assert should is False
    assert add is None


def test_passing_checks_cleans_up_stale_nudge_label():
    should, remove, add = refresh.decide(["nudged:oldsha1"], "abc1234", checks_passing=True)
    assert should is False
    assert remove == "nudged:oldsha1"
    assert add is None


def test_failing_checks_first_time_refreshes():
    should, remove, add = refresh.decide([], "abc1234", checks_passing=False)
    assert should is True
    assert remove is None
    assert add == "nudged:abc1234"


def test_failing_checks_same_head_sha_already_nudged_is_skipped():
    """The core anti-spam rule: a PR failing for a REAL reason must not get
    re-nudged on every subsequent unrelated main push.
    """
    should, remove, add = refresh.decide(["nudged:abc1234"], "abc1234", checks_passing=False)
    assert should is False


def test_failing_checks_new_head_sha_refreshes_again():
    """A genuinely new commit (real push to the PR branch, not just main
    moving) changes the head SHA, so the old nudge label no longer matches
    and it's eligible again.
    """
    should, remove, add = refresh.decide(["nudged:oldsha1"], "newsha2", checks_passing=False)
    assert should is True
    assert remove == "nudged:oldsha1"
    assert add == "nudged:newsha2"


def test_other_labels_are_left_alone():
    should, remove, add = refresh.decide(
        ["dependencies", "nudged:oldsha1", "python"], "newsha2", checks_passing=False
    )
    assert should is True
    assert remove == "nudged:oldsha1"
    assert add == "nudged:newsha2"


def test_cli_refresh_output_format(capsys):
    rc = refresh.main(["--head-sha", "abc1234", "--checks-passing", "false", "--labels", ""])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "REFRESH - nudged:abc1234"


def test_cli_skip_output_format(capsys):
    rc = refresh.main(
        ["--head-sha", "abc1234", "--checks-passing", "false", "--labels", "nudged:abc1234"]
    )
    assert rc == 0
    assert "SKIP" in capsys.readouterr().out
