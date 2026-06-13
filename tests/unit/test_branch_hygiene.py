import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from scripts.branch_hygiene import (
    classify_branch,
    delete_local_branch,
    delete_remote_branch,
    get_commit_age_days,
    get_diff_stat,
    get_pr_info,
    get_unmerged_branches,
    run_cmd,
)


def test_run_cmd_success() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="hello\n", stderr="", returncode=0
        )
        stdout, stderr, code = run_cmd(["echo", "hello"])
        assert stdout == "hello"
        assert stderr == ""
        assert code == 0

def test_run_cmd_failure() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = Exception("failed to run")
        stdout, stderr, code = run_cmd(["echo", "hello"])
        assert stdout == ""
        assert "failed to run" in stderr
        assert code == -1

def test_get_unmerged_branches() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = (
            "  origin/branch1\n  origin/branch2\n  origin/main -> origin/somebranch\n",
            "",
            0
        )
        branches = get_unmerged_branches()
        assert branches == ["origin/branch1", "origin/branch2"]

def test_get_pr_info() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = (
            '[{"number":123,"title":"Test PR","state":"MERGED","url":"someurl"}]',
            "",
            0
        )
        pr_info = get_pr_info("origin/branch1")
        assert len(pr_info) == 1
        assert pr_info[0]["number"] == 123
        assert pr_info[0]["state"] == "MERGED"

def test_get_pr_info_invalid_json() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = ('invalid json', "", 0)
        pr_info = get_pr_info("origin/branch1")
        assert pr_info == []

def test_get_diff_stat() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = (" 1 file changed, 1 insertion(+)", "", 0)
        assert get_diff_stat("origin/branch1") == "1 file changed, 1 insertion(+)"

def test_get_commit_age_days() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        now = int(time.time())
        mock_run.return_value = (str(now - 10 * 24 * 3600), "", 0)
        age_days, ts = get_commit_age_days("origin/branch1")
        assert pytest.approx(age_days, 0.1) == 10.0
        assert ts == now - 10 * 24 * 3600

def test_classify_branch_active_with_open_pr() -> None:
    with patch("scripts.branch_hygiene.get_pr_info") as mock_pr, \
         patch("scripts.branch_hygiene.get_diff_stat") as mock_diff, \
         patch("scripts.branch_hygiene.get_commit_age_days") as mock_age:
        mock_pr.return_value = [{"number": 123, "title": "Open PR", "state": "OPEN", "url": "url"}]
        mock_diff.return_value = "diff stat"
        mock_age.return_value = (5.0, 0)
        
        category, info = classify_branch("origin/feature")
        assert category == "Active"
        assert info["pr_state"] == "OPEN"
        assert info["has_diff"] is True

def test_classify_branch_stale_merged_pr() -> None:
    with patch("scripts.branch_hygiene.get_pr_info") as mock_pr, \
         patch("scripts.branch_hygiene.get_diff_stat") as mock_diff, \
         patch("scripts.branch_hygiene.get_commit_age_days") as mock_age:
        mock_pr.return_value = [{"number": 123, "title": "Merged PR", "state": "MERGED", "url": "url"}]
        mock_diff.return_value = "diff stat"
        mock_age.return_value = (5.0, 0)
        
        category, info = classify_branch("origin/feature")
        assert category == "Stale"
        assert info["pr_state"] == "MERGED"

def test_classify_branch_stale_no_diff() -> None:
    with patch("scripts.branch_hygiene.get_pr_info") as mock_pr, \
         patch("scripts.branch_hygiene.get_diff_stat") as mock_diff, \
         patch("scripts.branch_hygiene.get_commit_age_days") as mock_age:
        mock_pr.return_value = []
        mock_diff.return_value = ""
        mock_age.return_value = (5.0, 0)
        
        category, info = classify_branch("origin/feature")
        assert category == "Stale"
        assert info["has_diff"] is False

def test_classify_branch_stale_abandoned_no_pr() -> None:
    with patch("scripts.branch_hygiene.get_pr_info") as mock_pr, \
         patch("scripts.branch_hygiene.get_diff_stat") as mock_diff, \
         patch("scripts.branch_hygiene.get_commit_age_days") as mock_age:
        mock_pr.return_value = []
        mock_diff.return_value = "some diff"
        mock_age.return_value = (35.0, 0)
        
        category, info = classify_branch("origin/feature")
        assert category == "Stale"
        assert info["age_days"] == 35.0

def test_classify_branch_dependabot() -> None:
    with patch("scripts.branch_hygiene.get_commit_age_days") as mock_age:
        mock_age.return_value = (12.0, 0)
        category, info = classify_branch("origin/dependabot/pip/somepkg")
        assert category == "Dependabot"
        assert info["branch"] == "origin/dependabot/pip/somepkg"

def test_delete_remote_branch_dry_run() -> None:
    assert delete_remote_branch("origin/stale", dry_run=True) is True

def test_delete_remote_branch_execution() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = ("", "", 0)
        assert delete_remote_branch("origin/stale", dry_run=False) is True
        mock_run.assert_called_with(["git", "push", "origin", "--delete", "stale"])

def test_delete_local_branch_dry_run() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.return_value = ("refinfo", "", 0)
        assert delete_local_branch("origin/stale", dry_run=True) is True

def test_delete_local_branch_execution() -> None:
    with patch("scripts.branch_hygiene.run_cmd") as mock_run:
        mock_run.side_effect = [
            ("refinfo", "", 0),
            ("", "", 0)
        ]
        assert delete_local_branch("origin/stale", dry_run=False) is True
