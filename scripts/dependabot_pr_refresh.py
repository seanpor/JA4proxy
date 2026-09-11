#!/usr/bin/env python3
"""Decide whether a Dependabot PR needs a stale-CI refresh or cascading rebase (Phase 812, Phase 830).

Pure decision logic, kept separate from the gh-CLI orchestration (listing
PRs, checking status, applying labels, closing/reopening, updating branch) that
lives in .github/workflows/dependabot-pr-refresh.yml -- so the dedup rule itself
is unit-testable without mocking the GitHub API.

The rules:
1. If merge_state is "behind" (and checks are not currently failing):
   Action: UPDATE_BRANCH (calls GitHub API to update/rebase branch onto main).
2. If merge_state is "dirty" (merge conflicts):
   Action: CONFLICT_REBASE (comments @dependabot rebase to regenerate against main).
3. If checks are failing:
   A PR gets refreshed (close/reopen) at most ONCE per head SHA. A
   `nudged:<short-sha>` label marks "already refreshed at this commit".
   Action: REFRESH <remove-label-or--> <add-label>.
4. Otherwise:
   Action: SKIP <reason>.

CLI usage (one PR at a time, called from the workflow):
    python3 dependabot_pr_refresh.py --head-sha <sha> --checks-passing <true|false> --labels <comma-separated> [--merge-state <state>]
Prints one line: "UPDATE_BRANCH", "CONFLICT_REBASE", "REFRESH <remove> <add>", or "SKIP <reason>".
"""
from __future__ import annotations

import argparse
import sys

NUDGE_PREFIX = "nudged:"


def decide(
    labels: list[str],
    head_sha_short: str,
    checks_passing: bool,
    merge_state: str = "clean",
):
    """Returns (action, label_to_remove_or_None, label_to_add_or_None, reason).

    Actions:
    - ("REFRESH", remove_label, add_label, reason)
    - ("UPDATE_BRANCH", remove_label, None, reason)
    - ("CONFLICT_REBASE", None, None, reason)
    - ("SKIP", remove_label_or_None, None, reason)
    """
    target_label = f"{NUDGE_PREFIX}{head_sha_short}"
    existing_nudge = next((label for label in labels if label.startswith(NUDGE_PREFIX)), None)

    # If merge conflict, dependabot needs to regenerate the PR
    if merge_state == "dirty":
        return "CONFLICT_REBASE", None, None, "merge conflict"

    # If checks are failing, apply anti-spam refresh logic
    if not checks_passing:
        if existing_nudge == target_label:
            return "SKIP", None, None, "already refreshed at this head SHA"
        return "REFRESH", existing_nudge, target_label, "checks failing"

    # Checks are passing or clean: clean up any stale nudge label
    stale_label = existing_nudge

    # If branch is behind main, rebase/update it onto main so auto-merge can land it
    if merge_state == "behind":
        return "UPDATE_BRANCH", stale_label, None, "branch behind main"

    return "SKIP", stale_label, None, "checks passing and branch up to date"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--checks-passing", required=True, choices=["true", "false"])
    ap.add_argument("--labels", default="", help="comma-separated current labels")
    ap.add_argument("--merge-state", default="clean", help="mergeable_state from GitHub API")
    args = ap.parse_args(argv)

    labels = [label for label in args.labels.split(",") if label]
    action, remove_label, add_label, reason = decide(
        labels,
        args.head_sha,
        args.checks_passing == "true",
        args.merge_state.lower(),
    )

    if action == "REFRESH":
        print(f"REFRESH {remove_label or '-'} {add_label}")
    elif action == "UPDATE_BRANCH":
        print(f"UPDATE_BRANCH {remove_label or '-'}")
    elif action == "CONFLICT_REBASE":
        print("CONFLICT_REBASE")
    else:
        print(f"SKIP {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
