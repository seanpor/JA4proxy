#!/usr/bin/env python3
"""Decide whether a Dependabot PR needs a stale-CI refresh (Phase 812, 812-D).

Pure decision logic, kept separate from the gh-CLI orchestration (listing
PRs, checking status, applying labels, closing/reopening) that lives in
.github/workflows/dependabot-pr-refresh.yml -- so the dedup rule itself is
unit-testable without mocking the GitHub API.

The rule: a PR gets refreshed (close/reopen) at most ONCE per head SHA. A
`nudged:<short-sha>` label marks "already refreshed at this commit" -- if
the PR's checks are still failing after a real new commit changes the head
SHA, the label no longer matches and it gets refreshed again; if checks are
failing for a REAL, non-stale reason, it does NOT get re-refreshed on every
subsequent main push, which is the spam risk this rule specifically exists
to avoid (see docs/phases/PHASE_812.md's 812-D section).

CLI usage (one PR at a time, called from the workflow):
    python3 dependabot_pr_refresh.py --head-sha <sha> --checks-passing <true|false> --labels <comma-separated>
Prints one line: "REFRESH <remove-label-or-> <add-label>" or "SKIP <reason>".
"""
from __future__ import annotations

import argparse
import sys

NUDGE_PREFIX = "nudged:"


def decide(labels: list[str], head_sha_short: str, checks_passing: bool):
    """Returns (should_refresh, label_to_remove_or_None, label_to_add_or_None).

    Removing the stale nudged:<old-sha> label (if any) before adding the new
    one keeps exactly one nudged:* label on the PR at a time -- a second,
    smaller reason to remove it: an accumulating pile of one-per-push labels
    would be noise on a PR that fails for a long time.
    """
    target_label = f"{NUDGE_PREFIX}{head_sha_short}"
    existing_nudge = next((label for label in labels if label.startswith(NUDGE_PREFIX)), None)

    if checks_passing:
        # Nothing to refresh. If a stale nudge label is hanging around from
        # a previous failing commit, clean it up (cosmetic, not load-bearing).
        return False, existing_nudge, None

    if existing_nudge == target_label:
        return False, None, None  # already refreshed at this exact commit

    return True, existing_nudge, target_label


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--checks-passing", required=True, choices=["true", "false"])
    ap.add_argument("--labels", default="", help="comma-separated current labels")
    args = ap.parse_args(argv)

    labels = [label for label in args.labels.split(",") if label]
    should_refresh, remove_label, add_label = decide(
        labels, args.head_sha, args.checks_passing == "true"
    )

    if should_refresh:
        print(f"REFRESH {remove_label or '-'} {add_label}")
    else:
        reason = "checks passing" if args.checks_passing == "true" else "already refreshed at this head SHA"
        print(f"SKIP {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
