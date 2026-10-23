#!/usr/bin/env python3
"""Ensure the commit on `main` was actually built (Phase 849, issue #622).

GitHub does not dispatch workflows for events caused by the default
`GITHUB_TOKEN` — the anti-recursion rule. A PR merged by the Actions app (the
auto-merge workflows, or any bot calling `gh pr merge` with that token) therefore
lands on `main` with **no `push` run at all**: `ci.yml`'s `push: branches: [main]`
trigger never fires, and the commit that is now the tip has never been built or
scanned. The PR's own checks were green before that commit existed.

This script answers one question — "does the commit on `main` have a CI run?" —
and, with `--apply`, repairs a "no" by dispatching `ci.yml` against `main`.

    python3 scripts/ensure_main_verified.py            # report the tip
    python3 scripts/ensure_main_verified.py --apply    # repair it
    python3 scripts/ensure_main_verified.py --sha X    # report an arbitrary commit

Exit codes: 0 verified (or dispatched), 1 unverified and not repaired, 2 could
not run. "Could not run" is never reported as "verified": an unverifiable main
is a fact an operator needs, not a green tick.

Deliberately *not* re-dispatching a run that exists but failed: the failure is
already visible on the commit, and re-running it would loop. "Verified" here
means the workflow **ran**, not that it passed.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Sequence

#: The workflow whose absence means "this commit was never built" (ci.yml's
#: `name:`). Matched by display name because that is what `gh run list` reports.
WORKFLOW_NAME = "CI"
#: The workflow file to dispatch when the tip is unverified.
WORKFLOW_FILE = "ci.yml"


def decide(runs: Sequence[dict], sha: str, workflow_name: str = WORKFLOW_NAME) -> dict:
    """Verdict for one commit, from its runs (pure — the whole test surface).

    `verified` means a run of `workflow_name` exists **for this commit**, in any
    state: queued and in-progress runs count (dispatching would duplicate them),
    and a completed run counts whatever its conclusion (it ran; a red run is a
    real, already-visible signal — re-dispatching it would loop forever).
    """
    matching = [
        run
        for run in runs
        if run.get("workflowName") == workflow_name and run.get("headSha") in (None, sha)
    ]
    if not matching:
        return {
            "verified": False,
            "reason": f"no {workflow_name} run exists for this commit",
        }
    run = matching[0]
    status = str(run.get("status") or "unknown")
    conclusion = run.get("conclusion")
    detail = status if status != "completed" else f"completed/{conclusion or 'unknown'}"
    return {
        "verified": True,
        "reason": f"{workflow_name} run is {detail}",
        "url": run.get("url") or "",
    }


def _gh(args: Sequence[str]) -> str:
    """Run one `gh` command; raise RuntimeError with its stderr on failure."""
    proc = subprocess.run(  # nosec B603, B607 -- fixed argv, no shell
        ["gh", *args], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"`gh {args[0]}` failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def repo_slug() -> str:
    return _gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]).strip()


def resolve_sha(sha: str) -> str:
    """Expand a short `--sha` to the full commit SHA, via the API (not local git).

    `gh run list --commit` matches **full** SHAs only. A short SHA silently
    matches nothing and reads as "unverified" — a false alarm, which for a
    verifier is worse than no verifier. Resolved through the API rather than
    `git rev-parse` so it also works in a shallow checkout.
    """
    if re.fullmatch(r"[0-9a-f]{40}", sha):
        return sha
    return _gh(["api", f"repos/{repo_slug()}/commits/{sha}", "--jq", ".sha"]).strip()


def main_tip() -> str:
    return _gh(["api", f"repos/{repo_slug()}/commits/main", "--jq", ".sha"]).strip()


def runs_for(sha: str) -> list[dict]:
    """Every recent run GitHub knows about for this commit."""
    out = _gh(
        [
            "run", "list",
            "--commit", sha,
            "--limit", "100",
            "--json", "workflowName,status,conclusion,headSha,url",
        ]
    )
    try:
        return json.loads(out)
    except ValueError as exc:  # a parse failure must not read as "no runs"
        raise RuntimeError(f"could not parse `gh run list` output: {exc}") from exc


def dispatch(ref: str = "main") -> None:
    _gh(["workflow", "run", WORKFLOW_FILE, "--ref", ref])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--sha",
        default="",
        help="report this commit instead of main's tip (implies report-only: a dispatch verifies main, not an old commit)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="dispatch CI against main when the tip is unverified",
    )
    parser.add_argument("--workflow-name", default=WORKFLOW_NAME)
    args = parser.parse_args(argv)

    try:
        sha = resolve_sha(args.sha) if args.sha else main_tip()
        verdict = decide(runs_for(sha), sha, args.workflow_name)
    except RuntimeError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    short = sha[:12]
    if verdict["verified"]:
        location = f" ({verdict['url']})" if verdict.get("url") else ""
        print(f"✓ {short} is verified: {verdict['reason']}{location}")
        return 0

    if args.sha:
        print(
            f"✗ {short} is on main with no {args.workflow_name} run — {verdict['reason']}",
            file=sys.stderr,
        )
        return 1

    if not args.apply:
        print(
            f"✗ main tip {short} is unverified — {verdict['reason']}; "
            f"pass --apply to dispatch {WORKFLOW_FILE}",
            file=sys.stderr,
        )
        return 1

    try:
        dispatch()
    except RuntimeError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    print(f"→ dispatched {WORKFLOW_FILE} against main: {short} was unverified ({verdict['reason']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
