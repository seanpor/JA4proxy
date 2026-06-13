#!/usr/bin/env python3
"""Automates Git branch hygiene analysis and stale branch cleanup.

This script identifies stale branches by comparing them to origin/main using
git diff and checking the status of associated GitHub pull requests.
"""

import argparse
import json
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple


def run_cmd(args: List[str]) -> Tuple[str, str, int]:
    """Runs a shell command safely without using shell=True."""
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), -1

def get_unmerged_branches() -> List[str]:
    """Gets list of remote tracking branches not merged into origin/main."""
    out, _, code = run_cmd(["git", "branch", "-r", "--no-merged", "origin/main"])
    if code != 0:
        return []
    branches = []
    for line in out.splitlines():
        line = line.strip()
        if line and " -> " not in line:
            branches.append(line)
    return branches

def get_pr_info(branch_name: str) -> List[Dict[str, Any]]:
    """Gets pull request information for a given branch from GitHub CLI."""
    short_name = branch_name.replace("origin/", "")
    args = [
        "gh", "pr", "list",
        "--head", short_name,
        "--state", "all",
        "--json", "number,title,state,url"
    ]
    out, _, code = run_cmd(args)
    if code != 0 or not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []

def get_diff_stat(branch_name: str) -> str:
    """Returns the diff stat against origin/main."""
    out, _, _ = run_cmd(["git", "diff", "origin/main..." + branch_name, "--stat"])
    return out.strip()

def get_commit_age_days(branch_name: str) -> Tuple[float, int]:
    """Returns the age of the latest commit on the branch in days and timestamp."""
    out, _, code = run_cmd(["git", "log", "-1", "--format=%ct", branch_name])
    if code != 0 or not out:
        return 999.0, 0
    try:
        commit_time = int(out)
        age_seconds = time.time() - commit_time
        age_days = age_seconds / (24 * 3600)
        return age_days, commit_time
    except Exception:
        return 999.0, 0

def classify_branch(branch: str) -> Tuple[str, Dict[str, Any]]:
    """Classifies a branch as Active, Stale, or Dependabot."""
    if "origin/main" in branch:
        return "Skip", {}
    
    age_days, _ = get_commit_age_days(branch)
    
    if "dependabot/" in branch:
        return "Dependabot", {"branch": branch, "age_days": age_days}

    prs = get_pr_info(branch)
    diff = get_diff_stat(branch)

    pr_desc = "No PR"
    pr_state = None
    if prs:
        pr_desc = f"PR #{prs[0]['number']} ({prs[0]['state']}): {prs[0]['title']}"
        pr_state = prs[0]['state']

    has_diff = len(diff) > 0

    info = {
        "branch": branch,
        "pr": pr_desc,
        "pr_state": pr_state,
        "has_diff": has_diff,
        "diff_stat": diff,
        "age_days": age_days
    }

    # Stale conditions:
    # 1. Associated PR is MERGED or CLOSED
    # 2. No code diff against main
    # 3. No PR and age is > 30 days (Abandoned)
    if pr_state in ("MERGED", "CLOSED") or not has_diff or (not pr_state and age_days > 30):
        return "Stale", info
    
    return "Active", info

def delete_remote_branch(branch: str, dry_run: bool) -> bool:
    """Deletes the remote branch."""
    short_name = branch.replace("origin/", "")
    print(f"[Action] Deleting remote branch: {short_name}")
    if dry_run:
        print(f"  [Dry-run] git push origin --delete {short_name}")
        return True
    
    _, err, code = run_cmd(["git", "push", "origin", "--delete", short_name])
    if code == 0:
        print(f"  Successfully deleted remote branch {short_name}")
        return True
    else:
        print(f"  Failed to delete remote branch {short_name}: {err}", file=sys.stderr)
        return False

def delete_local_branch(branch: str, dry_run: bool) -> bool:
    """Deletes local tracking branch if it exists."""
    short_name = branch.replace("origin/", "")
    _, _, code = run_cmd(["git", "show-ref", "--verify", f"refs/heads/{short_name}"])
    if code != 0:
        return True

    print(f"[Action] Deleting local branch: {short_name}")
    if dry_run:
        print(f"  [Dry-run] git branch -D {short_name}")
        return True

    _, err, code = run_cmd(["git", "branch", "-D", short_name])
    if code == 0:
        print(f"  Successfully deleted local branch {short_name}")
        return True
    else:
        print(f"  Failed to delete local branch {short_name}: {err}", file=sys.stderr)
        return False

def main() -> None:
    parser = argparse.ArgumentParser(description="JA4proxy Git Branch Hygiene Tool")
    parser.add_argument("--delete", action="store_true", help="Perform actual deletion of stale branches")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Default dry-run mode (does not delete)")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="Disable dry-run mode")
    args = parser.parse_args()

    is_dry_run = True
    if args.delete and not args.dry_run:
        is_dry_run = False
    
    if args.delete and is_dry_run:
        print("WARNING: --delete was specified, but --no-dry-run was not. Running in DRY-RUN mode.")
        print("To execute deletions, run: python3 scripts/branch_hygiene.py --delete --no-dry-run\n")

    print("Fetching latest remote branches...")
    run_cmd(["git", "fetch", "--prune"])

    branches = get_unmerged_branches()
    print(f"Found {len(branches)} unmerged branches. Analyzing...\n")

    active = []
    stale = []
    dependabot = []

    for b in branches:
        category, info = classify_branch(b)
        if category == "Active":
            active.append(info)
        elif category == "Stale":
            stale.append(info)
        elif category == "Dependabot":
            dependabot.append(info)

    print("=== ACTIVE/WORTH RETRIEVING BRANCHES ===")
    for a in active:
        print(f"Branch: {a['branch']}")
        print(f"  PR: {a['pr']}")
        print(f"  Age: {a['age_days']:.1f} days")
        print(f"  Has Diff: {a['has_diff']}")
        print("-" * 40)

    print("\n=== DEPENDABOT BRANCHES ===")
    for d in dependabot:
        print(f"Branch: {d['branch']} (Age: {d['age_days']:.1f} days)")

    print("\n=== STALE/GARBAGE BRANCHES ===")
    for s in stale:
        print(f"Branch: {s['branch']}")
        print(f"  PR: {s['pr']}")
        print(f"  Age: {s['age_days']:.1f} days")
        print(f"  Has Diff: {s['has_diff']}")
        print("-" * 40)

    print(f"\nSummary: {len(active)} active, {len(stale)} stale, {len(dependabot)} dependabot branches.")

    if args.delete:
        if is_dry_run:
            print("\n[Dry-run] Would delete the following stale branches:")
            for s in stale:
                print(f"  - {s['branch']}")
        else:
            print(f"\n[Execution] Starting deletion of {len(stale)} stale branches...")
            success_count = 0
            for s in stale:
                rem_ok = delete_remote_branch(s['branch'], dry_run=False)
                loc_ok = delete_local_branch(s['branch'], dry_run=False)
                if rem_ok and loc_ok:
                    success_count += 1
            print(f"\n[Execution] Successfully deleted {success_count}/{len(stale)} stale branches.")

if __name__ == "__main__":
    main()
