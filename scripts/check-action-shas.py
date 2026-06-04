#!/usr/bin/env python3
"""Verify SHA-pinned GitHub Actions use commit SHAs, not annotated tag SHAs.

Scorecard-action's built-in verification rejects annotated tag SHAs
("imposter commit"). This script catches that before push.

Usage:
    python3 scripts/check-action-shas.py
    python3 scripts/check-action-shas.py --fix   # replace tag SHAs with commit SHAs

Exit code: 0 if all SHAs are commits, 1 otherwise.
"""

import argparse
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
import json

WORKFLOW_DIR = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows")

SHA_PATTERN = re.compile(
    r"^\s+-\s+uses:\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([0-9a-f]{40})(?:\s+#\s+(.+))?$",
    re.MULTILINE,
)


def get_commit_for_tag(repo: str, sha: str) -> str | None:
    """Given a SHA from a `uses:` line, check if it's an annotated tag.

    GitHub API: GET /repos/{repo}/git/tags/{sha}
    - If 200 and type == "tag": it's annotated; response has object.sha = real commit.
    - If 404: it's a commit/lightweight tag (the SHA is the commit itself).
    """
    url = f"https://api.github.com/repos/{repo}/git/tags/{sha}"
    req = urllib.request.Request(url)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        req.add_header("Authorization", f"token {token}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("object", {}).get("type") == "commit":
                return data["object"]["sha"]
            return None  # unexpected
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # commit or lightweight tag
        if e.code == 403:
            print(f"  [!] Rate limited — try setting GITHUB_TOKEN or GH_TOKEN", file=sys.stderr)
            return None
        raise
    except urllib.error.URLError:
        return None  # offline — can't verify, skip


def find_all_uses(filepath: str) -> list[tuple[str, str, str, int]]:
    """Return list of (repo, sha, tag_comment, line_number)."""
    results = []
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            m = SHA_PATTERN.match(line)
            if m:
                results.append((m.group(1), m.group(2), m.group(3) or "", i))
    return results


def main():
    parser = argparse.ArgumentParser(description="Verify SHA-pinned Actions use commit SHAs")
    parser.add_argument("--fix", action="store_true", help="Replace annotated tag SHAs with commit SHAs (in-place edit)")
    args = parser.parse_args()

    workflow_dir = os.path.abspath(WORKFLOW_DIR)
    if not os.path.isdir(workflow_dir):
        print(f"Workflow directory not found: {workflow_dir}", file=sys.stderr)
        sys.exit(1)

    errors = 0
    fixes = 0

    for fname in sorted(os.listdir(workflow_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        fpath = os.path.join(workflow_dir, fname)
        uses = find_all_uses(fpath)
        if not uses:
            continue

        for repo, sha, tag_comment, lineno in uses:
            commit_sha = get_commit_for_tag(repo, sha)
            if commit_sha and commit_sha != sha:
                print(
                    f"  ✗  {fname}:{lineno}  {repo}@{sha[:12]}...  "
                    f"annotated tag → commit is {commit_sha[:12]}..."
                )
                errors += 1

                if args.fix:
                    with open(fpath) as f:
                        content = f.read()
                    old = f"{repo}@{sha}"
                    new = f"{repo}@{commit_sha}"
                    if old in content:
                        content = content.replace(old, new)
                        with open(fpath, "w") as f:
                            f.write(content)
                        print(f"     → fixed to {commit_sha[:12]}...")
                        fixes += 1

    if errors == 0:
        print("✓ All SHA-pinned actions use commit SHAs")
        return 0
    else:
        print(f"\n{errors} annotated tag SHA(s) found. {'All fixed.' if fixes else 'Run with --fix to auto-replace.'}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
