#!/usr/bin/env python3
"""Verify and append new GitHub Actions SHA pins (Phase 812, 812-C).

Scoped to Dependabot Actions-group PRs, invoked by
.github/workflows/pin-table-autofix.yml via `pull_request_target` (so it
runs with the base repo's permissions, not the PR's -- Dependabot-triggered
`pull_request` workflows get a read-only GITHUB_TOKEN by default and could
never push a fixup commit).

Scans a workflow directory (the PR branch's copy, read as plain data -- this
script itself always runs from the trusted base-ref checkout, never
something read from the PR) for every `uses: owner/repo@SHA  # vTAG` triple,
using the exact same regex as tests/test_workflow_pinning.py. For each triple
not already in KNOWN_ACTION_SHAS (or already there but with an unexpected
SHA), verifies the SHA against `git ls-remote` -- a live network call, not a
guess -- before ever writing anything.

If every new/changed triple verifies: appends a line to the matching
action's block in tests/test_workflow_pinning.py and exits 0. If the action
has no existing block at all (a genuinely new action never seen before,
not just a new version of one already tracked), this script does NOT create
one -- that's a bigger, less mechanical edit better done by a human once,
after which every future version bump for that action IS the fast path this
script handles. If ANY triple fails to verify: makes NO changes to the file
at all (all-or-nothing) and exits 1 with the mismatch details -- this is the
actual supply-chain-hole case the table exists to catch, and must never be
silently patched over or partially applied.

Uses subprocess with argument lists (never shell=True), so there is no
shell-injection risk from a maliciously-named action/tag even before
validation -- the ACTION_NAME_RE/TAG_RE checks below exist to reject
obviously-wrong input early with a clear error, not as the sole injection
defense.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SHA_AND_TAG_RE = re.compile(
    r"uses:\s*([^/\s]+/[^@\s]+)@([a-f0-9]{40})\s*#\s*(v[0-9A-Za-z.\-_]+)"
)
ACTION_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_RE = re.compile(r"^v?[0-9]+(\.[0-9]+){0,3}(-[A-Za-z0-9.]+)?$")


def extract_triples(workflow_dir: Path) -> set[tuple[str, str, str]]:
    triples: set[tuple[str, str, str]] = set()
    for path in sorted(workflow_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for m in SHA_AND_TAG_RE.finditer(text):
            triples.add((m.group(1), m.group(2), m.group(3)))
    return triples


def load_known_shas(test_file: Path) -> dict[str, dict[str, str]]:
    """Parse KNOWN_ACTION_SHAS without executing the file (ast.literal_eval
    on just the dict literal's source span, not exec() on the whole module --
    this file is read from the PR branch, so never execute it as code).
    """
    import ast

    tree = ast.parse(test_file.read_text(encoding="utf-8"), filename=str(test_file))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "KNOWN_ACTION_SHAS" for t in node.targets
        ):
            return ast.literal_eval(node.value)
        # The real file declares this as `KNOWN_ACTION_SHAS: dict[...] = {...}`
        # (an annotated assignment, ast.AnnAssign) -- singular `.target`, not
        # a `.targets` list like plain ast.Assign.
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "KNOWN_ACTION_SHAS"
            and node.value is not None
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"KNOWN_ACTION_SHAS assignment not found in {test_file}")


def verify_sha(action: str, tag: str, expected_sha: str) -> tuple[bool, str]:
    """Returns (matches, detail). Tries the plain tag ref first, then the
    dereferenced (^{}) form for annotated tags -- the exact gotcha hit
    verifying ossf/scorecard-action's v2.4.4 in PR #379: `git ls-remote`
    without ^{} returns the annotated TAG OBJECT's sha, not the commit it
    points at.
    """
    if not ACTION_NAME_RE.match(action):
        return False, f"action name fails strict validation: {action!r}"
    if not TAG_RE.match(tag):
        return False, f"tag fails strict validation: {tag!r}"
    url = f"https://github.com/{action}"
    for ref_suffix in ("", "^{}"):
        try:
            out = subprocess.run(
                ["git", "ls-remote", url, f"refs/tags/{tag}{ref_suffix}"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as e:
            return False, f"git ls-remote failed for {action}@{tag}{ref_suffix}: {e.stderr}"
        if not out:
            continue
        remote_sha = out.split()[0]
        if remote_sha == expected_sha:
            return True, f"verified via refs/tags/{tag}{ref_suffix}"
    return False, f"no matching ref for {action}@{tag} resolves to {expected_sha}"


def apply_fix(test_file: Path, action: str, tag: str, sha: str, note: str) -> bool:
    """Insert a new line into the action's existing block. Returns False
    (no-op, caller must handle) if the action has no block at all yet.
    """
    text = test_file.read_text(encoding="utf-8")
    block_re = re.compile(rf'("{re.escape(action)}":\s*\{{\n)')
    m = block_re.search(text)
    if not m:
        return False
    insertion = f'        "{tag}": "{sha}",  # {note}\n'
    new_text = text[: m.end()] + insertion + text[m.end() :]
    test_file.write_text(new_text, encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflow-dir", required=True, type=Path)
    ap.add_argument("--test-file", required=True, type=Path)
    ap.add_argument("--note", default="phase-812-autofix")
    args = ap.parse_args(argv)

    known = load_known_shas(args.test_file)
    triples = extract_triples(args.workflow_dir)

    to_add: list[tuple[str, str, str]] = []
    for action, sha, tag in sorted(triples):
        if known.get(action, {}).get(tag) == sha:
            continue  # already known and matches -- idempotent no-op
        to_add.append((action, sha, tag))

    if not to_add:
        print("No new or changed (action, tag, sha) triples found. Nothing to do.")
        return 0

    print(f"Found {len(to_add)} new/changed triple(s) to verify:")
    verified: list[tuple[str, str, str]] = []
    failed: list[tuple[str, str, str, str]] = []
    for action, sha, tag in to_add:
        ok, detail = verify_sha(action, tag, sha)
        print(f"  {action}@{tag} -> {sha}: {'OK' if ok else 'MISMATCH'} ({detail})")
        if ok:
            verified.append((action, sha, tag))
        else:
            failed.append((action, sha, tag, detail))

    if failed:
        print(
            "\n✗ One or more triples failed verification -- making NO changes "
            "(all-or-nothing). This may be a real supply-chain issue, not a "
            "tooling bug:"
        )
        for action, sha, tag, detail in failed:
            print(f"  {action}@{tag} -> {sha}: {detail}")
        return 1

    unresolved: list[tuple[str, str, str]] = []
    for action, sha, tag in verified:
        if action not in known:
            unresolved.append((action, sha, tag))
            continue
        if not apply_fix(args.test_file, action, tag, sha, args.note):
            unresolved.append((action, sha, tag))

    if unresolved:
        print(
            "\n✗ Verified but could not auto-patch (no existing block for this "
            "action -- a brand-new action needs a one-time manual entry, "
            "after which future bumps take the fast path):"
        )
        for action, sha, tag in unresolved:
            print(f"  {action}@{tag} -> {sha}")
        return 1

    print(f"\n✓ Patched {len(verified)} verified entr{'y' if len(verified) == 1 else 'ies'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
