#!/usr/bin/env python3
"""
check_manifest.py — local consistency gate for the manifest-driven roadmap.

Three checks (all run; failures accumulate):

  1. SYNC   — TODO.md and PROJECT_STATUS.md match what sync-roadmap.py would
              generate from the current manifest.yaml.  Catches "manifest
              updated but sync script not re-run".

  2. CHANGELOG — Every phase marked COMPLETE in manifest.yaml has at least one
              mention in CHANGELOG.md.  Catches "phase shipped, log not written".

  3. TABLE  — Every phase in manifest.yaml appears in CLAUDE.md's phase index
              table.  Catches "new phase added but CLAUDE.md not updated".

Exit 0 = all checks pass.
Exit 1 = one or more checks failed (details printed to stdout).

Run via:  make check-manifest
          python3 scripts/check_manifest.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MANIFEST_PATH = ROOT / "docs/phases/manifest.yaml"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
CLAUDE_PATH = ROOT / "CLAUDE.md"
# Phase 332: TODO.md and PROJECT_STATUS.md are no longer committed — they are
# regenerated build artifacts — so the sync check no longer reads them from disk.


# ── Check 1: sync ─────────────────────────────────────────────────────────────


def check_sync() -> list[str]:
    """Return a list of failure messages (empty = pass).

    Phase 332: docs/phases/TODO.md and docs/PROJECT_STATUS.md are no longer
    committed — they are build artifacts regenerated from manifest.yaml by
    ``make sync`` (and published by CI). There is therefore nothing to diff and
    no "you forgot to regenerate" failure mode left. What still matters is that
    the generator *runs cleanly* against the current manifest — a malformed
    manifest or an epic referencing an undefined id must fail loudly here rather
    than at render time. So we regenerate both documents and surface any error.
    """
    # Import generation functions from sync-roadmap without executing __main__.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "sync_roadmap", ROOT / "scripts/sync-roadmap.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    failures = []
    try:
        manifest = mod.load_manifest()
        mod.generate_todo(manifest)
        mod.generate_status(manifest)
    except Exception as exc:  # noqa: BLE001 — surface any generation failure
        failures.append(
            f"manifest.yaml does not generate cleanly ({type(exc).__name__}: "
            f"{exc}) — fix manifest.yaml, then run: make sync"
        )

    return failures


# ── Check 2: changelog ────────────────────────────────────────────────────────


def check_changelog() -> list[str]:
    """Return a list of failure messages (empty = pass)."""
    import yaml

    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    changelog = CHANGELOG_PATH.read_text().lower()
    failures = []

    for phase_id, data in manifest["phases"].items():
        if data["status"] != "COMPLETE":
            continue
        # Accept "phase 12", "phase-12", "phase_12", "phase12", "phase 17b" etc.
        # Use negative lookahead (?![0-9]) instead of \b so "phase 17b" matches
        # a search for phase 17, while "phase 170" does not.
        pattern = re.compile(rf"\bphase[-_ ]?{phase_id}(?![0-9])", re.IGNORECASE)
        if not pattern.search(changelog):
            failures.append(
                f"Phase {phase_id} ({data['name']}) is COMPLETE in manifest.yaml "
                f"but has no matching entry in CHANGELOG.md"
            )

    return failures


# ── Check 3: CLAUDE.md phase table ───────────────────────────────────────────


def check_claude_table() -> list[str]:
    """Return a list of failure messages (empty = pass)."""
    import yaml

    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    claude = CLAUDE_PATH.read_text()
    failures = []

    for phase_id in manifest["phases"]:
        # Table rows look like: "| 16 | Extended fingerprinting | ..."
        if not re.search(rf"^\| {phase_id} \|", claude, re.MULTILINE):
            failures.append(
                f"Phase {phase_id} ({manifest['phases'][phase_id]['name']}) "
                f"is in manifest.yaml but missing from CLAUDE.md phase table"
            )

    return failures


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    checks = [
        ("SYNC     ", check_sync),
        ("CHANGELOG", check_changelog),
        ("TABLE    ", check_claude_table),
    ]

    all_failures: list[str] = []
    for label, fn in checks:
        failures = fn()
        status = (
            "✓ PASS"
            if not failures
            else f"✗ FAIL ({len(failures)} issue{'s' if len(failures) != 1 else ''})"
        )
        print(f"  {label}  {status}")
        all_failures.extend(failures)

    if all_failures:
        print()
        for msg in all_failures:
            print(f"  → {msg}")
        print()
        print("Fix the issues above, then re-run:  make check-manifest")
        return 1

    print()
    print("  All checks passed.")
    return 0


if __name__ == "__main__":
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Manifest consistency check")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    sys.exit(main())
