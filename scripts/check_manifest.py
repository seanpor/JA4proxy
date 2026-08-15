#!/usr/bin/env python3
"""
check_manifest.py — local consistency gate for the manifest-driven roadmap.

Two checks (both run; failures accumulate):

  1. SYNC   — TODO.md and PROJECT_STATUS.md match what sync-roadmap.py would
              generate from the current manifest.yaml.  Catches "manifest
              updated but sync script not re-run".

  2. CHANGELOG — Every phase marked COMPLETE in manifest.yaml has at least one
              mention in CHANGELOG.md, OR is in HISTORICAL_CHANGELOG_GAPS
              below.  Catches "phase shipped, log not written" for anything
              new, without pretending 202 old, undocumented phases don't
              exist.

  (Retired 2026-07-21, phase-800: a third TABLE check used to require every
  manifest phase to appear as a row in CLAUDE.md. CLAUDE.md's own "Phase
  Index" section has said since some earlier phase that the table "is no
  longer maintained here — single source of truth: docs/phases/manifest.yaml"
  — the check was enforcing an architecture the project had already replaced,
  and had drifted to 304 permanent failures nobody was fixing because there
  was nothing left to fix: the fix would have been re-introducing the exact
  hand-maintained table CLAUDE.md deliberately dropped. check_sync() above
  already validates the actual current substitute — TODO.md/PROJECT_STATUS.md
  generating cleanly from the manifest.)

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
# Phase 332: TODO.md and PROJECT_STATUS.md are no longer committed — they are
# regenerated build artifacts — so the sync check no longer reads them from disk.

# ── Historical CHANGELOG gap baseline ───────────────────────────────────────
#
# Snapshotted 2026-07-21 (phase-800): every phase ID below is COMPLETE in
# manifest.yaml with no CHANGELOG.md mention and no docs/fragments/ entry —
# confirmed by cross-referencing both, not just "grep found nothing". They
# predate the docs/fragments/ convention (introduced phase-322) and, in most
# cases, predate CHANGELOG discipline being enforced at all (phase 0 is in
# here). Backfilling 202 retroactive entries for already-shipped, in many
# cases since-superseded work would be either superficial or require
# archaeology nobody can responsibly do at scale — so this is an explicit,
# frozen baseline of accepted debt, not a silently-relaxed check.
#
# RULES:
#   - Never add a new ID to this set. A phase going COMPLETE today without a
#     CHANGELOG/fragment entry is a real process failure — fix it (write a
#     fragment), don't grandfather it in.
#   - Removing an ID (because someone backfilled its real history) is always
#     welcome.
HISTORICAL_CHANGELOG_GAPS = frozenset(
    {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
        "13", "14", "16", "17", "18", "19", "20", "21", "22", "23", "25",
        "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36",
        "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "51",
        "52", "53", "54", "56", "57", "58", "59", "61", "62", "63", "64",
        "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75",
        "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86",
        "86h", "86i", "87", "88", "88.1", "88.2", "88.3", "88.4", "88.5",
        "89", "90", "91", "92", "93", "93.1", "93.2", "93.3", "93.4",
        "93.5", "93.6", "93.7", "94", "100", "101", "102", "103", "104",
        "105", "106", "107", "108", "118", "119", "121", "122", "123",
        "124", "125", "126", "127", "129", "130", "131", "132", "133",
        "134", "135", "136", "137", "138", "139", "140", "141", "142",
        "143", "144", "145", "146", "147", "148", "149", "150", "151",
        "152", "153", "154", "155", "156", "157", "158", "161", "200",
        "202", "203", "204", "205", "206", "207", "208", "209", "210",
        "212", "213", "214", "215", "216", "217", "218", "219", "223",
        "244", "245.3", "245.5", "245.6", "245.7", "245.8", "245.9",
        "246.1", "246.2", "246.3", "246.4", "246.5", "247.1", "247.2",
        "247.3", "247.4", "247.5", "249.1", "249.2", "249.3", "249.4",
        "249.5", "249.6", "250.1", "250.2", "250.3", "250.4", "250.5",
        "250.6", "316", "335", "500", "501",
    }
)


# ── Check 1: sync ─────────────────────────────────────────────────────────────


def check_sync() -> list[str]:
    """Return a list of failure messages (empty = pass).

    Phase 332: docs/phases/TODO.md and docs/reference/PROJECT_STATUS.md are no longer
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

    # phase-820: also accept an unassembled docs/fragments/ entry.
    # CLAUDE.md forbids editing CHANGELOG.md directly — a phase writes a news
    # fragment, and `make changelog-assemble` folds it in *at release, not
    # per-phase* (Makefile:1517). Searching only CHANGELOG.md therefore made
    # this gate unsatisfiable for any phase closed between releases: the
    # failure message told you to write a fragment, then failed anyway when
    # you did. Concatenating the fragments makes the check match both its own
    # message and the documented process.
    fragments_dir = MANIFEST_PATH.parents[1] / "fragments"
    fragments = "\n".join(
        p.read_text().lower() for p in sorted(fragments_dir.glob("*.md"))
    )
    # Fragment filenames encode the phase (docs/fragments/README.md), so match
    # the names too — a fragment whose body says only "this phase" still counts.
    fragment_names = "\n".join(p.name.lower() for p in sorted(fragments_dir.glob("*.md")))
    searchable = "\n".join((changelog, fragments, fragment_names))

    failures = []

    for phase_id, data in manifest["phases"].items():
        if data["status"] != "COMPLETE":
            continue
        phase_id_str = str(phase_id)
        if phase_id_str in HISTORICAL_CHANGELOG_GAPS:
            continue
        # Accept "phase 12", "phase-12", "phase_12", "phase12", "phase 17b" etc.
        # Use negative lookahead (?![0-9]) instead of \b so "phase 17b" matches
        # a search for phase 17, while "phase 170" does not.
        pattern = re.compile(
            rf"\bphase[-_ ]?{re.escape(phase_id_str)}(?![0-9])", re.IGNORECASE
        )
        if not pattern.search(searchable):
            failures.append(
                f"Phase {phase_id} ({data['name']}) is COMPLETE in manifest.yaml "
                f"but has no matching entry in CHANGELOG.md or docs/fragments/ "
                f"(and is not in HISTORICAL_CHANGELOG_GAPS) — write a "
                f"docs/fragments/phase-{phase_id}-*.md entry"
            )

    return failures


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    checks = [
        ("SYNC     ", check_sync),
        ("CHANGELOG", check_changelog),
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
