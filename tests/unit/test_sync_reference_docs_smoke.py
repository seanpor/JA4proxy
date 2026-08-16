"""
Bit-rot guard for the rescued Phase 815 generator.

`scripts/sync_reference_docs.py` was written 2026-08-06 and survived only on the
`handoff-to-deepseek` branch. It is **unwired WIP** — no Makefile target or
workflow invokes it — so nothing else in the suite would notice if it stopped
importing after, say, a Python version bump.

These tests deliberately do NOT validate its output. That belongs to Phase 815
when the generator is actually wired in. They assert only that the file still
parses, imports, exposes its documented interface, and stays unwired until that
phase approves it.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "sync_reference_docs.py"


def test_script_exists():
    assert SCRIPT.is_file(), "the rescued Phase 815 generator has gone missing"


def test_script_parses():
    """Catches syntax rot from a Python upgrade."""
    ast.parse(SCRIPT.read_text(encoding="utf-8"))


def test_script_runs_and_reports_rather_than_crashing():
    """`--check` must exit cleanly-ish, not traceback.

    The docs it targets have no BEGIN/END GENERATED markers yet, so it is
    expected to report that. What matters is that it reports rather than
    raising.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True, text=True, cwd=REPO, timeout=120,
    )
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, (
        f"generator crashed instead of reporting:\n{combined[-1500:]}"
    )
    # "no traceback" alone is nearly unfalsifiable — SystemExit, argparse errors
    # and a bare sys.exit(3) all satisfy it, so a script gutted to
    # `import sys; sys.exit(3)` would pass. Pin the actual contract.
    assert result.returncode in (0, 1), (
        f"unexpected exit {result.returncode} from --check:\n{combined[-1500:]}"
    )
    assert "missing markers" in combined or "drift" in combined.lower(), (
        "--check produced neither a marker complaint nor a drift report — it is "
        f"not doing its job:\n{combined[-1500:]}"
    )


def test_check_never_writes():
    """--check is a CI gate; it must not mutate the repo.

    --migrate rewrites the Makefile in place, so an ordering slip between the
    two modes would let a read-only check edit the build's front door. Verified
    by running --check and diffing the working tree.
    """
    before = subprocess.run(["git", "status", "--porcelain"],
                            capture_output=True, text=True, cwd=REPO).stdout
    subprocess.run([sys.executable, str(SCRIPT), "--check"],
                   capture_output=True, text=True, cwd=REPO, timeout=120)
    after = subprocess.run(["git", "status", "--porcelain"],
                           capture_output=True, text=True, cwd=REPO).stdout
    assert before == after, f"--check modified the working tree:\n{after}"


def test_check_and_migrate_are_mutually_exclusive():
    """`--check --migrate` used to silently mutate the Makefile."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check", "--migrate"],
        capture_output=True, text=True, cwd=REPO, timeout=60,
    )
    assert result.returncode != 0, "--check --migrate must be rejected"
    assert "not allowed with" in (result.stdout + result.stderr)


def test_migrate_requires_explicit_confirmation():
    """--migrate without --yes must print a diff and write nothing."""
    before = subprocess.run(["git", "status", "--porcelain"],
                            capture_output=True, text=True, cwd=REPO).stdout
    result = subprocess.run([sys.executable, str(SCRIPT), "--migrate"],
                            capture_output=True, text=True, cwd=REPO, timeout=120)
    after = subprocess.run(["git", "status", "--porcelain"],
                           capture_output=True, text=True, cwd=REPO).stdout
    assert before == after, f"--migrate wrote without --yes:\n{after}"
    assert "Nothing written" in result.stdout


def test_documented_modes_still_exist():
    """HANDOFF-2026-08-06.md promises --check and --migrate."""
    src = SCRIPT.read_text(encoding="utf-8")
    for flag in ("--check", "--migrate"):
        assert flag in src, f"{flag} mode has disappeared from the generator"


def test_generator_is_still_unwired():
    """It must not be wired into the build before Phase 815 is approved.

    Wiring an untested generator into `make lint` or CI would gate the build on
    output nobody has validated. When Phase 815 lands, this test should be
    replaced by real coverage — not deleted quietly.
    """
    hits = []
    for path in [REPO / "Makefile", *(REPO / ".github" / "workflows").glob("*.yml")]:
        if path.is_file() and "sync_reference_docs" in path.read_text(encoding="utf-8"):
            hits.append(path.name)
    assert not hits, (
        f"sync_reference_docs.py is referenced by {hits}, but it is unwired WIP "
        "with no output validation. Land Phase 815 first."
    )
