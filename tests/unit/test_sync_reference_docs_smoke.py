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
