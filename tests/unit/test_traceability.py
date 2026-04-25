"""Unit tests for ``scripts/traceability.py``.

All tests use ``tmp_path`` fixtures so they never read or write the real
``docs/`` tree. The fixtures under ``tests/fixtures/traceability/`` are
copied into ``tmp_path`` and tweaked per scenario as needed.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "traceability.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "traceability"


def _load_script():
    """Import scripts/traceability.py as a module without running ``main``."""
    spec = importlib.util.spec_from_file_location("traceability_mod", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def trace_mod():
    return _load_script()


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    """Copy the on-disk fixture tree into ``tmp_path/phases``."""
    dest = tmp_path / "phases"
    dest.mkdir()
    for f in FIXTURE_DIR.iterdir():
        if f.is_file():
            shutil.copy2(f, dest / f.name)
    return dest


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_extracts_req_ids_from_tagged_phase(trace_mod, fixture_dir: Path) -> None:
    manifest = trace_mod.load_manifest(fixture_dir / "manifest.yaml")
    reqs = trace_mod.collect_requirements(fixture_dir, manifest)
    ids = {r.req_id for r in reqs}
    assert "REQ-999-01" in ids
    assert "REQ-999-02" in ids
    # All extracted reqs must come from the tagged phase
    assert all(r.phase == "999" for r in reqs)


def test_skips_phases_without_req_tagged_in_manifest(
    trace_mod, fixture_dir: Path
) -> None:
    manifest = trace_mod.load_manifest(fixture_dir / "manifest.yaml")
    reqs = trace_mod.collect_requirements(fixture_dir, manifest)
    ids = {r.req_id for r in reqs}
    assert "REQ-998-01" not in ids
    assert all(r.phase != "998" for r in reqs)


def test_exits_nonzero_on_missing_verified_by(
    trace_mod, fixture_dir: Path, tmp_path: Path, capsys
) -> None:
    # Replace PHASE_999 with one that has a REQ line lacking Verified by:
    bad = fixture_dir / "PHASE_999.md"
    bad.write_text(
        "# Phase 999 — Bad\n\n"
        "## Acceptance Criteria\n\n"
        "- [ ] REQ-999-99: This requirement has no Verified by clause.\n",
        encoding="utf-8",
    )
    out = tmp_path / "out" / "TRACEABILITY.md"
    rc = trace_mod.main(
        [
            "--phases-dir",
            str(fixture_dir),
            "--manifest",
            str(fixture_dir / "manifest.yaml"),
            "--output",
            str(out),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    # Stderr should mention the offending file
    assert "PHASE_999.md" in captured.err
    assert "REQ-999-99" in captured.err


def test_handles_manual_review_marker(trace_mod, fixture_dir: Path) -> None:
    manifest = trace_mod.load_manifest(fixture_dir / "manifest.yaml")
    reqs = trace_mod.collect_requirements(fixture_dir, manifest)
    manual = [r for r in reqs if r.req_id == "REQ-999-02"]
    assert len(manual) == 1
    assert manual[0].status == "MANUAL-REVIEW"
    assert manual[0].verified_by == "[MANUAL-REVIEW]"


def test_generates_table_with_correct_header(
    trace_mod, fixture_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "TRACEABILITY.md"
    rc = trace_mod.main(
        [
            "--phases-dir",
            str(fixture_dir),
            "--manifest",
            str(fixture_dir / "manifest.yaml"),
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "| REQ-ID | Phase | Description | Verified by | Status |" in text
    # Separator row must follow the header.
    assert "|--------|-------|-------------|-------------|--------|" in text


def test_check_mode_does_not_write_file(
    trace_mod, fixture_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "should_not_exist.md"
    assert not out.exists()
    rc = trace_mod.main(
        [
            "--check",
            "--phases-dir",
            str(fixture_dir),
            "--manifest",
            str(fixture_dir / "manifest.yaml"),
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    assert not out.exists()


def test_handles_multiline_verified_by(trace_mod, fixture_dir: Path) -> None:
    manifest = trace_mod.load_manifest(fixture_dir / "manifest.yaml")
    reqs = trace_mod.collect_requirements(fixture_dir, manifest)
    multiline = [r for r in reqs if r.req_id == "REQ-999-03"]
    assert len(multiline) == 1
    assert multiline[0].status == "AUTOMATED"
    assert "test_handles_multiline_verified_by" in multiline[0].verified_by
