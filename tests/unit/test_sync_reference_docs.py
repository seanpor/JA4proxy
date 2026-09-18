"""Unit tests for scripts/sync_reference_docs.py (Phase 815)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from scripts.sync_reference_docs import (
    BEGIN,
    END,
    Target,
    parse_first_party_images,
    parse_makefile,
    parse_scripts,
    render_images,
    render_scripts,
    render_targets,
    splice,
)

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "sync_reference_docs.py"


def test_script_exists_and_parses():
    assert SCRIPT.is_file(), "scripts/sync_reference_docs.py missing"
    ast.parse(SCRIPT.read_text(encoding="utf-8"))


def test_check_mode_in_sync_exits_zero():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=120,
    )
    assert result.returncode == 0, f"--check failed on clean repo:\n{result.stdout}\n{result.stderr}"
    assert "all reference documents are in sync" in result.stdout


def test_check_never_writes():
    before = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=REPO,
    ).stdout
    subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=120,
    )
    after = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=REPO,
    ).stdout
    assert before == after, f"--check modified the working tree:\n{after}"


def test_check_and_migrate_mutually_exclusive():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check", "--migrate"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=60,
    )
    assert result.returncode != 0
    assert "not allowed with" in (result.stdout + result.stderr)


def test_migrate_requires_explicit_confirmation():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--migrate"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=120,
    )
    assert "Nothing written" in result.stdout


def test_parse_makefile_fixtures():
    sample = """
# ── Build ─────────────────────────────────────────────────────────────
target-one: prereq1 ## Description for target one
\techo "1"

target-two: ## Description for target two
\techo "2"

# ── Undocumented ──────────────────────────────────────────────────────
target-bare:
\techo "bare"
"""
    targets = parse_makefile(sample)
    assert len(targets) == 3
    t1 = next(t for t in targets if t.name == "target-one")
    assert t1.description == "Description for target one"
    assert t1.section == "Build"
    assert t1.deps == "prereq1"

    t_bare = next(t for t in targets if t.name == "target-bare")
    assert t_bare.description == ""


def test_render_targets_separates_described_and_bare():
    targets = [
        Target(name="foo", description="Foo target", deps="", section="Section A"),
        Target(name="bar", description="", deps="", section="Section B"),
    ]
    rendered = render_targets(targets)
    assert "### Section A" in rendered
    assert "| `foo` | Foo target |" in rendered
    assert "### Undocumented" in rendered
    assert "| `bar` |" in rendered


def test_splice_preserves_surrounding_prose():
    doc = """# Header
Introductory prose here.

<!-- BEGIN GENERATED: test-key -->
Old table that will be replaced
<!-- END GENERATED: test-key -->

Concluding prose here.
"""
    new_table = "New generated table content"
    spliced = splice(doc, "test-key", new_table)
    expected = """# Header
Introductory prose here.

<!-- BEGIN GENERATED: test-key -->

New generated table content
<!-- END GENERATED: test-key -->

Concluding prose here.
"""
    assert spliced == expected


def test_splice_missing_markers_raises_exit():
    doc = "# Header without markers"
    try:
        splice(doc, "missing-key", "content")
    except SystemExit as exc:
        assert "missing markers for 'missing-key'" in str(exc)
    else:
        assert False, "splice should have raised SystemExit"


def test_parse_first_party_images_finds_production_images():
    images = parse_first_party_images()
    dockerfiles = {r[1] for r in images}
    assert "deploy/docker/Dockerfile.go-proxy" in dockerfiles
    assert "src/analytics/Dockerfile" in dockerfiles
    assert "deploy/docker/Dockerfile.management" in dockerfiles


def test_parse_scripts_finds_scripts():
    makefile_text = (REPO / "Makefile").read_text(encoding="utf-8")
    scripts = parse_scripts(makefile_text)
    script_names = {s[0] for s in scripts}
    assert "sync_reference_docs.py" in script_names
    assert "sync-roadmap.py" in script_names
