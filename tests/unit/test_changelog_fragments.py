"""Guard rails for the CHANGELOG news-fragment workflow (scripts/assemble-changelog.py).

Runs in the `make test` gate, so it both unit-tests the assembler's pure logic
and validates that any real fragments under docs/fragments/ stay well-formed.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "assemble-changelog.py"
_FRAGMENTS_DIR = _REPO_ROOT / "docs" / "fragments"


def _load_module():
    # The script name has a hyphen, so load it by path rather than import.
    spec = importlib.util.spec_from_file_location("assemble_changelog", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


asm = _load_module()

_BASE = """# Changelog

## [Unreleased]

### Added
- existing entry

## [1.0.0] - 2026-01-01
- shipped
"""


def test_no_fragments_is_noop() -> None:
    """Empty fragment list returns the changelog unchanged (idempotent)."""
    assert asm.assemble_changelog(_BASE, []) == _BASE


def test_inserts_under_added() -> None:
    """Fragment bullets land under the existing '### Added' heading."""
    out = asm.assemble_changelog(_BASE, [("phase-99.md", "- new thing (Phase 99)")])
    added = out.index("### Added")
    assert "- new thing (Phase 99)" in out
    # inserted above the pre-existing entry, below the heading
    assert out.index("- new thing (Phase 99)") > added
    assert out.index("- new thing (Phase 99)") < out.index("- existing entry")
    # the released section is untouched
    assert "## [1.0.0] - 2026-01-01" in out


def test_creates_added_when_missing() -> None:
    """If Unreleased has no '### Added', the assembler creates one."""
    changelog = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0]\n- shipped\n"
    out = asm.assemble_changelog(changelog, [("p.md", "- x")])
    assert "### Added" in out
    assert out.index("### Added") < out.index("## [1.0.0]")
    assert "- x" in out


def test_ordered_by_caller() -> None:
    """Fragments are emitted in the order given (caller sorts by filename)."""
    out = asm.assemble_changelog(_BASE, [("a.md", "- aaa"), ("b.md", "- bbb")])
    assert out.index("- aaa") < out.index("- bbb")


def test_missing_unreleased_raises() -> None:
    with pytest.raises(ValueError):
        asm.assemble_changelog("# Changelog\n\n## [1.0.0]\n- shipped\n", [("p.md", "- x")])


def test_collect_skips_readme(tmp_path: pathlib.Path) -> None:
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")
    (tmp_path / "phase-1.md").write_text("- a", encoding="utf-8")
    (tmp_path / "empty.md").write_text("\n  \n", encoding="utf-8")
    names = [n for n, _ in asm.collect_fragments(tmp_path)]
    assert names == ["phase-1.md"]  # README and empty fragment excluded


def test_real_fragments_are_well_formed() -> None:
    """Any committed fragment must be a non-empty .md with at least one bullet."""
    if not _FRAGMENTS_DIR.is_dir():
        pytest.skip("no fragments directory")
    for path in _FRAGMENTS_DIR.glob("*.md"):
        if path.name == "README.md":
            continue
        body = path.read_text(encoding="utf-8")
        assert body.strip(), f"{path.name} is empty"
        assert any(
            ln.lstrip().startswith("- ") for ln in body.splitlines()
        ), f"{path.name} has no Markdown bullet (- ...)"
