"""Phase 107h.2 — Evidence-path existence check.

Conformance mapping documents (``CRA_CONFORMANCE.md``, ``SSDF_MAPPING.md``)
cite repository paths as evidence that a control is implemented. If a cited
path is renamed or deleted, the mapping rots silently and a future audit
will discover stale evidence.

This test extracts every relative repo path appearing in the evidence
columns of those documents and asserts each one resolves to an existing
file or directory.

Phase 107 review:
- A-3 (LOW, Architecture): ATT&CK + control mappings reference signal modules
  by file path; if those modules move/rename, the mapping rots silently.
- S-2 (HIGH, Security): linked-to-but-non-existent evidence is an overclaim
  by another name — a doc says "implemented, see X" when X does not exist.

The Phase 107h.2 sub-task adds this test as the regression guard. It is
intentionally permissive about WHERE in the doc the path appears (anywhere
in the file body), because the mapping table format may evolve.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Documents whose linked evidence paths must exist on disk.
EVIDENCE_DOCS: list[Path] = [
    REPO_ROOT / "docs" / "compliance" / "CRA_CONFORMANCE.md",
    REPO_ROOT / "docs" / "compliance" / "SSDF_MAPPING.md",
]

#: Repo-rooted directories that count as "evidence path roots" — we only
#: validate paths that look like they point inside the codebase. External
#: links (https://, mailto:) and bare technique IDs are ignored.
EVIDENCE_ROOTS = (
    ".github",
    "cmd",
    "config",
    "deploy",
    "docs",
    "internal",
    "scripts",
    "src",
    "tests",
)

#: Match a relative repo path that starts with one of EVIDENCE_ROOTS, has
#: at least one path component after the root, and uses only file-name-safe
#: characters. Examples that match:
#:   docs/security/threat-model.md
#:   .github/workflows/go-proxy-image.yml
#:   src/security/manager.py
#:   tests/unit/test_foo.py
#: Examples that do NOT match (intentionally):
#:   /etc/passwd                   (absolute)
#:   docs/                         (no path-after-root)
#:   docs/foo bar.md               (space)
#:   https://docs.example.com      (URL)
_root_alt = "|".join(re.escape(r) for r in EVIDENCE_ROOTS)
EVIDENCE_PATH_PATTERN = re.compile(
    rf"(?<![\w/.-])(?P<path>(?:{_root_alt})/[\w./-]+\.[\w]+)(?![\w/.-])"
)

#: Lines that begin with `<!--` are TODO scaffolding markers, not evidence
#: claims. Skip them — they document what WILL be added, not what IS linked.
TODO_LINE = re.compile(r"<!--\s*TODO")


def _extract_evidence_paths(doc_path: Path) -> set[Path]:
    """Extract every plausible repo-relative path mentioned in the doc."""
    if not doc_path.exists():
        return set()
    text = doc_path.read_text(encoding="utf-8")
    paths: set[Path] = set()
    for line in text.splitlines():
        if TODO_LINE.search(line):
            continue
        for match in EVIDENCE_PATH_PATTERN.finditer(line):
            paths.add(REPO_ROOT / match.group("path"))
    return paths


@pytest.mark.parametrize(
    "doc_path",
    EVIDENCE_DOCS,
    ids=[str(p.relative_to(REPO_ROOT)) for p in EVIDENCE_DOCS],
)
def test_evidence_paths_exist(doc_path: Path) -> None:
    """Every repo-relative path cited in a conformance doc must exist on disk.

    Phase 107 review A-3 (Architecture, LOW) regression guard: catches
    signal-module renames or workflow renames that would silently rot the
    mapping.

    During scaffolding (Phase 107a/b/c.1/d/e/f/g.1), the docs contain only
    TODO markers and have no evidence paths to check; the test passes
    trivially. Once 107a.2-.5 / 107b.2-.3 land, every cited path must exist.
    """
    if not doc_path.exists():
        pytest.skip(f"{doc_path.relative_to(REPO_ROOT)} does not exist yet")

    paths = _extract_evidence_paths(doc_path)
    missing = sorted(p for p in paths if not p.exists())
    if missing:
        msg_lines = [
            f"Evidence paths cited in {doc_path.relative_to(REPO_ROOT)} do not exist:",
            "",
        ]
        for p in missing:
            msg_lines.append(f"  - {p.relative_to(REPO_ROOT)}")
        msg_lines += [
            "",
            "If a file was renamed, update the mapping doc with the new path.",
            "If a file was deleted, remove the row or replace with a real evidence link.",
        ]
        pytest.fail("\n".join(msg_lines))


def test_evidence_path_pattern_extracts_real_paths() -> None:
    """The extraction regex must catch realistic evidence-link formats."""
    sample = """
    | ER1 | Security by default | See `docs/security/threat-model.md` and config/proxy.yml | none | N/A |
    | ER7 | Logging | Per `docs/OBSERVABILITY_STANDARDS.md` | none | N/A |
    | PW.7 | SAST | Job `.github/workflows/ci.yml` Semgrep step | none | N/A |
    """
    matches = {m.group("path") for m in EVIDENCE_PATH_PATTERN.finditer(sample)}
    assert "docs/security/threat-model.md" in matches
    assert "config/proxy.yml" in matches
    assert "docs/OBSERVABILITY_STANDARDS.md" in matches
    assert ".github/workflows/ci.yml" in matches


def test_evidence_path_pattern_ignores_urls_and_absolute_paths() -> None:
    """The extraction regex must NOT match URLs or absolute paths."""
    sample = """
    See https://docs.example.com/foo.md or /etc/passwd or
    https://github.com/seanpor/JA4proxy/blob/main/docs/X.md
    """
    matches = {m.group("path") for m in EVIDENCE_PATH_PATTERN.finditer(sample)}
    assert matches == set(), f"Should not match URL/absolute paths, got: {matches}"


def test_todo_lines_are_skipped() -> None:
    """TODO scaffolding lines must not be parsed as evidence claims."""
    assert TODO_LINE.search("<!-- TODO 107a.2 — fill ER1-ER4 rows -->")
    assert TODO_LINE.search("    <!--   TODO 107b.3 -->")
    # Real evidence rows must NOT match the TODO pattern
    assert not TODO_LINE.search("| ER1 | ... | docs/security/threat-model.md | ... |")
