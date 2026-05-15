"""Phase 107h.1 — Overclaim-language CI gate.

Self-assessed conformance documents must not claim "certified" or
"compliant" — those words imply an accredited body has audited the
project, which is not the case for any standard JA4proxy maps against.

The phase 107 review (S-2 finding, HIGH severity) flags this as the
single highest-severity risk in the whole regulatory-conformance phase.
This test enforces it as a regression guard: any future doc PR that
introduces the words "certified" or "compliant" anywhere under
``docs/compliance/`` or in ``docs/security/CVD_POLICY.md`` fails CI.

If a future certification is obtained (e.g. ISO 27001 by an accredited
body), the relevant file path may be added to ``ALLOWLIST`` below with
a code comment explaining who certified what and when.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Files where "certified" / "compliant" is currently allowed. Empty by
#: design — JA4proxy has no third-party certifications today. To add an
#: entry, document who certified what (accredited body, scope, date) in
#: a code comment immediately above the path.
ALLOWLIST: set[Path] = set()

#: Words that signal an audited / certified claim. Word-boundary regex
#: catches "certified", "compliant" but not "certification", "compliance"
#: (those are descriptive nouns; the verbs/adjectives are the overclaim).
OVERCLAIM_PATTERN = re.compile(r"\b(certified|compliant)\b", re.IGNORECASE)

#: Paths to scan for overclaim language.
SCAN_TARGETS: list[Path] = [
    REPO_ROOT / "docs" / "compliance",
    REPO_ROOT / "docs" / "security" / "CVD_POLICY.md",
]


def _iter_markdown_files(target: Path) -> list[Path]:
    """Yield every ``.md`` file under ``target`` (or just ``target`` if it is one)."""
    if target.is_file():
        return [target] if target.suffix == ".md" else []
    if not target.exists():
        return []
    return sorted(target.rglob("*.md"))


def _scan_file_for_overclaims(path: Path) -> list[tuple[int, str]]:
    """Return list of (line_number, line_text) tuples where overclaim language appears."""
    findings: list[tuple[int, str]] = []
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if OVERCLAIM_PATTERN.search(line):
            findings.append((lineno, line.strip()))
    return findings


@pytest.mark.parametrize(
    "scan_target",
    SCAN_TARGETS,
    ids=[str(p.relative_to(REPO_ROOT)) for p in SCAN_TARGETS],
)
def test_no_overclaim_language(scan_target: Path) -> None:
    """No ``certified`` / ``compliant`` claims in compliance docs (S-2 regression guard).

    Phase 107 review S-2 (HIGH): documents that say "certified" / "compliant"
    when the project is self-assessed = fraudulent representation under CRA
    Article 24. This test fails if the words appear anywhere under
    ``docs/compliance/`` or in ``docs/security/CVD_POLICY.md`` outside the
    explicit allowlist.
    """
    if not scan_target.exists():
        pytest.skip(f"{scan_target.relative_to(REPO_ROOT)} does not exist yet")

    violations: dict[Path, list[tuple[int, str]]] = {}
    for md_file in _iter_markdown_files(scan_target):
        if md_file in ALLOWLIST:
            continue
        findings = _scan_file_for_overclaims(md_file)
        if findings:
            violations[md_file] = findings

    if violations:
        msg_lines = [
            "Overclaim language found in self-assessed compliance docs.",
            "Use 'self-assessed', 'aligned with', or 'mapped against' instead.",
            "If a real third-party certification was obtained, add the file to",
            "ALLOWLIST in tests/test_compliance_language.py with a code comment.",
            "",
        ]
        for path, findings in violations.items():
            msg_lines.append(f"  {path.relative_to(REPO_ROOT)}:")
            for lineno, line in findings:
                msg_lines.append(f"    line {lineno}: {line}")
        pytest.fail("\n".join(msg_lines))


def test_overclaim_pattern_actually_matches_overclaim_words() -> None:
    """The regex must match the literal overclaim words (sanity check on the gate itself)."""
    assert OVERCLAIM_PATTERN.search("This product is certified.")
    assert OVERCLAIM_PATTERN.search("We are CRA-compliant.")
    # Case-insensitive
    assert OVERCLAIM_PATTERN.search("CERTIFIED by someone")
    # Should NOT match descriptive nouns — those are honest usage
    assert not OVERCLAIM_PATTERN.search("conformance assessment")
    assert not OVERCLAIM_PATTERN.search("compliance team")
    assert not OVERCLAIM_PATTERN.search("certification roadmap")
