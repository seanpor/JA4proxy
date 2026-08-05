#!/usr/bin/env python3
"""
check_finding_spec.py — completeness gate for penetration-testing finding
specifications (Phase 814a).

A finding specification exists so that an implementer *with little codebase
knowledge* can execute the fix correctly, completely, and without asking a
question. Prose describing a vulnerability does not meet that bar: "SSRF in
webhooks.py" is a to-do for someone who already understands it, and a junior
handed that will fix one call site and miss four.

This script enforces the template in docs/security/pentest/PROGRAMME.md §9. It
checks *structure and substance*, not prose quality — it cannot tell you the
fix is correct, only that the author did not leave the parts a fixer needs
blank. That distinction matters: this is a floor, not a certificate.

Deliberately strict about three things, because they are the observed failure
modes rather than hypothetical ones:

  §6  "Every file that must change" must list actual files. Stopping at the
      first file is the single most common way a fix half-lands (Phase 522's
      role-default fix rippled through ~40 test call sites).
  §7  "Do NOT do this" must be present. For this product the tempting-but-wrong
      fix is usually "make it fail closed", which trades a security bug for an
      outage (rubric clause C-4).
  §9  Verification must name both expected states. A test that passes before
      and after the fix proves nothing.

Usage:
    python3 scripts/check_finding_spec.py <spec.md> [<spec.md> ...]
    python3 scripts/check_finding_spec.py --all      # every spec in the tree

Exit 0 = all specs complete. Exit 1 = at least one is not.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_GLOB = "docs/security/pentest/findings/*.md"

# Section number → (canonical heading fragment, human name).
# Matched case-insensitively on the "### N. <title>" headings of the template.
REQUIRED_SECTIONS: dict[int, tuple[str, str]] = {
    1: ("where it is", "Where it is"),
    2: ("what is wrong", "What is wrong"),
    3: ("why it matters", "Why it matters here"),
    4: ("reproduce", "Reproduce it"),
    5: ("the fix", "The fix"),
    6: ("every file that must change", "Every file that must change"),
    7: ("do not do this", "Do NOT do this"),
    8: ("anticipated questions", "Anticipated questions"),
    9: ("verification", "Verification"),
    10: ("performance impact", "Performance impact"),
    11: ("blast radius", "Blast radius and rollback"),
    12: ("definition of done", "Definition of done"),
}

# Header fields that must appear before section 1.
REQUIRED_HEADER_FIELDS = (
    "severity",
    "cwe",
    "lane",
    "discovered",
    "found against",
)

# Placeholder text that means "not filled in". Substance check, not style.
PLACEHOLDER_PATTERNS = (
    r"^\s*(tbd|todo|fixme|xxx|n/?a|\.\.\.|-)\s*$",
    r"<\s*(the actual code|exact path|one sentence|date|id|vector|pn)\b",
)


@dataclass
class SpecResult:
    """Outcome of checking one specification file."""

    path: Path
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _normalise(text: str) -> str:
    """Lowercase and collapse punctuation so heading matching is forgiving."""
    return re.sub(r"[^a-z0-9 ]+", " ", text.lower())


def _split_sections(body: str) -> dict[int, str]:
    """Return {section_number: section_body} for '### N. Title' headings."""
    sections: dict[int, str] = {}
    matches = list(re.finditer(r"^###\s+(\d+)\.\s*(.+?)\s*$", body, re.MULTILINE))
    for i, match in enumerate(matches):
        number = int(match.group(1))
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[number] = body[start:end]
    return sections


def _heading_titles(body: str) -> dict[int, str]:
    return {
        int(m.group(1)): m.group(2)
        for m in re.finditer(r"^###\s+(\d+)\.\s*(.+?)\s*$", body, re.MULTILINE)
    }


def _is_substantive(text: str) -> bool:
    """True when a section has content beyond whitespace and placeholders."""
    stripped = "\n".join(
        line for line in text.splitlines() if not line.strip().startswith(("|---", "| ---"))
    ).strip()
    if len(stripped) < 15:
        return False
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE | re.MULTILINE):
            return False
    return True


def _lists_real_files(text: str) -> bool:
    """§6 must name at least one plausible file path.

    A table of headers with no rows, or a sentence promising to work it out
    later, is exactly the gap that produces half-landed fixes.
    """
    # Any token that looks like a path with an extension, or a table row that
    # is not the header/separator.
    if re.search(r"[\w./-]+\.(go|py|yml|yaml|md|sh|json|toml|tf|ts|js)\b", text):
        return True
    rows = [
        line
        for line in text.splitlines()
        if line.strip().startswith("|")
        and not re.match(r"^\s*\|[\s|:-]+\|?\s*$", line)
        and "file" not in line.lower()[:20]
    ]
    return len(rows) >= 1


def _states_both_verification_states(text: str) -> bool:
    """§9 must say what happens on BOTH the unfixed and fixed builds."""
    lowered = text.lower()
    has_fail = re.search(r"\b(unfixed|pre-?fix|before|vulnerable)\b", lowered) and "fail" in lowered
    has_pass = re.search(r"\b(fixed|post-?fix|after)\b", lowered) and "pass" in lowered
    return bool(has_fail and has_pass)


def check_spec(path: Path) -> SpecResult:
    """Validate a single finding specification against the §9 template."""
    result = SpecResult(path=path)
    try:
        body = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.errors.append(f"cannot read: {exc}")
        return result

    if not re.search(r"^##\s+JA4PROXY-\d{4}-\d{4}\s+—", body, re.MULTILINE):
        result.errors.append(
            "missing canonical title line '## JA4PROXY-YYYY-NNNN — <title>' "
            "(IDs are allocated by findings_register.py, never by hand)"
        )

    header = body.split("### 1.", 1)[0]
    normalised_header = _normalise(header)
    for wanted in REQUIRED_HEADER_FIELDS:
        if _normalise(wanted) not in normalised_header:
            result.errors.append(f"header is missing the '{wanted}' field")

    sections = _split_sections(body)
    titles = _heading_titles(body)

    for number, (fragment, name) in REQUIRED_SECTIONS.items():
        if number not in sections:
            result.errors.append(f"§{number} '{name}' is missing entirely")
            continue
        actual_title = _normalise(titles.get(number, ""))
        if _normalise(fragment) not in actual_title:
            result.errors.append(
                f"§{number} should be '{name}' but is titled '{titles.get(number, '')}'"
            )
        if not _is_substantive(sections[number]):
            result.errors.append(f"§{number} '{name}' is empty or still a placeholder")

    if 6 in sections and _is_substantive(sections[6]) and not _lists_real_files(sections[6]):
        result.errors.append(
            "§6 'Every file that must change' names no actual file — a fixer "
            "cannot know where the ripple ends, which is how fixes half-land"
        )

    if 9 in sections and _is_substantive(sections[9]) and not _states_both_verification_states(sections[9]):
        result.errors.append(
            "§9 'Verification' must state the expected result on BOTH the "
            "unfixed build (FAIL) and the fixed build (PASS) — a test that "
            "passes in both states proves nothing"
        )

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("specs", nargs="*", help="specification files to check")
    parser.add_argument(
        "--all", action="store_true", help=f"check every spec matching {SPEC_GLOB}"
    )
    args = parser.parse_args(argv)

    paths: list[Path] = [Path(p) for p in args.specs]
    if args.all:
        paths.extend(sorted(ROOT.glob(SPEC_GLOB)))

    if not paths:
        # No specs yet is not a failure — the directory is created by the first
        # assessment sub-phase that finds something.
        print("check_finding_spec: no specifications to check")
        return 0

    results = [check_spec(p) for p in paths]
    failed = [r for r in results if not r.ok]

    for result in results:
        rel = result.path.relative_to(ROOT) if result.path.is_absolute() else result.path
        if result.ok:
            print(f"  ✓ {rel}")
        else:
            print(f"  ✗ {rel}")
            for error in result.errors:
                print(f"      {error}")

    print()
    if failed:
        print(f"check_finding_spec: {len(failed)}/{len(results)} specification(s) incomplete")
        print("  A finding without a complete specification does not leave the workstream.")
        print("  Template: docs/security/pentest/PROGRAMME.md §9")
        return 1

    print(f"check_finding_spec: {len(results)} specification(s) complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
