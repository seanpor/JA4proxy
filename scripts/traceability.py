#!/usr/bin/env python3
"""traceability.py — generate ``docs/TRACEABILITY.md`` from phase docs.

Reads local files and ``docs/phases/manifest.yaml`` only. No network. No untrusted input.

This script walks every ``docs/phases/PHASE_*.md`` file, extracts acceptance
criteria carrying a ``REQ-NNN-MM:`` prefix, parses the trailing ``Verified by:``
clause, and emits ``docs/TRACEABILITY.md`` as a sortable markdown table.

The schema lives in ``docs/STYLE_GUIDE.md`` §6. Tagging is opt-in: only phases
whose ``manifest.yaml`` entry has ``req_tagged: true`` are enforced. All other
phases are silently skipped.

Statuses emitted in the table:

- ``AUTOMATED``     — has a ``Verified by: `tests/...``` clause
- ``MANUAL-REVIEW`` — has the literal ``[MANUAL-REVIEW]`` marker
- ``MISSING``       — a tagged phase has a REQ line without ``Verified by:``

Exit codes:

- ``0`` — generation OK; all req_tagged phases have complete ``Verified by:`` clauses
- ``1`` — at least one req_tagged phase has a REQ line without ``Verified by:``
- ``2`` — argument or I/O error

CLI::

    python3 scripts/traceability.py [--check]

``--check`` mode does not write the file; it only exits with the correct code.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

ROOT = Path(__file__).resolve().parent.parent
PHASES_DIR = ROOT / "docs" / "phases"
MANIFEST_PATH = PHASES_DIR / "manifest.yaml"
OUTPUT_PATH = ROOT / "docs" / "TRACEABILITY.md"

# Matches ``REQ-NNN-MM:`` (3 digits, dash, 2+ digits). Allows optional list
# bullet/checkbox prefixes that are common in phase acceptance criteria.
_REQ_LINE = re.compile(
    r"""^\s*
        (?:[-*]\s+)?            # optional bullet
        (?:\[[ xX]\]\s+)?       # optional checkbox
        (?P<id>REQ-\d{3}-\d{2,}) # REQ-NNN-MM (MM may be 2+ digits)
        \s*:\s*
        (?P<rest>.*)$           # remainder of the line
    """,
    re.VERBOSE,
)

# Locates every ``Verified by:`` token (case-insensitive). We pick the LAST
# match so a literal mention inside a backticked phrase in the description
# (e.g. ``the `Verified by:` clause``) is not mistaken for the real clause.
_VERIFIED_BY_TOKEN = re.compile(r"Verified\s+by\s*:\s*", re.IGNORECASE)

# Inside the ``target``, locate either a backticked test path or the literal
# manual-review marker.
_BACKTICK = re.compile(r"`([^`]+)`")
_MANUAL_RE = re.compile(r"\[MANUAL[- ]REVIEW\]", re.IGNORECASE)


@dataclass(frozen=True)
class Requirement:
    """A single tagged acceptance criterion."""

    req_id: str
    phase: str
    description: str
    verified_by: str  # may be empty string when missing
    status: str  # AUTOMATED | MANUAL-REVIEW | MISSING
    source_file: Path
    source_line: int  # 1-based for human consumption


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    """Return the parsed manifest YAML, or ``{}`` if it cannot be loaded."""
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def tagged_phase_numbers(manifest: dict) -> set[str]:
    """Return the set of phase numbers (as strings) opted into REQ tagging.

    A phase is opted in when its manifest entry has ``req_tagged: true``.
    """
    phases = manifest.get("phases", {}) or {}
    out: set[str] = set()
    for key, entry in phases.items():
        if isinstance(entry, dict) and entry.get("req_tagged") is True:
            out.add(str(key))
    return out


def phase_number_from_filename(path: Path) -> str | None:
    """Return the phase number portion of ``PHASE_NN.md`` filenames.

    Strips leading zeros so ``PHASE_015.md`` and ``PHASE_15.md`` both map to
    ``"15"``. Skips review/notes/subplan files (``PHASE_15_review.md`` etc.).
    Returns ``None`` if the filename does not match the strict pattern.
    """
    m = re.fullmatch(r"PHASE_(\d+)\.md", path.name)
    if not m:
        return None
    raw = m.group(1)
    # Normalise: drop leading zeros but keep "0"
    return str(int(raw))


def _join_continuations(lines: list[str], start: int) -> tuple[str, int]:
    """Join a REQ line with any indented continuation lines.

    Returns ``(joined_text, end_index_exclusive)`` where ``end_index_exclusive``
    is the index of the first line that was *not* part of the continuation.

    A continuation line is a non-empty line that is indented (starts with
    whitespace) AND does not itself begin a new bullet/REQ. We stop at the
    first blank line, the next bullet, or a non-indented line.
    """
    if start >= len(lines):
        return "", start
    parts = [lines[start].rstrip()]
    i = start + 1
    while i < len(lines):
        nxt = lines[i]
        stripped = nxt.strip()
        if not stripped:
            break
        # New bullet or REQ -> stop
        if re.match(r"^\s*(?:[-*]\s+|\d+\.\s+|#)", nxt):
            break
        # Must be indented to count as continuation
        if not nxt.startswith((" ", "\t")):
            break
        parts.append(stripped)
        i += 1
    return " ".join(parts), i


def _classify(verified_clause: str) -> tuple[str, str]:
    """Return ``(verified_display, status)`` for the parsed clause.

    ``verified_clause`` is the text after ``Verified by:`` with surrounding
    whitespace stripped. Empty string → ``("", "MISSING")``.
    """
    if not verified_clause:
        return "", "MISSING"
    if _MANUAL_RE.search(verified_clause):
        return "[MANUAL-REVIEW]", "MANUAL-REVIEW"
    bt = _BACKTICK.search(verified_clause)
    if bt:
        return f"`{bt.group(1)}`", "AUTOMATED"
    # Fall back: a bare path is acceptable but unusual; still automated.
    return verified_clause.strip(), "AUTOMATED"


def parse_phase_file(path: Path, phase_number: str) -> list[Requirement]:
    """Extract every REQ-tagged acceptance criterion from a single phase file."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    out: list[Requirement] = []

    i = 0
    while i < len(lines):
        m = _REQ_LINE.match(lines[i])
        if not m:
            i += 1
            continue
        joined, next_i = _join_continuations(lines, i)
        # Re-match against the joined text to recover id + rest cleanly.
        jm = _REQ_LINE.match(joined)
        if not jm:
            i = next_i if next_i > i else i + 1
            continue
        req_id = jm.group("id")
        rest = jm.group("rest").strip()

        # Find the LAST ``Verified by:`` token so a literal mention inside a
        # backticked phrase in the description (e.g. "the `Verified by:`
        # clause") is not mistaken for the actual clause.
        vmatches = list(_VERIFIED_BY_TOKEN.finditer(rest))
        if vmatches:
            vmatch = vmatches[-1]
            description = rest[: vmatch.start()].rstrip(" .\t`")
            verified_clause = rest[vmatch.end():].strip()
        else:
            description = rest
            verified_clause = ""

        verified_display, status = _classify(verified_clause)
        out.append(
            Requirement(
                req_id=req_id,
                phase=phase_number,
                description=description,
                verified_by=verified_display,
                status=status,
                source_file=path,
                source_line=i + 1,
            )
        )
        i = next_i if next_i > i else i + 1
    return out


def collect_requirements(
    phases_dir: Path,
    manifest: dict,
) -> list[Requirement]:
    """Walk ``phases_dir`` and return all REQs from req_tagged phases."""
    tagged = tagged_phase_numbers(manifest)
    out: list[Requirement] = []
    if not phases_dir.is_dir():
        return out
    for phase_path in sorted(phases_dir.glob("PHASE_*.md")):
        num = phase_number_from_filename(phase_path)
        if num is None:
            continue
        if num not in tagged:
            continue
        out.extend(parse_phase_file(phase_path, num))
    return out


def _escape_md_cell(text: str) -> str:
    """Escape pipe characters so they don't break the markdown table."""
    return text.replace("|", "\\|")


def render_table(reqs: Iterable[Requirement]) -> str:
    """Render the requirements as a sortable markdown table."""
    header = (
        "| REQ-ID | Phase | Description | Verified by | Status |\n"
        "|--------|-------|-------------|-------------|--------|\n"
    )
    rows = []
    # Stable sort by (phase as int when possible, req_id)
    def sort_key(r: Requirement) -> tuple:
        try:
            phase_n = int(r.phase)
        except ValueError:
            phase_n = 10**9
        return (phase_n, r.req_id)

    for r in sorted(reqs, key=sort_key):
        rows.append(
            "| {id} | {phase} | {desc} | {ver} | {status} |".format(
                id=_escape_md_cell(r.req_id),
                phase=_escape_md_cell(r.phase),
                desc=_escape_md_cell(r.description),
                ver=_escape_md_cell(r.verified_by) if r.verified_by else "—",
                status=_escape_md_cell(r.status),
            )
        )
    return header + "\n".join(rows) + ("\n" if rows else "")


def render_document(reqs: Iterable[Requirement]) -> str:
    """Render the full ``docs/TRACEABILITY.md`` body."""
    body = (
        "# Requirements Traceability Matrix\n\n"
        "> Auto-generated by `scripts/traceability.py`. Do not edit by hand.\n"
        "> See `docs/STYLE_GUIDE.md` §6 for the REQ-tagging schema.\n\n"
    )
    body += render_table(reqs)
    return body


def report_missing(reqs: Iterable[Requirement], stream) -> int:
    """Write any ``MISSING`` requirements to ``stream``. Returns count."""
    n = 0
    for r in reqs:
        if r.status == "MISSING":
            stream.write(
                f"{r.source_file}:{r.source_line}: {r.req_id} "
                "lacks a 'Verified by:' clause\n"
            )
            n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        description="Generate docs/TRACEABILITY.md from phase docs."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate without writing the output file.",
    )
    parser.add_argument(
        "--phases-dir",
        type=Path,
        default=PHASES_DIR,
        help="Override the phases directory (testing).",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH,
        help="Override the manifest path (testing).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Override the output file path (testing).",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"failed to load manifest {args.manifest}: {exc}\n")
        return 2

    try:
        reqs = collect_requirements(args.phases_dir, manifest)
    except OSError as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"failed to read phase docs: {exc}\n")
        return 2

    missing = report_missing(reqs, sys.stderr)

    if not args.check:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(render_document(reqs), encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"failed to write {args.output}: {exc}\n")
            return 2

    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
