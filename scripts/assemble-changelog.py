#!/usr/bin/env python3
"""Assemble CHANGELOG news fragments into CHANGELOG.md.

Why this exists
---------------
``CHANGELOG.md`` prepends every phase's entry under the same
``## [Unreleased]`` → ``### Added`` heading. With several agents working in
parallel that single location is a guaranteed merge-conflict magnet. The
news-fragment pattern (cf. Towncrier) sidesteps it: each phase drops a
*uniquely named* fragment file under ``docs/fragments/`` and never touches
``CHANGELOG.md``. Unique filenames never collide, so phases stop conflicting.

This script folds those fragments into ``CHANGELOG.md`` and deletes them. It is
a **serialized** step — run it at release time (or by the orchestrator), not
per-phase — so the one place that edits ``CHANGELOG.md`` is never contended.

Run it containerised, like the rest of the Python tooling:

    make changelog-assemble        # wraps: docker run … ja4proxy-tools python …

Fragment format: a fragment is one or more Markdown bullet lines, e.g.

    - **Thing I added (Phase 322)**: one-line description. See `docs/phases/...`.

Filename convention: ``docs/fragments/phase-<NN><suffix>.md`` (any unique,
descriptive name ending in ``.md``; ``README.md`` is ignored).
"""

from __future__ import annotations

import pathlib
import sys

CHANGELOG_PATH = pathlib.Path("CHANGELOG.md")
FRAGMENTS_DIR = pathlib.Path("docs/fragments")
UNRELEASED_HEADING = "## [Unreleased]"
ADDED_HEADING = "### Added"


def collect_fragments(fragments_dir: pathlib.Path) -> list[tuple[str, str]]:
    """Return ``(name, body)`` for every fragment, sorted by filename.

    ``README.md`` and dotfiles are skipped. Bodies are stripped of trailing
    whitespace; empty fragments are skipped.
    """
    out: list[tuple[str, str]] = []
    for path in sorted(fragments_dir.glob("*.md")):
        if path.name == "README.md" or path.name.startswith("."):
            continue
        body = path.read_text(encoding="utf-8").strip("\n")
        if body.strip():
            out.append((path.name, body))
    return out


def assemble_changelog(changelog: str, fragments: list[tuple[str, str]]) -> str:
    """Insert fragment bodies under ``## [Unreleased]`` → ``### Added``.

    Pure function (no I/O) so it can be unit-tested. Idempotent when
    ``fragments`` is empty: returns ``changelog`` unchanged. Raises
    ``ValueError`` if the ``## [Unreleased]`` heading is missing.
    """
    if not fragments:
        return changelog

    lines = changelog.splitlines()
    try:
        unreleased_idx = next(
            i for i, ln in enumerate(lines) if ln.strip() == UNRELEASED_HEADING
        )
    except StopIteration:
        raise ValueError(f"{UNRELEASED_HEADING!r} heading not found in CHANGELOG")

    # Find the end of the Unreleased block (next '## ' heading or EOF).
    block_end = len(lines)
    for i in range(unreleased_idx + 1, len(lines)):
        if lines[i].startswith("## "):
            block_end = i
            break

    # Find an existing '### Added' inside the Unreleased block, else plan to
    # create one immediately after the Unreleased heading.
    added_idx = None
    for i in range(unreleased_idx + 1, block_end):
        if lines[i].strip() == ADDED_HEADING:
            added_idx = i
            break

    block = "\n".join(body for _, body in fragments)
    if added_idx is None:
        insertion = [UNRELEASED_HEADING, "", ADDED_HEADING, block]
        lines[unreleased_idx] = "\n".join(insertion)
    else:
        # Insert fragment bullets directly under '### Added'.
        lines.insert(added_idx + 1, block)

    result = "\n".join(lines)
    if changelog.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def main() -> int:
    if not CHANGELOG_PATH.exists():
        print(f"ERROR: {CHANGELOG_PATH} not found", file=sys.stderr)
        return 1
    if not FRAGMENTS_DIR.is_dir():
        print(f"ERROR: {FRAGMENTS_DIR} not found", file=sys.stderr)
        return 1

    fragments = collect_fragments(FRAGMENTS_DIR)
    if not fragments:
        print("No changelog fragments to assemble — nothing to do.")
        return 0

    new_text = assemble_changelog(CHANGELOG_PATH.read_text(encoding="utf-8"), fragments)
    CHANGELOG_PATH.write_text(new_text, encoding="utf-8")

    for name, _ in fragments:
        (FRAGMENTS_DIR / name).unlink()

    print(f"Assembled {len(fragments)} fragment(s) into {CHANGELOG_PATH}:")
    for name, _ in fragments:
        print(f"  - consumed docs/fragments/{name}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
