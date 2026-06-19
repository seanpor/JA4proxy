"""Phase 107f.4 — ATT&CK mapping CI gate.

The forward-mapping table in ``docs/security/ATTACK_MAPPING.md`` couples
JA4proxy signal modules to MITRE ATT&CK technique IDs. Two regression hazards:

1. **A-3 (Architecture, LOW):** if a signal module is renamed/moved, the
   ``Source file`` column rots silently and SOC consumers can no longer pivot
   from a JA4proxy event to the source code that produced it.
2. **T-3 (Testing, MEDIUM):** the Notes-for-Implementer policy requires every
   row to carry an honest ``high`` / ``medium`` / ``low`` confidence label.
   A future row added without a label undermines the whole document's
   credibility.

This module enforces both. Two independent ``def test_*`` functions so each
hazard reports independently.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK_MAPPING = REPO_ROOT / "docs" / "security" / "ATTACK_MAPPING.md"

#: Confidence labels permitted in the Confidence column. The CI gate is
#: case-insensitive on the label word but strict on the allowed set.
CONFIDENCE_PATTERN = re.compile(r"^(high|medium|low)\b", re.IGNORECASE)

#: A row in the forward-mapping table starts with `|` and contains 6 columns
#: (plus the leading/trailing empty cells from the `|...|...|` syntax). We
#: locate the table by its header signature ("Signal module" + "Confidence")
#: rather than by absolute line number so the doc can grow new sections.
HEADER_SIGNATURE = ("Signal module", "Confidence")
TABLE_SEPARATOR = re.compile(r"^\|[\s\-:|]+\|\s*$")


def _parse_forward_table() -> list[list[str]]:
    """Return the data rows of the forward-mapping table as lists of cells.

    Skips the header row, the markdown separator row, and any row whose first
    non-empty cell is an HTML comment (TODO scaffolding).
    """
    text = ATTACK_MAPPING.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Find the header line (must contain both signature substrings)
    header_idx = None
    for idx, line in enumerate(lines):
        if all(sig in line for sig in HEADER_SIGNATURE):
            header_idx = idx
            break
    if header_idx is None:
        pytest.fail(
            "Could not locate forward-mapping table header in "
            f"{ATTACK_MAPPING.relative_to(REPO_ROOT)} "
            f"(looking for substrings: {HEADER_SIGNATURE})"
        )

    rows: list[list[str]] = []
    # Data rows begin two lines after the header (header, separator, then data)
    for line in lines[header_idx + 1 :]:
        if not line.startswith("|"):
            break  # table ended
        if TABLE_SEPARATOR.match(line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0].startswith("<!--"):
            continue
        rows.append(cells)
    return rows


def test_attack_mapping_confidence_labels_present() -> None:
    """Every forward-mapping row must carry one of high/medium/low (T-3 guard).

    Confidence column is the 5th cell (index 4). The label must START the
    cell — a free-form justification follows after a dash.
    """
    rows = _parse_forward_table()
    assert rows, "Forward-mapping table is empty — expected populated rows"

    bad: list[tuple[int, str]] = []
    for i, cells in enumerate(rows, start=1):
        if len(cells) < 6:
            bad.append((i, f"row has {len(cells)} cells, expected ≥ 6: {cells!r}"))
            continue
        confidence_cell = cells[4]
        if not CONFIDENCE_PATTERN.match(confidence_cell):
            bad.append(
                (
                    i,
                    f"confidence cell {confidence_cell!r} does not start with high/medium/low",
                )
            )
    if bad:
        msg = ["Confidence-label gate failed:"]
        for i, why in bad:
            msg.append(f"  row {i}: {why}")
        pytest.fail("\n".join(msg))


def test_attack_mapping_source_files_exist() -> None:
    """Every Source-file path in the forward-mapping table must exist on disk (A-3 guard)."""
    rows = _parse_forward_table()
    assert rows, "Forward-mapping table is empty — expected populated rows"

    missing: list[tuple[int, str]] = []
    for i, cells in enumerate(rows, start=1):
        if len(cells) < 6:
            missing.append((i, f"row has {len(cells)} cells, no Source-file column"))
            continue
        source_cell = cells[5].strip("`")  # tolerate backtick-wrapped paths
        candidate = REPO_ROOT / source_cell
        if not candidate.exists():
            missing.append((i, f"path does not exist: {source_cell}"))
    if missing:
        msg = ["Source-file existence gate failed:"]
        for i, why in missing:
            msg.append(f"  row {i}: {why}")
        msg.append("")
        msg.append("If a signal module was renamed, update ATTACK_MAPPING.md.")
        pytest.fail("\n".join(msg))
