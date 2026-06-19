"""Structural tests for ``docs/security/RISK_REGISTER.md``.

Phase 106 sub-task 5.4. Asserts the schema and minimum-row constraints
defined in ``docs/phases/PHASE_106.md`` §106b are preserved as the file
evolves.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[2]
RISK_REGISTER = REPO_ROOT / "docs" / "security" / "RISK_REGISTER.md"

REQUIRED_COLUMNS = {
    "id",
    "risk",
    "category",
    "likelihood",
    "impact",
    "owner",
    "mitigation",
    "residual",
    "status",
}

ALLOWED_CATEGORIES = {
    "technical",
    "operational",
    "security",
    "compliance",
    "supply-chain",
    "supply chain",  # accepted alias
    "commercial",
}

EMPTY_PLACEHOLDERS = {"", "-", "tbd", "n/a", "na"}

MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
TABLE_SEPARATOR_RE = re.compile(r"^\|[\s\-:|]+\|$")


def _parse_tables(text: str) -> list[dict]:
    """Parse all GitHub-flavoured Markdown pipe tables out of ``text``.

    Returns a list of ``{"header": [...], "rows": [{col: cell, ...}, ...]}``.
    The parser is intentionally minimal — it only handles the table shape
    used by RISK_REGISTER.md (every cell on its own line, no escaped pipes).
    """
    tables: list[dict] = []
    cur_header: list[str] | None = None
    cur_rows: list[dict] = []
    in_table = False

    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("|") and not in_table:
            cur_header = [c.strip() for c in stripped.strip("|").split("|")]
            cur_rows = []
            in_table = True
            continue
        if in_table and TABLE_SEPARATOR_RE.match(stripped):
            continue
        if in_table and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # pad/truncate to header length defensively
            if cur_header is not None:
                if len(cells) < len(cur_header):
                    cells = cells + [""] * (len(cur_header) - len(cells))
                elif len(cells) > len(cur_header):
                    cells = cells[: len(cur_header)]
                cur_rows.append(dict(zip(cur_header, cells)))
            continue
        if in_table and not stripped.startswith("|"):
            if cur_header is not None and cur_rows:
                tables.append({"header": cur_header, "rows": cur_rows})
            cur_header = None
            cur_rows = []
            in_table = False

    if in_table and cur_header is not None and cur_rows:
        tables.append({"header": cur_header, "rows": cur_rows})

    return tables


def _risk_tables(text: str) -> list[dict]:
    """Return tables whose header contains both 'ID' and 'Risk' (case-insensitive)."""
    out = []
    for tbl in _parse_tables(text):
        lower_header = {h.lower() for h in tbl["header"]}
        if "id" in lower_header and "risk" in lower_header:
            out.append(tbl)
    return out


def _all_risk_rows(text: str) -> list[dict]:
    rows: list[dict] = []
    for tbl in _risk_tables(text):
        rows.extend(tbl["rows"])
    return rows


def _cell(row: dict, name: str) -> str:
    """Return the cell from ``row`` whose header matches ``name`` case-insensitively."""
    for k, v in row.items():
        if k.lower() == name.lower():
            return v
    return ""


@pytest.fixture(scope="module")
def register_text() -> str:
    assert RISK_REGISTER.exists(), f"RISK_REGISTER.md not found at {RISK_REGISTER}"
    return RISK_REGISTER.read_text(encoding="utf-8")


def test_at_least_30_rows(register_text: str) -> None:
    rows = _all_risk_rows(register_text)
    assert (
        len(rows) >= 30
    ), f"RISK_REGISTER.md must have >= 30 risk rows; found {len(rows)}"


def test_required_columns_present(register_text: str) -> None:
    tables = _risk_tables(register_text)
    assert tables, "No risk-register tables (with ID + Risk columns) found"
    for tbl in tables:
        header_lower = {h.lower() for h in tbl["header"]}
        missing = REQUIRED_COLUMNS - header_lower
        assert not missing, (
            f"Risk table missing required columns {sorted(missing)}; "
            f"have {sorted(header_lower)}"
        )


def test_no_empty_mitigation(register_text: str) -> None:
    rows = _all_risk_rows(register_text)
    assert rows, "no rows parsed"
    bad: list[tuple[str, str]] = []
    for row in rows:
        rid = _cell(row, "ID")
        mitigation = _cell(row, "Mitigation").strip()
        if mitigation.lower() in EMPTY_PLACEHOLDERS:
            bad.append((rid, mitigation))
    assert not bad, "Rows with empty/placeholder Mitigation column: " + ", ".join(
        f"{rid!r}={val!r}" for rid, val in bad
    )


def test_categories_in_allowed_set(register_text: str) -> None:
    rows = _all_risk_rows(register_text)
    assert rows, "no rows parsed"
    bad: list[tuple[str, str]] = []
    for row in rows:
        rid = _cell(row, "ID")
        cat = _cell(row, "Category").strip().lower()
        if cat not in ALLOWED_CATEGORIES:
            bad.append((rid, cat))
    assert not bad, (
        "Rows with disallowed Category values: "
        + ", ".join(f"{rid!r}={val!r}" for rid, val in bad)
        + f"; allowed={sorted(ALLOWED_CATEGORIES)}"
    )


def test_each_row_has_source_link(register_text: str) -> None:
    rows = _all_risk_rows(register_text)
    assert rows, "no rows parsed"
    bad: list[str] = []
    for row in rows:
        rid = _cell(row, "ID")
        # Look across every cell — Mitigation, Source (if present), or any other.
        joined = " ".join(row.values())
        if not MARKDOWN_LINK_RE.search(joined):
            bad.append(rid)
    assert not bad, f"Rows missing any markdown link to a source: {bad}"


def test_internal_links_resolve(register_text: str) -> None:
    """Every relative markdown link in RISK_REGISTER.md resolves to a file."""
    base = RISK_REGISTER.parent
    missing: list[tuple[str, str]] = []
    for match in MARKDOWN_LINK_RE.finditer(register_text):
        text, target = match.group(1), match.group(2).strip()
        # skip absolute URLs and anchors
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        # strip a trailing #anchor / ?query so we resolve the file path itself
        path_part = target.split("#", 1)[0].split("?", 1)[0]
        if not path_part:
            continue
        resolved = (base / path_part).resolve()
        if not resolved.exists():
            missing.append((text, target))
    assert not missing, "Unresolved relative markdown links: " + ", ".join(
        f"[{t}]({u})" for t, u in missing
    )
