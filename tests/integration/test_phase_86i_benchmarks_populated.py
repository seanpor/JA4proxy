"""Phase 86i Gap 2 integration — benchmarks.md has been populated.

Asserts the Go Proxy Benchmarks section has zero `_(measure)_`
placeholders and that the hardware header fields (hardware/OS/Redis/
Git SHA/Go version/Python version) are populated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS_MD = REPO_ROOT / "docs" / "performance" / "benchmarks.md"


def _read() -> str:
    assert BENCHMARKS_MD.exists(), f"missing {BENCHMARKS_MD}"
    return BENCHMARKS_MD.read_text()


def test_benchmarks_md_has_no_placeholders():
    """The Go Proxy Benchmarks section must have zero `_(measure)_` markers."""
    text = _read()
    # Grab everything from the Go Proxy Benchmarks heading to the next
    # top-level or second-level heading that isn't a subsection.
    m = re.search(r"## Go Proxy Benchmarks(.*?)(?=\n## |\Z)", text, re.DOTALL)
    assert m, "Go Proxy Benchmarks section not found in benchmarks.md"
    section = m.group(1)
    placeholders = re.findall(r"_\(measure\)_", section)
    assert not placeholders, (
        f"Phase 86i: {len(placeholders)} `_(measure)_` placeholders "
        f"remain in the Go Proxy Benchmarks section"
    )


def test_benchmarks_md_has_hardware_header():
    """Hardware / OS / Redis / Git SHA / Go version / Python version must
    all be populated in the Reference Hardware header."""
    text = _read()
    # Each required field must have something other than `_(...)_`.
    # Look at the Reference Hardware table rows.
    ref_section_match = re.search(
        r"## Reference Hardware(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert ref_section_match, "Reference Hardware section missing"
    ref = ref_section_match.group(1)
    required_fields = ["CPU", "OS", "Redis", "Go", "Python"]
    for field in required_fields:
        # Expect a table row `| field | actual value |`.
        row = re.search(rf"\|\s*{re.escape(field)}[^|]*\|\s*([^|]+)\|", ref)
        assert row, f"Reference Hardware row for {field!r} not found"
        value = row.group(1).strip()
        assert value and not re.match(
            r"_\(.*\)_", value
        ), f"Reference Hardware field {field!r} still unpopulated: {value!r}"

    # Go Proxy Benchmarks section must show a real Git SHA.
    go_section_match = re.search(
        r"## Go Proxy Benchmarks(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert go_section_match
    go = go_section_match.group(1)
    sha_line = re.search(r"Git SHA:\s*([A-Za-z0-9_()]+)", go)
    assert sha_line, "Git SHA line missing from Go Proxy Benchmarks"
    sha_val = sha_line.group(1).strip()
    assert not sha_val.startswith("_("), f"Git SHA still a placeholder: {sha_val!r}"


# ── PHASE_101 M26: numeric + SHA shape validation ──────────────────────────


def test_git_sha_matches_hex_shape():
    """PHASE_101 M26 — the Go Proxy Benchmarks header's Git SHA must be a
    real 7–40 char hex blob, not a placeholder, alias, or branch name.

    A placeholder-looking string like ``b0dd515`` matches; a non-hex
    alias like ``HEAD`` or a branch name like ``main`` fails — those
    were creeping in via copy-paste from `git rev-parse --short HEAD`
    output that included branch metadata.
    """
    text = _read()
    go_section_match = re.search(
        r"## Go Proxy Benchmarks(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert go_section_match, "Go Proxy Benchmarks section missing"
    go = go_section_match.group(1)
    sha_match = re.search(r"Git SHA:\s*([0-9a-f]{7,40})\b", go)
    assert sha_match, (
        "PHASE_101 M26: Git SHA in Go Proxy Benchmarks must match "
        "[0-9a-f]{7,40} — got header without a hex SHA"
    )


def test_reference_hardware_required_fields_present():
    """PHASE_101 M26 — every field SREs use to compare measurement
    contexts must be populated: CPU, OS, Redis, Go, Python."""
    text = _read()
    ref_section_match = re.search(
        r"## Reference Hardware(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert ref_section_match, "Reference Hardware section missing"
    ref = ref_section_match.group(1)
    for field in ("CPU", "OS", "Redis", "Go", "Python"):
        row = re.search(rf"\|\s*{re.escape(field)}\s*\|\s*([^|]+)\|", ref)
        assert row, f"PHASE_101 M26: Reference Hardware row {field!r} missing"
        value = row.group(1).strip()
        assert value, f"PHASE_101 M26: {field!r} row is empty"
        assert not re.match(
            r"_\(.*\)_", value
        ), f"PHASE_101 M26: {field!r} still has placeholder: {value!r}"


def test_run_date_present_and_iso():
    """PHASE_101 M26 — the Go Proxy Benchmarks block must have a
    parseable ``Run date: YYYY-MM-DD`` line. Without a date, comparing
    historical runs becomes guesswork."""
    text = _read()
    go_section_match = re.search(
        r"## Go Proxy Benchmarks(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert go_section_match
    go = go_section_match.group(1)
    date_match = re.search(r"Run date:\s*(\d{4}-\d{2}-\d{2})\b", go)
    assert date_match, (
        "PHASE_101 M26: Go Proxy Benchmarks must include " "`Run date: YYYY-MM-DD`"
    )


def test_historical_runs_throughput_parses_as_positive_finite_float():
    """PHASE_101 M26 — every Historical Runs row's Throughput cell must
    be a positive finite float (NaN, Inf, negative, zero are all
    rejected). Catches typos like an extra unit, a placeholder, or a
    wrapped notebook value."""
    text = _read()
    hist_match = re.search(r"## Historical Runs(.*?)(?=\n## |\Z)", text, re.DOTALL)
    assert hist_match, "Historical Runs section missing"
    hist = hist_match.group(1)
    # Skip the header row and separator. Each data row has 6 pipes.
    rows = [
        ln
        for ln in hist.splitlines()
        if ln.strip().startswith("|") and not re.match(r"^\|[\s\-:|]+$", ln.strip())
    ]
    assert len(rows) >= 2, "Historical Runs needs header + ≥1 data row"
    # Drop the table header.
    data_rows = rows[1:]
    assert data_rows, "PHASE_101 M26: Historical Runs has no data rows"
    for row in data_rows:
        cells = [c.strip() for c in row.split("|")[1:-1]]
        assert len(cells) >= 4, f"PHASE_101 M26: malformed historical row: {row!r}"
        throughput_cell = cells[3]
        # Strip thousands separators and any trailing unit token.
        numeric = re.match(r"([0-9.]+)", throughput_cell.replace(",", ""))
        assert numeric, (
            f"PHASE_101 M26: throughput cell {throughput_cell!r} "
            "has no leading numeric value"
        )
        value = float(numeric.group(1))
        assert value > 0, (
            f"PHASE_101 M26: throughput must be > 0, got {value} "
            f"from {throughput_cell!r}"
        )
        # math.isnan/isinf cannot return True after a successful float()
        # parse of a leading-digit string, but be explicit so a future
        # cell containing a literal "NaN" is caught before it propagates.
        import math

        assert math.isfinite(
            value
        ), f"PHASE_101 M26: throughput must be finite, got {value}"
