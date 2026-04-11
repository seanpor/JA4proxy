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
        row = re.search(
            rf"\|\s*{re.escape(field)}[^|]*\|\s*([^|]+)\|", ref
        )
        assert row, f"Reference Hardware row for {field!r} not found"
        value = row.group(1).strip()
        assert value and not re.match(r"_\(.*\)_", value), (
            f"Reference Hardware field {field!r} still unpopulated: {value!r}"
        )

    # Go Proxy Benchmarks section must show a real Git SHA.
    go_section_match = re.search(
        r"## Go Proxy Benchmarks(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    assert go_section_match
    go = go_section_match.group(1)
    sha_line = re.search(r"Git SHA:\s*([A-Za-z0-9_()]+)", go)
    assert sha_line, "Git SHA line missing from Go Proxy Benchmarks"
    sha_val = sha_line.group(1).strip()
    assert not sha_val.startswith("_("), (
        f"Git SHA still a placeholder: {sha_val!r}"
    )
