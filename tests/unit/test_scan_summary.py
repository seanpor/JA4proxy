"""Unit tests for scripts/scan_summary.py (Phase 228).

Covers the pure logic (severity tally, verdict, table rendering). The docker/
trivy invocation in scan_image() is integration-only and not exercised here.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "scan_summary.py"
_spec = importlib.util.spec_from_file_location("scan_summary", _MODULE_PATH)
scan_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_summary)


SAMPLE = {
    "Results": [
        {"Vulnerabilities": [
            {"Severity": "CRITICAL"},
            {"Severity": "HIGH"},
            {"Severity": "high"},        # case-insensitive
            {"Severity": "LOW"},         # ignored (not tracked)
        ]},
        {"Vulnerabilities": [{"Severity": "MEDIUM"}]},
        {"Vulnerabilities": None},       # null list tolerated
        {},                              # missing key tolerated
    ]
}


def test_count_severities_tallies_and_ignores_untracked():
    counts = scan_summary.count_severities(SAMPLE)
    assert counts == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1}


def test_count_severities_empty_document():
    assert scan_summary.count_severities({}) == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}


@pytest.mark.parametrize("counts,expected", [
    ({"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0}, "FAIL"),
    ({"CRITICAL": 0, "HIGH": 3, "MEDIUM": 9}, "WARN"),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 5}, "OK"),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}, "OK"),
])
def test_verdict(counts, expected):
    assert scan_summary.verdict(counts) == expected


def test_format_table_has_rows_totals_and_verdicts():
    rows = [
        ("img-a", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}),
        ("img-b", {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 4}),
    ]
    table = scan_summary.format_table(rows)
    assert "IMAGE" in table and "VERDICT" in table
    assert "img-a" in table and "img-b" in table
    # totals line sums correctly and inherits the worst verdict (CRITICAL present)
    total_line = [ln for ln in table.splitlines() if ln.startswith("TOTAL")][0]
    assert "2" in total_line and "FAIL" in total_line


def test_format_table_empty_rows():
    # No images scanned (e.g. nothing built) must not crash.
    table = scan_summary.format_table([])
    assert "TOTAL" in table


# --- Phase 228 part 2: gosec + misconfig ------------------------------------

GOSEC_SAMPLE = {
    "Issues": [
        {"severity": "HIGH", "rule_id": "G402"},
        {"severity": "MEDIUM", "rule_id": "G104"},
        {"severity": "medium", "rule_id": "G104"},   # case-insensitive
        {"severity": "LOW", "rule_id": "G101"},
        {"severity": "INFO"},                          # untracked, ignored
    ],
    "Stats": {"found": 5},
}

MISCONFIG_SAMPLE = {
    "Results": [
        {"Misconfigurations": [
            {"Severity": "HIGH", "ID": "DS-0002"},
            {"Severity": "MEDIUM", "ID": "DS-0026"},
        ]},
        {"Misconfigurations": None},
        {"Vulnerabilities": [{"Severity": "CRITICAL"}]},  # not a misconfig — ignored
    ]
}


def test_count_gosec():
    assert scan_summary.count_gosec(GOSEC_SAMPLE) == {"HIGH": 1, "MEDIUM": 2, "LOW": 1}


def test_count_gosec_empty():
    assert scan_summary.count_gosec({}) == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_count_misconfig_ignores_vulnerabilities():
    assert scan_summary.count_misconfig(MISCONFIG_SAMPLE) == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1}


@pytest.mark.parametrize("counts,fail,warn,expected", [
    ({"HIGH": 1, "MEDIUM": 0, "LOW": 0}, ("HIGH",), ("MEDIUM",), "FAIL"),   # gosec HIGH = FAIL
    ({"HIGH": 0, "MEDIUM": 2, "LOW": 0}, ("HIGH",), ("MEDIUM",), "WARN"),
    ({"CRITICAL": 0, "HIGH": 1}, ("CRITICAL", "HIGH"), (), "FAIL"),         # misconfig HIGH = FAIL
])
def test_verdict_parameterized(counts, fail, warn, expected):
    assert scan_summary.verdict(counts, fail=fail, warn=warn) == expected


def test_format_table_gosec_columns():
    v = lambda c: scan_summary.verdict(c, fail=("HIGH",), warn=("MEDIUM",))  # noqa: E731
    table = scan_summary.format_table(
        [("gosec", {"HIGH": 1, "MEDIUM": 0, "LOW": 2})],
        scan_summary.GOSEC_SEVS, v, name_header="SCAN",
    )
    assert "SCAN" in table and "LOW" in table and "CRIT" not in table
    assert "FAIL" in table  # HIGH present
