"""Phase 86i Gap 3 integration — observability standards register the
five new ja4proxy_loadtest_* metrics.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OBS_STANDARDS = REPO_ROOT / "docs" / "OBSERVABILITY_STANDARDS.md"

REQUIRED_LOADTEST_METRICS = [
    "ja4proxy_loadtest_connections_attempted_total",
    "ja4proxy_loadtest_connections_completed_total",
    "ja4proxy_loadtest_errors_total",
    "ja4proxy_loadtest_latency_seconds",
    "ja4proxy_loadtest_throughput_cps",
]


def test_observability_standards_registers_loadtest_metrics():
    assert OBS_STANDARDS.exists(), f"missing {OBS_STANDARDS}"
    text = OBS_STANDARDS.read_text()
    assert "Load Testing" in text, (
        "Phase 86i: OBSERVABILITY_STANDARDS.md must have a Load Testing subsection"
    )
    for metric in REQUIRED_LOADTEST_METRICS:
        assert metric in text, (
            f"Phase 86i: {metric} not registered in OBSERVABILITY_STANDARDS.md"
        )
