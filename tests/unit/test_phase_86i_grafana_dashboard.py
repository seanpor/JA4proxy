"""Phase 86i Gap 4 — capacity planning Grafana dashboard tests.

These tests assert that `monitoring/grafana/dashboards/04_capacity.json`
exists, is valid Grafana JSON, has the four rows specified in PHASE_86i.md,
uses the documented ceiling dashboard variables, and is provisioned via
`monitoring/grafana/provisioning/dashboards/default.yml`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = (
    REPO_ROOT / "monitoring" / "grafana" / "dashboards" / "04_capacity.json"
)
PROVISION_PATH = (
    REPO_ROOT / "monitoring" / "grafana" / "provisioning" / "dashboards" / "default.yml"
)


def _load_dashboard() -> dict:
    assert DASHBOARD_PATH.exists(), (
        f"Phase 86i: capacity dashboard missing at {DASHBOARD_PATH}"
    )
    with open(DASHBOARD_PATH) as f:
        return json.load(f)


def test_04_capacity_json_parses():
    data = _load_dashboard()
    # Minimal Grafana dashboard JSON shape.
    assert isinstance(data, dict)
    assert "title" in data
    assert "panels" in data or "rows" in data


def test_dashboard_has_four_rows():
    """Four rows: Throughput Headroom, Latency Budget, Scaling Pressure,
    30-Day Growth."""
    data = _load_dashboard()
    rows = data.get("rows")
    if rows is None:
        # Newer Grafana schema uses panels with type=row.
        rows = [p for p in data.get("panels", []) if p.get("type") == "row"]
    assert len(rows) == 4, f"expected 4 rows, got {len(rows)}"


def test_dashboard_uses_ceiling_variables():
    """Dashboard variables BYPASS_CEILING_CPS and SIGNAL_CEILING_CPS must
    be templated so ceilings come from benchmarks.md."""
    data = _load_dashboard()
    templating = data.get("templating", {}) or {}
    variables = templating.get("list", [])
    names = {v.get("name") for v in variables}
    assert "BYPASS_CEILING_CPS" in names, (
        "missing BYPASS_CEILING_CPS templated variable"
    )
    assert "SIGNAL_CEILING_CPS" in names, (
        "missing SIGNAL_CEILING_CPS templated variable"
    )


def test_dashboard_provisioned_in_default_yml():
    """The dashboard file must be discoverable by Grafana's provisioning —
    either the provisioning yml explicitly names it, or the yml points at
    a folder that includes the file. Assert the filename is referenced.
    """
    assert PROVISION_PATH.exists(), f"missing provisioning file: {PROVISION_PATH}"
    text = PROVISION_PATH.read_text()
    assert "04_capacity" in text, (
        "Phase 86i: 04_capacity.json not referenced in "
        "monitoring/grafana/provisioning/dashboards/default.yml"
    )
