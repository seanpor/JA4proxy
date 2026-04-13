"""Phase 86i Gap 4 — capacity planning Grafana dashboard tests.

These tests assert that `deploy/monitoring/grafana/dashboards/04_capacity.json`
exists, is valid Grafana JSON, has the four rows specified in PHASE_86i.md,
uses the documented ceiling dashboard variables, and is provisioned via
`deploy/monitoring/grafana/provisioning/dashboards/default.yml`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = (
    REPO_ROOT / "deploy" / "monitoring" / "grafana" / "dashboards" / "04_capacity.json"
)
PROVISION_PATH = (
    REPO_ROOT / "deploy" / "monitoring" / "grafana" / "provisioning" / "dashboards" / "default.yml"
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
        "deploy/monitoring/grafana/provisioning/dashboards/default.yml"
    )


# ── Phase 86i reviewer blocker 2 — metric-name correctness ────────────────
#
# Before the fix, 04_capacity.json referenced ja4proxy metric names and
# labels that the Go proxy never exports (ja4proxy_tarpit_pool_size,
# ja4proxy_redis_latency_seconds_bucket, ja4proxy_connections_total{bypass=...},
# etc). Every panel on the dashboard would have been broken in a real
# deployment.


METRICS_GO = REPO_ROOT / "internal" / "metrics" / "metrics.go"


def _exported_metric_names() -> set:
    """Parse internal/metrics/metrics.go for every Name: "ja4proxy_..." and
    return the set of base metric names the proxy actually exports.

    Histograms are also accessible via the ``_bucket``, ``_count`` and
    ``_sum`` suffixes — we expand those here so the expr regex below
    matches them too.
    """
    import re
    src = METRICS_GO.read_text()
    base = set(re.findall(r'Name:\s*"(ja4proxy_[a-z0-9_]+)"', src))
    # Histogram-derived names.
    histogram_bases = {
        "ja4proxy_pipeline_duration_seconds",
        "ja4proxy_risk_score",
        "ja4proxy_sni_dga_score",
    }
    derived = set()
    for name in base & histogram_bases:
        derived.update({f"{name}_bucket", f"{name}_count", f"{name}_sum"})
    return base | derived


# Non-proxy metrics that 04_capacity.json legitimately references. These
# come from sibling exporters (haproxy_exporter, redis_exporter) that are
# scraped by Prometheus alongside ja4proxy.
ALLOWED_FOREIGN_METRICS = {
    "haproxy_backend_current_queue",
    "redis_memory_used_bytes",
    "redis_config_maxmemory",
}


def _panel_exprs(data: dict):
    """Yield (panel_title, expr) for every target expr on the dashboard."""
    for panel in data.get("panels", []):
        if panel.get("type") == "row":
            continue
        for t in panel.get("targets", []) or []:
            expr = t.get("expr")
            if expr:
                yield panel.get("title", "<untitled>"), expr


def test_dashboard_metrics_exist_in_proxy():
    """Every ja4proxy_* metric name referenced in any panel expr must
    appear in internal/metrics/metrics.go."""
    import re

    data = _load_dashboard()
    exported = _exported_metric_names()

    missing: list[tuple[str, str, str]] = []
    pattern = re.compile(r"ja4proxy_[a-z0-9_]+")
    for title, expr in _panel_exprs(data):
        for name in pattern.findall(expr):
            if name not in exported:
                missing.append((title, name, expr))

    assert not missing, (
        "Phase 86i reviewer blocker 2: dashboard references metrics the "
        "proxy does not export:\n"
        + "\n".join(f"  {t}: {n}  (in: {e})" for t, n, e in missing)
    )


def test_dashboard_does_not_use_nonexistent_labels_on_connections_total():
    """ja4proxy_connections_total has only an ``action`` label (see
    internal/metrics/metrics.go). The pre-fix dashboard referenced
    ``{bypass=...}`` on it, which would silently match zero series."""
    import re

    data = _load_dashboard()
    bad = []
    for title, expr in _panel_exprs(data):
        if "ja4proxy_connections_total" not in expr:
            continue
        # Extract the label block following the metric name.
        for m in re.finditer(
            r"ja4proxy_connections_total\s*\{([^}]*)\}", expr
        ):
            label_block = m.group(1)
            for label in re.findall(r"(\w+)\s*=", label_block):
                if label != "action":
                    bad.append((title, label, expr))

    assert not bad, (
        "ja4proxy_connections_total only has label 'action'; "
        "dashboard uses invalid labels:\n"
        + "\n".join(f"  {t}: {lbl!r} in {e}" for t, lbl, e in bad)
    )


def test_dashboard_foreign_metrics_are_in_allowlist():
    """Any non-ja4proxy metric must either be a promql function or in
    the foreign-exporter allowlist. Catches silent typos."""
    import re

    data = _load_dashboard()
    exported = _exported_metric_names()
    # A conservative list of promql function/keyword identifiers we expect
    # to see on a capacity dashboard.
    keywords = {
        "sum", "rate", "avg", "max", "min", "histogram_quantile",
        "predict_linear", "deriv", "clamp_min", "clamp_max", "by",
        "le", "vector", "irate", "increase", "topk", "bottomk", "on",
    }
    pattern = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
    # Grafana templated variables ($BYPASS_CEILING_CPS etc) are defined
    # in the dashboard templating block; capture them so they're not
    # flagged as unknown metrics.
    template_vars = {
        v.get("name") for v in
        (data.get("templating", {}) or {}).get("list", [])
        if v.get("name")
    }

    unexpected: list[tuple[str, str]] = []
    for title, expr in _panel_exprs(data):
        # Strip `$VAR` references before identifier scanning.
        stripped_expr = re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", "", expr)
        for ident in pattern.findall(stripped_expr):
            if ident in template_vars:
                continue
            if ident.startswith("ja4proxy_"):
                continue
            if ident in keywords:
                continue
            if ident in ALLOWED_FOREIGN_METRICS:
                continue
            if ident.isdigit() or ident in ("d", "h", "m", "s"):
                continue
            # Anything that looks like a metric name (underscored lower-case
            # word not in the keyword list) is suspect.
            if "_" in ident:
                unexpected.append((title, ident))

    assert not unexpected, (
        "Dashboard references unrecognised identifiers — either add to "
        "ALLOWED_FOREIGN_METRICS in this test or fix the dashboard:\n"
        + "\n".join(f"  {t}: {i}" for t, i in unexpected)
    )
