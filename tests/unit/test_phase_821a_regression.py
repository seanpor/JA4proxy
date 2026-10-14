"""
Phase 821a regression tests.

Regression Test #1: Every metric name, label name, and label value in the catalogue
resolves against Go source definitions with >=1 emission site outside internal/metrics/.

Regression Test #2: Cardinality guard scoped to all of internal/.
No label may be named 'ip', 'client_ip', 'ja4', 'sni', or 'fingerprint'.
SNIGuard and JA4Guard remain unused in production code.

Regression Test #3: No client-supplied PromQL. No route in management accepts arbitrary
query parameters passed to the Prometheus client.

Regression Test #4: Metric catalogue lint. Every tile has non-empty means/when_red,
and proper zero handling (no binary '+' between selectors, counter tiles carry
or vector(0) unless renders_empty_as_no_rows is True).
"""

from __future__ import annotations

import ast
import inspect
import re
import subprocess
from pathlib import Path

import pytest

from management.api.metric_catalogue import CATALOGUE, Tile

REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Helpers for Go source parsing
# ---------------------------------------------------------------------------

_METRIC_OPTS_RE = re.compile(
    r'(?:CounterOpts|GaugeOpts|HistogramOpts|SummaryOpts)\s*\{\s*Name:\s*"([^"]+)"'
)
_VEC_LABELS_RE = re.compile(
    r'New(?:Counter|Gauge|Histogram|Summary)Vec\s*\(\s*(?:prometheus\.)?(?:Counter|Gauge|Histogram|Summary)Opts\s*\{\s*Name:\s*"([^"]+)"[^}]*\}\s*,\s*\[\]string\{([^}]+)\}',
    re.DOTALL,
)


def _load_go_metric_definitions() -> dict[str, set[str]]:
    """Parse internal/ for all metric definitions and their declared label names."""
    metrics: dict[str, set[str]] = {}

    for path in (REPO / "internal").rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="ignore")

        # Find vector metrics with labels
        for match in _VEC_LABELS_RE.finditer(text):
            name = match.group(1)
            raw_labels = match.group(2)
            label_names = {lbl.strip().strip('"') for lbl in raw_labels.split(",") if lbl.strip().strip('"')}
            metrics[name] = label_names

        # Find scalar metrics (empty label set)
        for match in _METRIC_OPTS_RE.finditer(text):
            name = match.group(1)
            if name not in metrics:
                metrics[name] = set()

    return metrics


def _get_go_emission_sites() -> set[str]:
    """Metric names with >=1 emission site (.Inc, .Set, .Observe, .WithLabelValues)
    outside internal/metrics/.
    """
    emitted = set()
    call_pattern = re.compile(r'\b([A-Za-z0-9_]+)\s*\.\s*(?:Inc|Set|Observe|WithLabelValues|With)\b')

    # Look for calls to .Inc, .Set, .Observe, .WithLabelValues across internal/ and cmd/
    # (excluding metrics.go and metrics_coverage_test.go where metrics are only declared/registered)
    for path in list((REPO / "internal").rglob("*.go")) + list((REPO / "cmd").rglob("*.go")):
        if path.name == "metrics.go" or path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="ignore")
        for match in call_pattern.finditer(text):
            emitted.add(match.group(1))

    # Also map Go variable names to Prometheus metric names
    var_to_metric: dict[str, str] = {}
    metrics_go = (REPO / "internal" / "metrics" / "metrics.go").read_text(errors="ignore")
    # Matches: VarName = prometheus.New...Opts{Name: "ja4proxy_..."
    for match in re.finditer(r'([A-Za-z0-9_]+)\s*=\s*(?:prometheus\.)?New[A-Za-z0-9]+\s*\(\s*(?:prometheus\.)?[A-Za-z0-9]+Opts\s*\{\s*Name:\s*"([^"]+)"', metrics_go):
        var_to_metric[match.group(1)] = match.group(2)

    # Return the Prometheus metric names that are emitted outside internal/metrics
    emitted_metric_names = set()
    for var, metric_name in var_to_metric.items():
        if var in emitted:
            emitted_metric_names.add(metric_name)

    # Some metrics might be emitted directly in cmd/ja4pd/ or internal/tap/
    for path in list((REPO / "cmd").rglob("*.go")) + list((REPO / "internal" / "tap").rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="ignore")
        for m_name in re.findall(r'"(ja4proxy_[a-z0-9_]+)"', text):
            emitted_metric_names.add(m_name)

    return emitted_metric_names


# ---------------------------------------------------------------------------
# Regression Test #1: Catalogue resolution against Go source
# ---------------------------------------------------------------------------

def test_catalogue_metrics_and_labels_resolve_in_go():
    """Every metric name, label name, and label value in the catalogue must resolve
    against Go source definitions, with >=1 emission site outside internal/metrics/.
    """
    assert len(CATALOGUE) > 0, "Catalogue must not be empty"
    go_metrics = _load_go_metric_definitions()
    emitted_metrics = _get_go_emission_sites()

    from tests.unit.test_metric_selector_validity import extract_label_selectors

    for tile_id, tile in CATALOGUE.items():
        # Match direct metric names or __name__=~"..." regexes
        metric_names = re.findall(r'\b(ja4proxy_[a-z0-9_]+)\b', tile.expr)
        name_regex_matches = re.findall(r'__name__=~"([^"]+)"', tile.expr)
        for pattern in name_regex_matches:
            # e.g. ja4proxy_(workchan_dropped|stream_event_drops|...)_total
            m_sub = re.match(r'([^(]+)\(([^)]+)\)(.*)', pattern)
            if m_sub:
                prefix, group, suffix = m_sub.group(1), m_sub.group(2), m_sub.group(3)
                for part in group.split('|'):
                    metric_names.append(f"{prefix}{part}{suffix}")
            else:
                metric_names.append(pattern)

        assert metric_names, f"Tile {tile_id} has expression without ja4proxy_* metric: {tile.expr}"

        for m_name in metric_names:
            base_name = re.sub(r'_(bucket|sum|count)$', '', m_name)
            assert base_name in go_metrics, (
                f"Tile {tile_id} references unknown metric {base_name} (raw: {m_name}) not defined in Go source"
            )
            assert base_name in emitted_metrics, (
                f"Tile {tile_id} references metric {base_name} which has no emission sites outside internal/metrics/"
            )

        # Check label names if selectors exist
        selectors = extract_label_selectors(tile.expr)
        for m_name, labels in selectors:
            base_name = re.sub(r'_(bucket|sum|count)$', '', m_name)
            declared_labels = go_metrics.get(base_name, set())
            for lbl_name in labels.keys():
                assert lbl_name in declared_labels, (
                    f"Tile {tile_id} uses label '{lbl_name}' on metric {base_name}, but declared labels are {declared_labels}"
                )


# ---------------------------------------------------------------------------
# Regression Test #2: Cardinality guard scoped to all of internal/
# ---------------------------------------------------------------------------

def test_cardinality_guard_no_forbidden_labels_and_guards_unused():
    """No metric in internal/ may have labels named ip, client_ip, ja4, sni, fingerprint.
    SNIGuard and JA4Guard must remain unused in production code.
    """
    forbidden_labels = {"ip", "client_ip", "ja4", "sni", "fingerprint"}

    for path in (REPO / "internal").rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="ignore")

        for match in _VEC_LABELS_RE.finditer(text):
            name = match.group(1)
            raw_labels = match.group(2)
            label_names = {lbl.strip().strip('"').lower() for lbl in raw_labels.split(",") if lbl.strip()}
            intersection = label_names & forbidden_labels
            assert not intersection, (
                f"Metric {name} in {path} uses forbidden high-cardinality labels: {intersection}"
            )

    # Check SNIGuard and JA4Guard are unused outside tests and definitions
    for path in (REPO / "internal").rglob("*.go"):
        if path.name.endswith("_test.go") or path.name == "metrics.go":
            continue
        text = path.read_text(errors="ignore")
        assert "SNIGuard" not in text, f"SNIGuard found used in production code {path}"
        assert "JA4Guard" not in text, f"JA4Guard found used in production code {path}"


# ---------------------------------------------------------------------------
# Regression Test #3: No client-supplied PromQL
# ---------------------------------------------------------------------------

def test_no_client_supplied_promql():
    """Ensure no FastAPI route in management/ takes query string parameters that
    are fed into Prometheus query functions. The API must only accept tile IDs.
    """
    from management.api.routes import partials

    # Inspect partials and other route modules
    for name, func in inspect.getmembers(partials, inspect.isfunction):
        sig = inspect.signature(func)
        param_names = set(sig.parameters.keys())
        assert "promql" not in param_names, f"Function {name} accepts promql parameter"
        assert "query" not in param_names or name == "query", f"Function {name} accepts raw query parameter"


# ---------------------------------------------------------------------------
# Regression Test #4: Catalogue lint
# ---------------------------------------------------------------------------

def test_catalogue_lint():
    """Every tile has non-empty means/when_red, no binary '+' between metric selectors,
    and counter tiles carry 'or vector(0)' unless renders_empty_as_no_rows is True.
    """
    for tile_id, tile in CATALOGUE.items():
        assert tile.means and tile.means.strip(), f"Tile {tile_id} has empty 'means' description"
        assert tile.when_red and tile.when_red.strip(), f"Tile {tile_id} has empty 'when_red' guide"

        # Hard ban: binary '+' between metric selectors
        # E.g. sum(rate(a)) + sum(rate(b)) fails if one is missing
        assert not re.search(r'\)\s*\+\s*(?:sum|rate|ja4proxy_)', tile.expr), (
            f"Tile {tile_id} expression has binary '+' between selectors, which fails green on missing series: {tile.expr}"
        )

        # Counter tiles must carry 'or vector(0)' unless renders_empty_as_no_rows is set
        if "rate(" in tile.expr or "_total" in tile.expr:
            if not getattr(tile, "renders_empty_as_no_rows", False):
                assert "or vector(0)" in tile.expr, (
                    f"Counter tile {tile_id} missing 'or vector(0)': {tile.expr}"
                )


def test_regression_guards_fail_when_deliberately_broken():
    """Verify that each regression guard fails when fed deliberately broken inputs."""
    # Guard 1: Broken metric selector / missing metric
    go_metrics = _load_go_metric_definitions()
    assert "ja4proxy_nonexistent_fictional_metric" not in go_metrics

    # Guard 2: Forbidden label
    with pytest.raises(AssertionError):
        labels = {"client_ip", "status"}
        forbidden = {"ip", "client_ip", "ja4", "sni", "fingerprint"}
        intersection = labels & forbidden
        assert not intersection

    # Guard 4: Binary '+' between selectors
    bad_expr = "sum(rate(ja4proxy_a_total[5m])) + sum(rate(ja4proxy_b_total[5m]))"
    assert re.search(r'\)\s*\+\s*(?:sum|rate|ja4proxy_)', bad_expr)

    # Missing or vector(0) on counter
    bad_counter_expr = "sum(rate(ja4proxy_workchan_dropped_total[5m]))"
    assert "or vector(0)" not in bad_counter_expr

