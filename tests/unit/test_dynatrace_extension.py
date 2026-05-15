"""Phase 86e — Tests for Dynatrace EF2 extension."""

from pathlib import Path
from typing import Any

import pytest
import yaml

EXTENSION_YAML = (
    Path(__file__).parent.parent.parent
    / "deploy"
    / "dynatrace"
    / "ja4proxy-extension"
    / "extension.yaml"
)


@pytest.fixture
def extension() -> dict[str, Any]:
    with open(EXTENSION_YAML) as f:
        return yaml.safe_load(f)


class TestExtensionYAML:
    """Validate the Dynatrace EF2 extension.yaml structure."""

    def test_file_exists(self):
        assert EXTENSION_YAML.exists(), f"Extension YAML not found at {EXTENSION_YAML}"

    def test_valid_yaml(self, extension: dict):
        assert isinstance(extension, dict)

    def test_required_fields(self, extension: dict):
        """EF2 requires: name, version, minDynatraceVersion, author, metrics."""
        for field in ("name", "version", "minDynatraceVersion", "author", "metrics"):
            assert field in extension, f"Missing required field: {field}"

    def test_name_format(self, extension: dict):
        """Custom extensions must be prefixed with 'custom:'."""
        assert extension["name"].startswith(
            "custom:"
        ), f"Extension name must start with 'custom:', got: {extension['name']}"

    def test_version_is_string(self, extension: dict):
        assert isinstance(extension["version"], str)

    def test_author_has_name(self, extension: dict):
        assert "name" in extension["author"]

    def test_metrics_defined(self, extension: dict):
        assert len(extension["metrics"]) >= 1, "At least one metric must be defined"


class TestMetricDefinitions:
    """Validate individual metric definitions."""

    REQUIRED_METRIC_KEYS = {"key", "value", "unit", "displayName"}

    @pytest.fixture
    def metrics(self, extension: dict):
        return extension.get("metrics", [])

    def test_all_metrics_have_required_keys(self, metrics: list):
        for i, metric in enumerate(metrics):
            missing = self.REQUIRED_METRIC_KEYS - set(metric.keys())
            assert (
                not missing
            ), f"Metric {i} ({metric.get('key', 'unknown')}) missing keys: {missing}"

    def test_metric_keys_are_unique(self, metrics: list):
        keys = [m["key"] for m in metrics]
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"Duplicate metric keys: {duplicates}"

    def test_metric_keys_use_ext_prefix(self, metrics: list):
        for m in metrics:
            assert m["key"].startswith(
                "ext:ja4proxy."
            ), f"Metric key must start with 'ext:ja4proxy.', got: {m['key']}"

    def test_expected_metrics_present(self, metrics: list):
        expected = {
            "ext:ja4proxy.node.healthy",
            "ext:ja4proxy.node.redis_latency_ms",
            "ext:ja4proxy.connections.active",
            "ext:ja4proxy.block_rate",
            "ext:ja4proxy.dial_setting",
            "ext:ja4proxy.cert_days_remaining",
            "ext:ja4proxy.active_bans",
        }
        actual = {m["key"] for m in metrics}
        missing = expected - actual
        assert not missing, f"Expected metrics missing: {missing}"

    def test_value_types_are_valid(self, metrics: list):
        valid_types = {"int64", "double", "int"}
        for m in metrics:
            vtype = m.get("value", {}).get("type", "")
            assert vtype in valid_types, (
                f"Metric {m['key']} has invalid value type: {vtype} "
                f"(valid: {valid_types})"
            )


class TestTopologyDefinition:
    """Validate topology entity type definition."""

    def test_topology_exists(self, extension: dict):
        assert "topology" in extension, "Extension must define topology"
        assert "types" in extension["topology"], "Topology must have types"

    def test_topology_has_ja4proxy_node(self, extension: dict):
        types = extension["topology"]["types"]
        names = {t["name"] for t in types}
        assert "ja4proxy:node" in names, "Missing ja4proxy:node topology type"

    def test_topology_has_display_name(self, extension: dict):
        for t in extension["topology"]["types"]:
            assert (
                "displayName" in t
            ), f"Topology type {t.get('name')} missing displayName"

    def test_topology_has_rules(self, extension: dict):
        for t in extension["topology"]["types"]:
            assert "rules" in t, f"Topology type {t.get('name')} missing rules"


class TestDynatracePlugin:
    """Validate the runtime plugin.py skeleton."""

    PLUGIN_PATH = (
        Path(__file__).parent.parent.parent
        / "deploy"
        / "dynatrace"
        / "ja4proxy-extension"
        / "plugin.py"
    )

    def test_plugin_file_exists(self):
        assert self.PLUGIN_PATH.exists(), f"plugin.py not found at {self.PLUGIN_PATH}"

    def test_plugin_has_build_entry_point(self):
        """EF2 requires a build() factory function."""
        source = self.PLUGIN_PATH.read_text()
        assert "def build(" in source, "plugin.py must define build() factory function"

    def test_plugin_has_query_method(self):
        """The plugin class must implement query() for metric collection."""
        source = self.PLUGIN_PATH.read_text()
        assert "def query(" in source, "Plugin must implement query() method"

    def test_plugin_handles_missing_dt_runtime(self):
        """Plugin must gracefully skip when dtpython is not available (local dev)."""
        source = self.PLUGIN_PATH.read_text()
        assert (
            "HAS_DT" in source or "ImportError" in source
        ), "Plugin should handle missing dtpython imports gracefully"

    def test_plugin_references_correct_endpoint(self):
        """Phase 86i: plugin now scrapes /metrics instead of
        /api/v1/health/deep — richer label set preserved."""
        source = self.PLUGIN_PATH.read_text()
        assert "/metrics" in source, "Plugin must scrape /metrics (Phase 86i)"

    def test_plugin_uses_auth_header(self):
        """Plugin should support Bearer token authentication."""
        source = self.PLUGIN_PATH.read_text()
        assert (
            "Authorization" in source
        ), "Plugin should support Authorization header for API auth"


# ── Phase 86i: Prometheus text-format scraping ──────────────────────────────


class TestPhase86iPrometheusScraper:
    """Phase 86i Gap 1 — Dynatrace plugin switches to /metrics scraping."""

    PLUGIN_PATH = (
        Path(__file__).parent.parent.parent
        / "deploy"
        / "dynatrace"
        / "ja4proxy-extension"
        / "plugin.py"
    )

    CANONICAL_EXPOSITION = """\
# HELP ja4proxy_connections_total Total connections.
# TYPE ja4proxy_connections_total counter
ja4proxy_connections_total{bypass="h2"} 12345
ja4proxy_connections_total{bypass="none"} 678
# HELP ja4proxy_dial_setting Current dial.
# TYPE ja4proxy_dial_setting gauge
ja4proxy_dial_setting 100
# HELP ja4proxy_pipeline_duration_seconds Pipeline duration.
# TYPE ja4proxy_pipeline_duration_seconds histogram
ja4proxy_pipeline_duration_seconds_bucket{le="0.001"} 42
ja4proxy_pipeline_duration_seconds_bucket{le="0.01"} 84
ja4proxy_pipeline_duration_seconds_bucket{le="+Inf"} 100
ja4proxy_pipeline_duration_seconds_sum 1.23
ja4proxy_pipeline_duration_seconds_count 100
"""

    def _load_plugin_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ja4proxy_dt_plugin", self.PLUGIN_PATH
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_plugin_parses_prometheus_text_format(self):
        """Plugin must expose a parser that extracts samples from the
        canonical Prometheus exposition format (counter, gauge, histogram)."""
        mod = self._load_plugin_module()
        assert hasattr(
            mod, "parse_prometheus_text"
        ), "Phase 86i: plugin.py must export parse_prometheus_text()"
        samples = mod.parse_prometheus_text(self.CANONICAL_EXPOSITION)
        # Expect a dict-like or list of (name, labels, value) triples.
        flat = (
            list(samples)
            if not isinstance(samples, dict)
            else [(k, {}, v) for k, v in samples.items()]
        )
        names = {s[0] for s in flat}
        assert "ja4proxy_connections_total" in names
        assert "ja4proxy_dial_setting" in names
        # Histogram buckets should be present in some form.
        assert any("pipeline_duration_seconds" in n for n in names)

    def test_plugin_handles_scrape_failure_gracefully(self, caplog):
        """On HTTP scrape failure, plugin must log one error and emit no
        metrics — must not crash."""
        import logging
        from unittest.mock import patch

        mod = self._load_plugin_module()
        assert hasattr(
            mod, "scrape_metrics"
        ), "Phase 86i: plugin.py must export scrape_metrics(url)"
        with patch("urllib.request.urlopen", side_effect=OSError("boom")):
            with caplog.at_level(logging.ERROR):
                result = mod.scrape_metrics("http://127.0.0.1:9/metrics")
        assert result in (
            None,
            {},
            [],
            (),
        ), "failed scrape must return empty/None, not raise"

    def test_extension_yaml_topology_preserved(self):
        """Phase 86i: topology entity type must still be defined after
        the metric-set rewrite."""
        with open(EXTENSION_YAML) as f:
            ext = yaml.safe_load(f)
        assert "topology" in ext
        types = ext["topology"].get("types", [])
        assert any(
            t.get("name") == "ja4proxy:node" for t in types
        ), "Phase 86i: ja4proxy:node topology type must remain"


# ── PHASE_101 H15: parser hardening ──────────────────────────────────────────


class TestPhase101H15ParserHardening:
    """PHASE_101 H15 — Prometheus parser must drop NaN/Inf samples and
    correctly decode backslash-escaped label values.

    Before H15, ``float("NaN")`` silently flowed into the Dynatrace
    series and ``_parse_labels`` mis-split on escaped quotes, so any
    request-path label containing ``\\"`` truncated the rest of the
    labelset.
    """

    PLUGIN_PATH = (
        Path(__file__).parent.parent.parent
        / "deploy"
        / "dynatrace"
        / "ja4proxy-extension"
        / "plugin.py"
    )

    def _load(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ja4proxy_dt_plugin_h15", self.PLUGIN_PATH
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_nan_and_inf_samples_are_dropped(self):
        mod = self._load()
        text = (
            "ja4proxy_good 1.0\n"
            "ja4proxy_nan NaN\n"
            "ja4proxy_pos_inf +Inf\n"
            "ja4proxy_neg_inf -Inf\n"
            "ja4proxy_also_good 42\n"
        )
        samples = mod.parse_prometheus_text(text)
        names = {s[0] for s in samples}
        assert "ja4proxy_good" in names
        assert "ja4proxy_also_good" in names
        assert (
            "ja4proxy_nan" not in names
        ), "NaN samples must be dropped — they corrupt Dynatrace timeseries"
        assert "ja4proxy_pos_inf" not in names
        assert "ja4proxy_neg_inf" not in names

    def test_escaped_quote_in_label_value_preserves_full_labelset(self):
        """A label like ``path="/a\\"b"`` must not terminate the label region
        early. Tail labels like ``method`` must still be parsed."""
        mod = self._load()
        # Raw exposition bytes: path="/a\"b,c",method="GET"
        line = 'ja4proxy_requests_total{path="/a\\"b,c",method="GET"} 7'
        samples = mod.parse_prometheus_text(line)
        assert len(samples) == 1, f"expected 1 sample, got {samples!r}"
        name, labels, value = samples[0]
        assert name == "ja4proxy_requests_total"
        assert value == 7.0
        assert (
            labels.get("method") == "GET"
        ), f"tail label dropped — parser mis-handled escaped quote: {labels!r}"
        # The decoded path should contain the literal quote + comma.
        assert (
            labels.get("path") == '/a"b,c'
        ), f"escape not decoded correctly: {labels.get('path')!r}"

    def test_escaped_backslash_and_newline_decoded(self):
        """``\\\\`` → ``\\`` and ``\\n`` → newline, per the Prometheus spec."""
        mod = self._load()
        line = 'ja4proxy_log{path="a\\\\b",msg="line1\\nline2"} 1'
        samples = mod.parse_prometheus_text(line)
        assert len(samples) == 1
        _, labels, _ = samples[0]
        assert labels.get("path") == "a\\b"
        assert labels.get("msg") == "line1\nline2"


# ── PHASE_101 M25: topology entity emitted on scrape failure ────────────────


class _StubTopology:
    """Minimal fake of Dynatrace EF2 ``dt.TopologyBuilder()`` chain."""

    def __init__(self, registry):
        self._registry = registry
        self._kind = None
        self._dims: dict = {}

    def series(self, kind: str):
        self._kind = kind
        return self

    def dimensions(self, **kwargs):
        self._dims = kwargs
        return self

    def point(self, value, ts):
        self._dims["_value"] = value
        self._dims["_ts"] = ts
        return self

    def build(self):
        self._registry.append({"kind": self._kind, "dims": dict(self._dims)})
        return {"kind": self._kind, "dims": dict(self._dims)}


class _StubDT:
    """Fake module mirroring the ``dt`` EF2 runtime surface used by the plugin."""

    def __init__(self):
        self.records: list = []

    def TopologyBuilder(self):  # noqa: N802 — matches Dynatrace API casing
        return _StubTopology(self.records)

    def series(self, key):
        t = _StubTopology(self.records)
        t.series(key)
        return t


class _StubDTLog:
    def __init__(self):
        self.messages: list[str] = []

    def info(self, msg):
        self.messages.append(msg)


class TestPhase101M25TopologyOnFailure:
    """PHASE_101 M25 — ``query()`` must emit the ``ja4proxy:node`` topology
    entity on every tick, including when the scrape returns zero samples.

    Without this, Dynatrace shows the node as missing (no entity record)
    rather than as "scrape failing" (entity present, metrics stale).
    """

    PLUGIN_PATH = (
        Path(__file__).parent.parent.parent
        / "deploy"
        / "dynatrace"
        / "ja4proxy-extension"
        / "plugin.py"
    )

    def _load(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ja4proxy_dt_plugin_m25", self.PLUGIN_PATH
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_query_emits_topology_even_when_scrape_returns_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mod = self._load()
        stub_dt = _StubDT()
        stub_log = _StubDTLog()
        monkeypatch.setattr(mod, "HAS_DT", True, raising=False)
        monkeypatch.setattr(mod, "dt", stub_dt, raising=False)
        monkeypatch.setattr(mod, "dtlog", stub_log, raising=False)
        monkeypatch.setattr(mod, "scrape_metrics", lambda *a, **kw: [], raising=False)

        plugin = mod.JA4proxyPlugin({"metrics_url": "http://example.invalid/metrics"})
        series = plugin.query()

        assert series, "M25: query() must return ≥1 entity even on scrape failure"
        kinds = [r["kind"] for r in stub_dt.records]
        assert (
            "ja4proxy:node" in kinds
        ), f"M25: topology entity ja4proxy:node missing from {kinds!r}"

    def test_query_emits_topology_when_scrape_returns_samples(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: the happy path still emits the topology + any mapped
        metric series."""
        mod = self._load()
        stub_dt = _StubDT()
        stub_log = _StubDTLog()
        monkeypatch.setattr(mod, "HAS_DT", True, raising=False)
        monkeypatch.setattr(mod, "dt", stub_dt, raising=False)
        monkeypatch.setattr(mod, "dtlog", stub_log, raising=False)
        monkeypatch.setattr(
            mod,
            "scrape_metrics",
            lambda *a, **kw: [("ja4proxy_dial_setting", {}, 100.0)],
            raising=False,
        )

        plugin = mod.JA4proxyPlugin({"metrics_url": "http://example.invalid/metrics"})
        series = plugin.query()

        assert (
            len(series) >= 2
        ), f"expected topology + dial_setting series, got {series!r}"
        kinds = [r["kind"] for r in stub_dt.records]
        assert "ja4proxy:node" in kinds
        assert "ext:ja4proxy.dial_setting" in kinds
