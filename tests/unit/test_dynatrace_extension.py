"""Phase 86e — Tests for Dynatrace EF2 extension."""

from pathlib import Path
from typing import Any

import pytest
import yaml

EXTENSION_YAML = Path(__file__).parent.parent.parent / "deploy" / "dynatrace" / "ja4proxy-extension" / "extension.yaml"


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
        assert extension["name"].startswith("custom:"), (
            f"Extension name must start with 'custom:', got: {extension['name']}"
        )

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
            assert not missing, (
                f"Metric {i} ({metric.get('key', 'unknown')}) missing keys: {missing}"
            )

    def test_metric_keys_are_unique(self, metrics: list):
        keys = [m["key"] for m in metrics]
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"Duplicate metric keys: {duplicates}"

    def test_metric_keys_use_ext_prefix(self, metrics: list):
        for m in metrics:
            assert m["key"].startswith("ext:ja4proxy."), (
                f"Metric key must start with 'ext:ja4proxy.', got: {m['key']}"
            )

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
            assert "displayName" in t, f"Topology type {t.get('name')} missing displayName"

    def test_topology_has_rules(self, extension: dict):
        for t in extension["topology"]["types"]:
            assert "rules" in t, f"Topology type {t.get('name')} missing rules"


class TestDynatracePlugin:
    """Validate the runtime plugin.py skeleton."""

    PLUGIN_PATH = Path(__file__).parent.parent.parent / "deploy" / "dynatrace" / "ja4proxy-extension" / "plugin.py"

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
        assert "HAS_DT" in source or "ImportError" in source, \
            "Plugin should handle missing dtpython imports gracefully"

    def test_plugin_references_correct_endpoint(self):
        """Plugin must poll /api/v1/health/deep (the 86a endpoint)."""
        source = self.PLUGIN_PATH.read_text()
        assert "/api/v1/health/deep" in source, \
            "Plugin must poll /api/v1/health/deep"

    def test_plugin_uses_auth_header(self):
        """Plugin should support Bearer token authentication."""
        source = self.PLUGIN_PATH.read_text()
        assert "Authorization" in source, \
            "Plugin should support Authorization header for API auth"
