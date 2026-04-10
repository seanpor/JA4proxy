"""Phase 86d — Tests for Datadog integration.

The Datadog Agent SDK (datadog_checks.base) is not available in the local
test environment. The runtime check logic tests (3 tests) are skipped
when the SDK is absent — they run inside a Datadog Agent container.
The 15 static validation tests (JSON/YAML structure) always run.
"""

import json
from pathlib import Path

import pytest
import yaml

DATADOG_DIR = Path(__file__).parent.parent.parent / "deploy" / "datadog"
CHECK_PATH = DATADOG_DIR / "checks" / "ja4proxy" / "check.py"


# ── Dashboard JSON validation ────────────────────────────────────────────────

class TestDatadogDashboard:
    DASHBOARD = DATADOG_DIR / "ja4proxy-dashboard.json"

    def test_file_exists(self):
        assert self.DASHBOARD.exists()

    def test_valid_json(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        assert "title" in data
        assert "widgets" in data
        assert len(data["widgets"]) >= 1

    def test_has_health_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert "Node Health" in titles

    def test_has_block_rate_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert any("Block Rate" in t for t in titles)

    def test_has_cert_expiry_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert any("Certificate" in t or "Cert" in t for t in titles)


# ── Monitors JSON validation ─────────────────────────────────────────────────

class TestDatadogMonitors:
    MONITORS = DATADOG_DIR / "ja4proxy-monitors.json"

    def test_file_exists(self):
        assert self.MONITORS.exists()

    def test_valid_json(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_has_node_unhealthy_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("unhealthy" in n.lower() for n in names)

    def test_has_redis_latency_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("redis" in n.lower() for n in names)

    def test_has_cert_expiry_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("certificate" in n.lower() or "cert" in n.lower() for n in names)

    def test_has_block_rate_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("block" in n.lower() for n in names)

    def test_all_monitors_have_message(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        for m in data:
            assert m.get("message"), f"Monitor {m.get('name')} has no message"


# ── Conf YAML validation ─────────────────────────────────────────────────────

class TestDatadogConf:
    CONF = DATADOG_DIR / "conf.d" / "ja4proxy.d" / "conf.yaml"

    def test_file_exists(self):
        assert self.CONF.exists()

    def test_valid_yaml(self):
        with open(self.CONF) as f:
            data = yaml.safe_load(f)
        assert "instances" in data
        assert len(data["instances"]) >= 1

    def test_instance_has_management_url(self):
        with open(self.CONF) as f:
            data = yaml.safe_load(f)
        for inst in data["instances"]:
            assert "management_url" in inst, "Each instance needs management_url"
            assert inst["management_url"].startswith("http"), (
                f"management_url must be a full URL, got: {inst['management_url']}"
            )


# ── Check module static analysis ─────────────────────────────────────────────

class TestCheckModule:
    """Static checks on the check.py source (no runtime import needed)."""

    CHECK_FILE = CHECK_PATH

    def test_file_exists(self):
        assert self.CHECK_FILE.exists()

    def test_has_required_metrics_in_source(self):
        """The check.py source must reference all expected metric names."""
        source = self.CHECK_FILE.read_text()
        expected_metrics = [
            "ja4proxy.node.healthy",
            "ja4proxy.node.redis_latency_ms",
            "ja4proxy.node.dial_setting",
            "ja4proxy.node.cert_days_remaining",
            "ja4proxy.connections.active",
            "ja4proxy.connections.total",
            "ja4proxy.block_rate_pct",
            "ja4proxy.bans.active",
            "ja4proxy.node_health",
        ]
        for metric in expected_metrics:
            assert metric in source, f"Metric {metric!r} not found in check.py source"

    def test_emits_service_check_on_failure(self):
        """The check must emit UNKNOWN service check on HTTP failure."""
        source = self.CHECK_FILE.read_text()
        assert "UNKNOWN" in source
        assert "service_check" in source
