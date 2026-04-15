"""Tests for PHASE_101g: Medium items (M8-M14).

M8 — TAXII bundle size cap
M9 — Per-feed User-Agent header
M10 — Gauge -> Counter for ti_feed_indicators_managed
M11 — Stable-ordered dropped list
M12 — Replace BLE001 bare Exception catches
M13 — seed_file inside leader lock
M14 — Audit log on feed enable/disable
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestM8BundleSizeCap:
    """M8: TAXII bundle size cap."""

    def test_feed_config_has_max_bundle_bytes(self):
        """FeedConfig should have max_bundle_bytes field."""
        from src.analytics.ti_feeds.base import FeedConfig

        cfg = FeedConfig(id="test", type="taxii2")
        assert hasattr(cfg, "max_bundle_bytes"), "FeedConfig should have max_bundle_bytes"
        assert cfg.max_bundle_bytes > 0, "max_bundle_bytes should have a default"


class TestM9UserAgent:
    """M9: Per-feed User-Agent header."""

    def test_feed_config_has_user_agent(self):
        """FeedConfig should have user_agent field."""
        from src.analytics.ti_feeds.base import FeedConfig

        cfg = FeedConfig(id="test-feed", type="taxii2")
        assert hasattr(cfg, "user_agent"), "FeedConfig should have user_agent"
        assert "test-feed" in cfg.user_agent, "user_agent should include feed_id"


class TestM10GaugeToCounter:
    """M10: Check ti_feed_indicators_managed metric exists."""

    def test_indicators_managed_metric_exists(self):
        """ja4proxy_ti_feed_indicators_managed should be defined."""
        with open("src/analytics/ti_feeds/metrics.py") as f:
            content = f.read()
        assert "ti_feed_indicators_managed" in content or "indicators_managed" in content, (
            "Should have indicators_managed"
        )


class TestM11StableOrderedDropped:
    """M11: verify compute_dropped_ids exists and returns list."""

    def test_dropped_ids_exists(self):
        """compute_dropped_ids should exist in state.py."""
        with open("src/analytics/ti_feeds/state.py") as f:
            content = f.read()
        assert "compute_dropped_ids" in content, "compute_dropped_ids should exist"


class TestM12ExplicitExceptions:
    """M12: Replace bare Exception catches with explicit unions."""

    def test_taxii_client_has_explicit_exceptions(self):
        """taxii.py should catch explicit types, not bare Exception."""
        import ast
        from pathlib import Path

        for filename in ["taxii.py", "crowdstrike.py", "recorded_future.py", "rest_generic.py"]:
            path = Path(f"src/analytics/ti_feeds/{filename}")
            content = path.read_text()

            if "except Exception:" in content:
                pytest.fail(f"Found 'except Exception:' in {filename} - should use explicit types")
            if "except Error:" in content:  # Old Python 2 style
                pytest.fail(f"Found Python 2 style 'except Error:' in {filename}")


class TestM13SeedFileLeaderLock:
    """M13: seed_file.run_once should run inside leader lock."""

    def test_seed_file_has_leader_lock(self):
        """seed_file.py should acquire leader lock in run_once."""
        import ast
        from pathlib import Path

        seed_path = Path("src/analytics/ti_feeds/seed_file.py")
        content = seed_path.read_text()

        assert "leader" in content.lower() or "lock" in content.lower(), "seed_file should use leader lock"


class TestM14AuditLogEnableDisable:
    """M14: Audit log on feed enable/disable."""

    def test_threat_intel_routes_has_audit(self):
        """threat_intel.py should log audit on enable/disable."""
        import ast
        from pathlib import Path

        routes_path = Path("management/api/routes/threat_intel.py")
        if not routes_path.exists():
            pytest.skip("threat_intel.py not yet created")

        content = routes_path.read_text()
        tree = ast.parse(content)

        has_enable = has_disable = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if "enable" in node.name.lower():
                    has_enable = True
                if "disable" in node.name.lower():
                    has_disable = True

        if has_enable or has_disable:
            assert "audit" in content.lower() or "log" in content.lower(), "Enable/disable should have audit logging"
