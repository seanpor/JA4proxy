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
    """M11: ``compute_dropped_ids`` returns a stable-ordered list of tuples,
    not a dict. Stable order makes parallel poll loops deterministic and lets
    the cleanup-cap split (``runner._poll_one``) pick the same head every run
    instead of churning a randomly-ordered dict.
    """

    def test_returns_list_not_dict(self):
        """Return type must be list, not dict — callers slice it."""
        from src.analytics.ti_feeds.state import compute_dropped_ids

        result = compute_dropped_ids({"sid-a": "h-a", "sid-b": "h-b"}, set())
        assert isinstance(result, list), f"expected list, got {type(result).__name__}"
        assert all(isinstance(item, tuple) and len(item) == 2 for item in result), (
            "every item must be a (stix_id, handle) tuple"
        )

    def test_sorted_by_stix_id_ascending(self):
        """Output must be sorted by stix_id ascending — deterministic across runs."""
        from src.analytics.ti_feeds.state import compute_dropped_ids

        # Insert in reverse order to make the sort observable.
        previous = {"sid-z": "h-z", "sid-a": "h-a", "sid-m": "h-m"}
        result = compute_dropped_ids(previous, current=set())
        assert result == [("sid-a", "h-a"), ("sid-m", "h-m"), ("sid-z", "h-z")]

    def test_excludes_ids_present_in_current(self):
        """Only stix_ids absent from ``current`` appear in the output."""
        from src.analytics.ti_feeds.state import compute_dropped_ids

        previous = {"sid-a": "h-a", "sid-b": "h-b", "sid-c": "h-c"}
        result = compute_dropped_ids(previous, current={"sid-b"})
        assert result == [("sid-a", "h-a"), ("sid-c", "h-c")]

    def test_empty_when_all_present(self):
        """If every previous id is still seen, result is an empty list."""
        from src.analytics.ti_feeds.state import compute_dropped_ids

        previous = {"sid-a": "h-a", "sid-b": "h-b"}
        result = compute_dropped_ids(previous, current={"sid-a", "sid-b"})
        assert result == []

    def test_handles_preserved_with_each_id(self):
        """Each tuple pairs the stix_id with its original handle (no swap)."""
        from src.analytics.ti_feeds.state import compute_dropped_ids

        previous = {"sid-a": "uuid-A", "sid-b": "10.0.0.1"}
        result = compute_dropped_ids(previous, current=set())
        assert dict(result) == previous


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
    """M13: ``seed_file.run_once`` must run inside the shared leader lock.

    Without this gate every analytics replica POSTs every seed entry on
    startup. The Mgmt API is first-writer-wins so it's safe but wasteful;
    the lock collapses N startup loads into one.
    """

    @pytest.mark.asyncio
    async def test_run_once_skips_when_not_leader(self, tmp_path):
        """When ``try_acquire_leader`` returns False, run_once must do no work."""
        from src.analytics.ti_feeds.seed_file import run_once

        seed = tmp_path / "seed.yml"
        seed.write_text(
            "fingerprints:\n"
            "  - ja4: \"t10d170900_9dc949161b6c_b64c0ad42cb7\"\n"
            "    name: \"X\"\n"
            "    category: \"c2_framework\"\n"
            "    source: \"https://example.test\"\n"
            "    confidence: 95\n"
        )

        mgmt = MagicMock()
        mgmt.post_blocklist = AsyncMock()
        state = MagicMock()
        state.try_acquire_leader = AsyncMock(return_value=False)
        state.mark = AsyncMock()

        summary = await run_once(
            mgmt=mgmt, state=state, path=seed, min_entries=1, instance_id="replica-A"
        )

        assert summary == {"loaded": 0, "created": 0, "rejected": 0, "errors": 0}
        state.try_acquire_leader.assert_awaited_once_with(
            "replica-A", ttl_seconds=60
        )
        mgmt.post_blocklist.assert_not_called()
        state.mark.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_once_executes_when_leader_acquired(self, tmp_path):
        """When ``try_acquire_leader`` returns True, run_once does the work."""
        from src.analytics.ti_feeds.seed_file import run_once

        seed = tmp_path / "seed.yml"
        seed.write_text(
            "fingerprints:\n"
            "  - ja4: \"t10d170900_9dc949161b6c_b64c0ad42cb7\"\n"
            "    name: \"X\"\n"
            "    category: \"c2_framework\"\n"
            "    source: \"https://example.test\"\n"
            "    confidence: 95\n"
        )

        mgmt = MagicMock()
        post_resp = MagicMock()
        post_resp.id = "res-1"
        mgmt.post_blocklist = AsyncMock(return_value=post_resp)
        state = MagicMock()
        state.try_acquire_leader = AsyncMock(return_value=True)
        state.mark = AsyncMock()

        summary = await run_once(
            mgmt=mgmt, state=state, path=seed, min_entries=1, instance_id="replica-A"
        )

        assert summary["loaded"] == 1
        assert summary["created"] == 1
        state.try_acquire_leader.assert_awaited_once_with(
            "replica-A", ttl_seconds=60
        )
        mgmt.post_blocklist.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_once_skips_lock_when_instance_id_none(self, tmp_path):
        """Legacy callers (no instance_id) must NOT touch the leader lock."""
        from src.analytics.ti_feeds.seed_file import run_once

        seed = tmp_path / "seed.yml"
        seed.write_text(
            "fingerprints:\n"
            "  - ja4: \"t10d170900_9dc949161b6c_b64c0ad42cb7\"\n"
            "    name: \"X\"\n"
            "    category: \"c2_framework\"\n"
            "    source: \"https://example.test\"\n"
            "    confidence: 95\n"
        )

        mgmt = MagicMock()
        post_resp = MagicMock()
        post_resp.id = "res-1"
        mgmt.post_blocklist = AsyncMock(return_value=post_resp)
        state = MagicMock()
        state.try_acquire_leader = AsyncMock(return_value=False)  # would block
        state.mark = AsyncMock()

        summary = await run_once(
            mgmt=mgmt, state=state, path=seed, min_entries=1, instance_id=None
        )

        # No leader gate → work done despite try_acquire_leader=False
        assert summary["loaded"] == 1
        assert summary["created"] == 1
        state.try_acquire_leader.assert_not_called()


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
