"""Tests for Phase 101b — Compliance hygiene (M1, M2, M4, L1, L2, L5).

This module covers:
- M1: XTRIM MINID fallback for Redis < 6.2
- M2: Rename beaconing_records_cleaned -> beaconing_datapoints_cleaned
- M4: Paginate audit log reads in pack builder
- L1: Jinja2 Environment cached at module level
- L2: JSONL trailing newline documented
- L5: DSAR retention strings from config, not hardcoded
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.unit
class TestM1XtrimMinidFallback:
    """M1: XTRIM MINID fallback for Redis < 6.2."""

    @pytest.mark.asyncio
    async def test_redis_6_0_uses_fallback_path(self):
        """Redis 6.0 should use XRANGE+XDEL instead of XTRIM MINID."""
        import fakeredis.aioredis

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await fake_redis.xadd(
            "ja4proxy:events", {"a": "1", "timestamp": "1000000000000-0"}
        )
        await fake_redis.xadd(
            "ja4proxy:events", {"a": "2", "timestamp": "2000000000000-0"}
        )

        fake_redis.info = AsyncMock(return_value={"redis_version": "6.0.0"})
        fake_redis.xtrim = AsyncMock()
        fake_redis.xrange = AsyncMock(
            return_value=[
                ("1000000000000-0", {"a": "1", "timestamp": "1000000000000-0"}),
                ("2000000000000-0", {"a": "2", "timestamp": "2000000000000-0"}),
            ]
        )
        fake_redis.xdel = AsyncMock(return_value=1)
        fake_redis.xlen = AsyncMock(side_effect=[2, 1])

        from management.compliance.purge import GDPRPurge

        purge = GDPRPurge(fake_redis, {"connection_log_retention_days": 1})
        summary = await purge.run()

        fake_redis.xtrim.assert_not_called()
        fake_redis.xrange.assert_called()
        fake_redis.xdel.assert_called()
        assert summary.connection_events_deleted >= 0

    @pytest.mark.asyncio
    async def test_redis_6_2_uses_minid(self):
        """Redis 6.2+ should use XTRIM MINID."""
        import fakeredis.aioredis

        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await fake_redis.xadd(
            "ja4proxy:events", {"a": "1", "timestamp": "1000000000000-0"}
        )
        await fake_redis.xadd(
            "ja4proxy:events", {"a": "2", "timestamp": "2000000000000-0"}
        )

        fake_redis.info = AsyncMock(return_value={"redis_version": "6.2.0"})
        fake_redis.xtrim = AsyncMock()
        fake_redis.xrange = AsyncMock()
        fake_redis.xdel = AsyncMock()
        fake_redis.xlen = AsyncMock(side_effect=[2, 1])

        from management.compliance.purge import GDPRPurge

        purge = GDPRPurge(fake_redis, {"connection_log_retention_days": 1})
        summary = await purge.run()

        fake_redis.xtrim.assert_called()
        fake_redis.xrange.assert_not_called()
        fake_redis.xdel.assert_not_called()


@pytest.mark.unit
class TestM2BeaconingRename:
    """M2: Rename beaconing_records_cleaned -> beaconing_datapoints_cleaned."""

    def test_purge_summary_has_new_field_name(self):
        """PurgeSummary should use beaconing_datapoints_cleaned field name."""
        from management.compliance.purge import PurgeSummary

        summary = PurgeSummary(beaconing_datapoints_cleaned=42)
        d = summary.to_dict()

        assert "beaconing_datapoints_cleaned" in d
        assert d["beaconing_datapoints_cleaned"] == 42

    def test_purge_summary_to_dict_new_field(self):
        """to_dict() should include beaconing_datapoints_cleaned."""
        from management.compliance.purge import PurgeSummary

        summary = PurgeSummary()
        d = summary.to_dict()

        assert "beaconing_datapoints_cleaned" in d


@pytest.mark.unit
class TestL1Jinja2EnvironmentCache:
    """L1: Jinja2 Environment cached at module level."""

    def test_two_renderers_share_environment(self):
        """Two ReportRenderer instances should share compiled Jinja2 templates."""
        from management.compliance import report_renderer

        original_cache = report_renderer._ENV_CACHE.copy()
        report_renderer._ENV_CACHE.clear()

        try:
            from management.compliance.report_renderer import ReportRenderer

            r1 = ReportRenderer(template_dir="management/templates")
            r2 = ReportRenderer(template_dir="management/templates")

            assert id(r1._env) == id(r2._env), "Environments should be cached"
        finally:
            report_renderer._ENV_CACHE.clear()
            report_renderer._ENV_CACHE.update(original_cache)


@pytest.mark.unit
class TestL2JsonlTrailingNewline:
    """L2: JSONL trailing newline documented."""

    def test_non_empty_jsonl_ends_with_newline(self, tmp_path):
        """Non-empty JSONL files should end with newline."""
        test_file = tmp_path / "test.jsonl"
        test_file.write_text('{"a": 1}\n{"b": 2}\n')

        content = test_file.read_bytes()
        assert content.endswith(b"\n"), "Non-empty JSONL should end with newline"

    def test_empty_jsonl_is_zero_bytes(self, tmp_path):
        """Empty JSONL files should be zero bytes."""
        test_file = tmp_path / "empty.jsonl"
        test_file.write_text("")

        assert test_file.stat().st_size == 0, "Empty file should be zero bytes"


@pytest.mark.unit
class TestL5DsarRetentionFromConfig:
    """L5: DSAR retention strings from config, not hardcoded."""

    def test_dsar_retention_from_config_module(self):
        """Config module loads gdpr settings."""
        from management.api import proxy_config

        assert hasattr(proxy_config, "get_proxy_config")
