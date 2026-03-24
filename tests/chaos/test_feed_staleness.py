"""Chaos tests: blocklist feed failure scenarios (Phase 8).

Verifies that download failures, timeouts, and malformed data never crash
the proxy and that the last known trie is always retained.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis

from src.security.blocklists import (
    _BLOCKLIST_DOWNLOAD_ERRORS,
    BlocklistManager,
    FeedConfig,
    FeedManager,
    parse_feed,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def _feed_cfg(**kwargs) -> FeedConfig:
    defaults = dict(
        name="spamhaus_drop",
        url="https://example.com/drop.txt",
        format="spamhaus",
        is_bypass=True,
        action="block",
        score=80,
        refresh_interval_seconds=43200,
        enabled=True,
    )
    defaults.update(kwargs)
    return FeedConfig(**defaults)


def _make_feed_manager(feed_cfg: FeedConfig, redis=None) -> tuple[FeedManager, BlocklistManager]:
    config = {
        "blocklists": {
            "feeds": [
                {
                    "name": feed_cfg.name,
                    "url": feed_cfg.url,
                    "format": feed_cfg.format,
                    "is_bypass": feed_cfg.is_bypass,
                    "action": feed_cfg.action,
                    "score": feed_cfg.score,
                    "refresh_interval_seconds": feed_cfg.refresh_interval_seconds,
                    "enabled": True,
                }
            ]
        }
    }
    mgr = BlocklistManager()
    fm = FeedManager(config, mgr, redis_client=redis)
    return fm, mgr


# ---------------------------------------------------------------------------
# HTTP 503 — last known trie retained
# ---------------------------------------------------------------------------

class TestHTTP503:
    """HTTP 503 from feed server: last known trie retained, error counter up."""

    def test_503_retains_existing_trie(self):
        """After a 503, previously loaded CIDRs are still in the trie."""
        import aiohttp

        feed_cfg = _feed_cfg()
        fm, mgr = _make_feed_manager(feed_cfg)

        # Pre-load some CIDRs
        mgr.load_cidrs(["1.10.16.0/20"], feed_cfg.name, feed_cfg)
        assert mgr.is_blocked("1.10.16.1")[0] is True

        before = _BLOCKLIST_DOWNLOAD_ERRORS.labels(feed="spamhaus_drop")._value.get()

        # Simulate 503
        async def run():
            mock_resp = MagicMock()
            mock_resp.status = 503
            mock_resp.history = []
            mock_resp.request_info = MagicMock()
            exc = aiohttp.ClientResponseError(
                mock_resp.request_info, mock_resp.history, status=503
            )
            with patch("src.security.blocklists.aiohttp") as mock_aiohttp:
                mock_session = AsyncMock()
                mock_aiohttp.ClientSession.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_aiohttp.ClientSession.return_value.__aexit__ = AsyncMock()
                mock_aiohttp.ClientTimeout = MagicMock()
                mock_session.get.return_value.__aenter__ = AsyncMock(
                    side_effect=exc
                )
                await fm._download_and_store(feed_cfg)

        _run(run())

        # Trie still has old data
        assert mgr.is_blocked("1.10.16.1")[0] is True
        # Error counter incremented
        assert _BLOCKLIST_DOWNLOAD_ERRORS.labels("spamhaus_drop")._value.get() == before + 1

    def test_503_logs_error_json(self, caplog):
        """HTTP 503 emits structured ERROR log."""
        import aiohttp

        feed_cfg = _feed_cfg()
        fm, mgr = _make_feed_manager(feed_cfg)

        async def run():
            mock_resp = MagicMock()
            mock_resp.status = 503
            mock_resp.history = []
            mock_resp.request_info = MagicMock()
            exc = aiohttp.ClientResponseError(
                mock_resp.request_info, mock_resp.history, status=503
            )
            with patch("src.security.blocklists.aiohttp") as mock_aiohttp:
                mock_session = AsyncMock()
                mock_aiohttp.ClientSession.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_aiohttp.ClientSession.return_value.__aexit__ = AsyncMock()
                mock_aiohttp.ClientTimeout = MagicMock()
                mock_session.get.return_value.__aenter__ = AsyncMock(side_effect=exc)

                with caplog.at_level(logging.ERROR, logger="src.security.blocklists"):
                    await fm._download_and_store(feed_cfg)

        _run(run())

        json_logs = [
            json.loads(r.message) for r in caplog.records
            if r.message.startswith("{")
        ]
        assert any(
            log.get("event") == "feed_download_failed" and
            log.get("subsystem") == "blocklist"
            for log in json_logs
        )


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

class TestDownloadTimeout:
    """Download timeout: last known trie retained, no hang."""

    def test_timeout_retains_trie(self):
        import aiohttp

        feed_cfg = _feed_cfg()
        fm, mgr = _make_feed_manager(feed_cfg)
        mgr.load_cidrs(["2.57.96.0/22"], feed_cfg.name, feed_cfg)

        before = _BLOCKLIST_DOWNLOAD_ERRORS.labels("spamhaus_drop")._value.get()

        async def run():
            with patch("src.security.blocklists.aiohttp") as mock_aiohttp:
                mock_session = AsyncMock()
                mock_aiohttp.ClientSession.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_aiohttp.ClientSession.return_value.__aexit__ = AsyncMock()
                mock_aiohttp.ClientTimeout = MagicMock()
                mock_session.get.return_value.__aenter__ = AsyncMock(
                    side_effect=asyncio.TimeoutError("download timed out")
                )
                await fm._download_and_store(feed_cfg)

        _run(run())

        assert mgr.is_blocked("2.57.97.1")[0] is True
        assert _BLOCKLIST_DOWNLOAD_ERRORS.labels("spamhaus_drop")._value.get() == before + 1


# ---------------------------------------------------------------------------
# Malformed CIDR data
# ---------------------------------------------------------------------------

class TestMalformedFeedData:
    """Malformed lines are skipped; valid CIDRs are loaded; no crash."""

    def test_malformed_lines_skipped(self):
        malformed = """\
; comment
1.10.16.0/20 ; SBL123
NOT_A_CIDR
999.999.999.0/24
2.57.96.0/22 ; SBL456
"""
        cidrs = parse_feed(malformed, "spamhaus")
        assert "1.10.16.0/20" in cidrs
        assert "2.57.96.0/22" in cidrs
        assert "NOT_A_CIDR" not in cidrs

    def test_all_malformed_loads_empty(self):
        bad = "NOT_A_CIDR\n999.999.999.0/24\n"
        cidrs = parse_feed(bad, "spamhaus")
        assert cidrs == []

    def test_malformed_download_response_no_crash(self):
        """If server returns garbage, parse safely and load what's valid."""
        import aiohttp

        feed_cfg = _feed_cfg()
        fm, mgr = _make_feed_manager(feed_cfg)

        garbage_text = "THIS IS NOT A BLOCKLIST\n\nRANDOM GARBAGE\n"

        async def run():
            with patch("src.security.blocklists.aiohttp") as mock_aiohttp:
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.headers = {}
                mock_resp.text = AsyncMock(return_value=garbage_text)
                mock_session = AsyncMock()
                mock_session.get.return_value.__aenter__ = AsyncMock(
                    return_value=mock_resp
                )
                mock_session.get.return_value.__aexit__ = AsyncMock()
                mock_aiohttp.ClientSession.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_aiohttp.ClientSession.return_value.__aexit__ = AsyncMock()
                mock_aiohttp.ClientTimeout = MagicMock()
                fm._redis = None  # disable Redis store
                await fm._download_and_store(feed_cfg)

        _run(run())  # Must not raise
        # Trie is empty (garbage parsed to nothing) but no crash
        assert mgr.is_blocked("1.2.3.4")[0] is False


# ---------------------------------------------------------------------------
# Redis unavailable at startup
# ---------------------------------------------------------------------------

class TestRedisUnavailableAtStartup:
    """When Redis is down, attempt direct download (act as leader)."""

    def test_no_redis_attempts_direct_download(self):
        """Without Redis, _try_become_leader returns True (act as leader)."""
        feed_cfg = _feed_cfg()
        fm, mgr = _make_feed_manager(feed_cfg, redis=None)

        async def run():
            result = await fm._try_become_leader(feed_cfg)
            return result

        assert _run(run()) is True

    def test_redis_exception_acts_as_leader(self):
        """Redis SET NX raising RedisError → act as leader (fail open)."""
        feed_cfg = _feed_cfg()
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock(side_effect=redis.RedisError("Redis down"))
        fm, mgr = _make_feed_manager(feed_cfg, redis=mock_redis)

        async def run():
            return await fm._try_become_leader(feed_cfg)

        assert _run(run()) is True

    def test_redis_down_load_from_redis_returns_none(self):
        """_load_from_redis returns None when Redis raises, no crash."""
        feed_cfg = _feed_cfg()
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=redis.RedisError("Redis down"))
        fm, mgr = _make_feed_manager(feed_cfg, redis=mock_redis)

        async def run():
            return await fm._load_from_redis("spamhaus_drop")

        result = _run(run())
        assert result is None
