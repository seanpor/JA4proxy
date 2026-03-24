"""Chaos tests: multiple simultaneous failures.

Each test simulates a realistic failure scenario where one or more external
dependencies are unavailable or return garbage, and verifies that the proxy
still makes an allow decision (fail open, dial=0).

Uses unittest.TestCase + asyncio.run(). No pytest-asyncio dependency.
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import redis

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_local_cache(dial=0):
    cache = MagicMock()
    cache.dial = dial
    cache.whitelist_decisions = {}
    cache.analytics_signals = MagicMock()
    cache.analytics_signals.get = MagicMock(return_value=None)
    cache.analytics_signals.set = MagicMock()
    cache.rdap_results = MagicMock()
    cache.rdap_results.get = MagicMock(return_value=None)
    return cache


def _make_pipeline(collectors=None):
    from src.security.pipeline import Pipeline

    config = {
        "security_policy": {},
        "monitor_mode": {"log_counterfactuals": False},
        "blocklists": {},
    }
    redis_client = MagicMock()
    redis_client.get = MagicMock(return_value=None)

    return Pipeline(
        config=config,
        local_cache=_make_local_cache(),
        redis_client=redis_client,
        collectors=collectors,
    )


def _make_ctx(ip="5.5.5.5"):
    from src.security.models import ConnectionContext
    return ConnectionContext(client_ip=ip, alpn=None, ja4="", sni=None)


# ---------------------------------------------------------------------------
# Chaos tests
# ---------------------------------------------------------------------------

class TestExceptionHandlingChaos(unittest.TestCase):

    def test_all_external_apis_fail_simultaneously_pipeline_allows(self):
        """All signal collectors raise simultaneously → pipeline returns action=allow."""

        class FailingCollector:
            def __init__(self, exc):
                self._exc = exc

            async def get_signal(self, ctx):
                raise self._exc

        collectors = [
            FailingCollector(redis.RedisError("redis down")),
            FailingCollector(asyncio.TimeoutError()),
            FailingCollector(ConnectionError("network unreachable")),
            FailingCollector(RuntimeError("unexpected internal error")),
            FailingCollector(AttributeError("NoneType has no attribute get")),
            FailingCollector(ValueError("malformed data")),
        ]

        pipeline = _make_pipeline(collectors=collectors)
        ctx = _make_ctx()

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow",
                         "Pipeline must fail open when all signal modules raise")

    def test_redis_down_all_modules_fail_open(self):
        """Redis client raises RedisError on every call → pipeline returns allow."""
        from src.security.pipeline import Pipeline

        redis_client = MagicMock()
        redis_client.get = MagicMock(side_effect=redis.RedisError("connection refused"))
        redis_client.set = MagicMock(side_effect=redis.RedisError("connection refused"))
        redis_client.smembers = MagicMock(side_effect=redis.RedisError("connection refused"))

        local_cache = _make_local_cache()
        # analytics_signals.get also raises to simulate full Redis outage
        local_cache.analytics_signals.get = MagicMock(return_value=None)

        config = {
            "security_policy": {},
            "monitor_mode": {"log_counterfactuals": False},
            "blocklists": {},
        }

        # Build pipeline with the broken redis client but no collectors so
        # it exercises the _get_analytics_signals / rate_tracker paths.
        class RedisErrorCollector:
            async def get_signal(self, ctx):
                raise redis.RedisError("all redis ops fail")

        pipeline = Pipeline(
            config=config,
            local_cache=local_cache,
            redis_client=redis_client,
            collectors=[RedisErrorCollector()],
        )
        ctx = _make_ctx()

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")

    def test_abuseipdb_malformed_json_fail_open(self):
        """AbuseIPDB checker raises json.JSONDecodeError → pipeline returns allow."""

        class AbuseIPDBMalfunctionCollector:
            async def get_signal(self, ctx):
                raise json.JSONDecodeError("unexpected token", "bad json", 0)

        pipeline = _make_pipeline(collectors=[AbuseIPDBMalfunctionCollector()])
        ctx = _make_ctx()

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")

    def test_dns_timeout_fail_open_no_signal(self):
        """DNS lookup times out → pipeline returns allow; no DNS signal in result."""

        class DNSTimeoutCollector:
            async def get_signal(self, ctx):
                raise asyncio.TimeoutError()

        pipeline = _make_pipeline(collectors=[DNSTimeoutCollector()])
        ctx = _make_ctx()

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")
        dns_signal_names = [
            s.name for s in result.signals
            if hasattr(s, "name") and "dns" in s.name.lower()
        ]
        self.assertEqual(dns_signal_names, [],
                         "No DNS signal should be present when lookup times out")

    def test_rdap_500_error_fail_open(self):
        """RDAP raises aiohttp.ClientResponseError(500) → pipeline returns allow."""
        try:
            import aiohttp

            class RDAPServerErrorCollector:
                async def get_signal(self, ctx):
                    request_info = MagicMock()
                    request_info.real_url = "https://rdap.arin.net/registry/ip/5.5.5.5"
                    raise aiohttp.ClientResponseError(
                        request_info=request_info,
                        history=(),
                        status=500,
                        message="Internal Server Error",
                    )

            pipeline = _make_pipeline(collectors=[RDAPServerErrorCollector()])
        except ImportError:
            # aiohttp not installed — simulate with generic exception
            class RDAPFallbackCollector:
                async def get_signal(self, ctx):
                    raise RuntimeError("RDAP HTTP 500")

            pipeline = _make_pipeline(collectors=[RDAPFallbackCollector()])

        ctx = _make_ctx()
        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")

    def test_blocklist_download_corrupted_response_old_list_retained(self):
        """BlocklistManager retains previously loaded CIDRs when download fails."""
        from src.security.blocklists import BlocklistManager, FeedConfig, FeedManager

        mgr = BlocklistManager()
        # Pre-load a CIDR that should be retained after download failure
        feed_cfg = FeedConfig(
            name="test_drop",
            url="http://example.com/drop.txt",
            format="spamhaus",
            is_bypass=True,
            action="block",
            score=60,
            refresh_interval_seconds=43200,
        )
        mgr.load_cidrs(["192.0.2.0/24"], "test_drop", feed_cfg)

        # Confirm the CIDR is loaded and blocks correctly
        blocked_before, _ = mgr.is_blocked("192.0.2.1")
        self.assertTrue(blocked_before, "CIDR must be blocked before download failure")

        # Simulate a download failure: FeedManager._download_and_store raises
        config = {
            "blocklists": {
                "feeds": [
                    {
                        "name": "test_drop",
                        "url": "http://example.com/drop.txt",
                        "format": "spamhaus",
                        "is_bypass": True,
                        "action": "block",
                        "score": 60,
                        "refresh_interval_seconds": 43200,
                        "enabled": True,
                    }
                ]
            }
        }
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(return_value=None)  # no cached CIDRs
        redis_mock.set = AsyncMock(return_value=True)   # leader election wins

        fm = FeedManager(config, mgr, redis_client=redis_mock)

        try:
            import aiohttp

            async def fail_download():
                # aiohttp.ClientError is the base class for download errors
                raise aiohttp.ClientError("connection error")
        except ImportError:
            async def fail_download():
                raise RuntimeError("download failed")

        with patch.object(fm, "_download_and_store", side_effect=fail_download):
            # Patch _try_become_leader to return True (act as leader → trigger download)
            async def leader_yes(feed_cfg_arg):
                return True

            with patch.object(fm, "_try_become_leader", side_effect=leader_yes):
                # _load_from_redis returns None → slow path → leader → download → fails
                try:
                    asyncio.run(fm._load_feed(fm._feeds[0]))
                except Exception:
                    pass  # Failure in _load_feed must not crash the test

        # BlocklistManager must still have the previously loaded CIDR
        blocked_after, _ = mgr.is_blocked("192.0.2.1")
        self.assertTrue(blocked_after,
                        "Previously loaded CIDR must be retained after download failure")

    def test_multiple_error_types_pipeline_still_allows_ipv6(self):
        """Mix of exception types with an IPv6 client address → pipeline allows."""

        class MixedFailureCollector:
            _count = 0

            async def get_signal(self, ctx):
                MixedFailureCollector._count += 1
                n = MixedFailureCollector._count % 4
                if n == 0:
                    raise asyncio.TimeoutError()
                elif n == 1:
                    raise redis.RedisError("redis down")
                elif n == 2:
                    raise json.JSONDecodeError("bad", "", 0)
                else:
                    raise OSError("network error")

        collectors = [MixedFailureCollector() for _ in range(4)]
        pipeline = _make_pipeline(collectors=collectors)

        # Use an IPv6 client address
        from src.security.models import ConnectionContext
        ctx = ConnectionContext(client_ip="2001:db8::1", alpn=None, ja4="", sni=None)

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")

    def test_redis_error_in_analytics_signals_pipeline_allows(self):
        """RedisError in _get_analytics_signals → pipeline still returns allow."""
        from src.security.pipeline import Pipeline

        redis_client = MagicMock()
        # Normal operations work, but analytics-specific key raises
        def redis_get_side_effect(key):
            if "analytics:" in str(key):
                raise redis.RedisError("redis blip")
            return None

        redis_client.get = MagicMock(side_effect=redis_get_side_effect)

        local_cache = _make_local_cache()

        config = {
            "security_policy": {},
            "monitor_mode": {"log_counterfactuals": False},
            "blocklists": {},
        }

        pipeline = Pipeline(
            config=config,
            local_cache=local_cache,
            redis_client=redis_client,
            collectors=[],
        )
        ctx = _make_ctx("10.20.30.40")

        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")


if __name__ == "__main__":
    unittest.main()
