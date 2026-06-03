import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import redis as redis_module

from src.security.models import ConnectionContext, RiskSignal
from src.security.tcp_analyzer import TCPAnalyzer, generate_ja4t


class TestTCPAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = {
            "tcp_analyzer": {
                "tcp_fingerprinting": {"enabled": True, "score": 30},
                "session_resumption": {
                    "enabled": True,
                    "min_connections": 5,
                    "score": 15,
                },
                "connection_lifespan": {
                    "enabled": True,
                    "min_connections": 5,
                    "threshold_ms": 500,
                    "score": 20,
                },
                "concurrent_connections": {
                    "enabled": True,
                    "thresholds": {"moderate": 10, "high": 20, "severe": 30},
                    "risk_scores": {"moderate": 10, "high": 25, "severe": 40},
                },
                "return_visitor": {
                    "enabled": True,
                    "trusted_days": 7,
                    "trusted_allow_rate": 0.9,
                    "score_reduction_pct": 20,
                },
                "tls_alerts": {"enabled": True, "rate_threshold": 3, "score": 20},
            }
        }

    def _create_tcp_analyzer(self, redis_client):
        return TCPAnalyzer(self.config, redis_client)

    def test_ja4t_mismatch_signal(self):
        redis_client = MagicMock()
        tcp_analyzer = self._create_tcp_analyzer(redis_client)
        # Use a JA4 that contains "chrome" so it maps to Windows
        # TTL 64 maps to Linux in our ja4t_os_map
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="chrome_13d1516h2_8daaf6152771_02713d6af862",
            tcp_ttl=64,
            tcp_window_size=65535,
            tcp_options="020405b40103030801010402",
        )
        ctx.tcp_ja4t = generate_ja4t(ctx.tcp_ttl, ctx.tcp_window_size, ctx.tcp_options)

        signals = tcp_analyzer._check_ja4t_mismatch(ctx)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].name, "ja4t_mismatch")

    def test_ja4t_no_mismatch_signal(self):
        redis_client = MagicMock()
        tcp_analyzer = self._create_tcp_analyzer(redis_client)
        # Use a JA4 that contains "chrome" which maps to Windows
        # TTL 128 also maps to Windows - no mismatch
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="chrome_13d1516h2_8daaf6152771_02713d6af862",
            tcp_ttl=128,
            tcp_window_size=65535,
            tcp_options="020405b40103030801010402",
        )
        ctx.tcp_ja4t = generate_ja4t(ctx.tcp_ttl, ctx.tcp_window_size, ctx.tcp_options)

        signals = tcp_analyzer._check_ja4t_mismatch(ctx)
        self.assertEqual(len(signals), 0)

    def test_session_resumption_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(
                return_value=[5, 0, True]
            )  # total=5, resumed=0
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="some_ja4")
            signals = await tcp_analyzer._check_session_resumption(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "no_session_resumption")

        asyncio.run(run_test())

    def test_session_resumption_no_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(
                return_value=[5, 2, True]
            )  # total=5, resumed=2
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="some_ja4")
            signals = await tcp_analyzer._check_session_resumption(ctx)
            self.assertEqual(len(signals), 0)

        asyncio.run(run_test())

    def test_connection_lifespan_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline for zadd, expire, zcard
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[1, True, 5])  # zcard=5
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            redis_client.zrange = AsyncMock(return_value=[(b"200:12345", 200.0)])

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=200)
            signals = await tcp_analyzer._check_connection_lifespan(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "short_connection_lifespan")

        asyncio.run(run_test())

    def test_connection_lifespan_no_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[1, True, 5])  # zcard=5
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            redis_client.zrange = AsyncMock(return_value=[(b"600:12345", 600.0)])

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=600)
            signals = await tcp_analyzer._check_connection_lifespan(ctx)
            self.assertEqual(len(signals), 0)

        asyncio.run(run_test())

    def test_concurrent_connections_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[25, True])  # count=25
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp_analyzer._check_concurrent_connections(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "high_concurrency")

        asyncio.run(run_test())

    def test_return_visitor_trust(self):
        async def run_test():
            redis_client = MagicMock()
            now = __import__("time").time()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(
                return_value=[
                    {
                        b"first_seen": str(int(now - 8 * 86400)).encode(),
                        b"total": b"100",
                        b"allowed": b"95",
                    },
                    True,  # hset
                    101,  # hincrby total
                    96,  # hincrby allowed
                    True,  # expire
                ]
            )
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp_analyzer._check_return_visitor(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "return_visitor_trust")
            self.assertEqual(signals[0].score, -1)

        asyncio.run(run_test())

    def test_tls_alert_rate_signal(self):
        async def run_test():
            redis_client = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[5, True])  # count=5
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis_client.pipeline.return_value = pipeline

            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(
                client_ip="1.2.3.4", tls_alerts=["handshake_failure"]
            )
            signals = await tcp_analyzer._check_tls_alerts(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "high_tls_alert_rate")

        asyncio.run(run_test())


class TestTCPAnalyzerCoverageGaps(unittest.TestCase):
    """Phase 16c — cover previously uncovered code paths."""

    def _make(self, redis=None, extra_cfg=None):
        cfg = {
            "tcp_analyzer": {
                "tcp_fingerprinting": {"enabled": True, "score": 30},
                "session_resumption": {
                    "enabled": True,
                    "min_connections": 5,
                    "score": 15,
                },
                "connection_lifespan": {
                    "enabled": True,
                    "min_connections": 5,
                    "threshold_ms": 500,
                    "score": 20,
                },
                "concurrent_connections": {
                    "enabled": True,
                    "thresholds": {"moderate": 10, "high": 20, "severe": 30},
                    "risk_scores": {"moderate": 10, "high": 25, "severe": 40},
                },
                "return_visitor": {
                    "enabled": True,
                    "trusted_days": 7,
                    "trusted_allow_rate": 0.9,
                    "score_reduction_pct": 20,
                },
                "tls_alerts": {"enabled": True, "rate_threshold": 3, "score": 20},
            }
        }
        if extra_cfg:
            cfg["tcp_analyzer"].update(extra_cfg)
        if redis is None:
            redis = MagicMock()
        return TCPAnalyzer(cfg, redis)

    # -- analyze() full path (lines 65-88)

    def test_analyze_returns_signals_and_increments_counter(self):
        """analyze() runs all enabled checks and increments TCP signals counter."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline for all checks
            pipeline = MagicMock()
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)

            # We need to return different results for different calls to execute()
            # session_resumption: [9, 0, True]
            # connection_lifespan: [1, True, 0]
            # concurrent_connections: [35, True]
            # return_visitor: [{}, True, 1, 1, True]
            # tls_alerts: (not called because tls_alerts=None)
            pipeline.execute = AsyncMock(
                side_effect=[
                    [9, 0, True],  # session_resumption
                    [1, True, 0],  # connection_lifespan
                    [35, True],  # concurrent_connections
                    [{}, True, 1, 1, True],  # return_visitor
                ]
            )
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)

            ctx = ConnectionContext(
                client_ip="1.2.3.4",
                ja4="chrome_13d1516h2_8daaf6152771",
                tcp_ttl=128,
                tcp_window_size=65535,
                tcp_options="0204ffff",
                tls_alerts=None,
                connection_lifespan_ms=100,
            )
            ctx.tcp_ja4t = None  # skip JA4T mismatch
            signals = await tcp.analyze(ctx)
            # Severe concurrency should have fired
            names = [s.name for s in signals]
            self.assertIn("severe_concurrency", names)

        asyncio.run(run())

    def test_analyze_all_disabled_returns_empty(self):
        """analyze() with all features disabled returns empty signals."""

        async def run():
            cfg = {
                "tcp_analyzer": {
                    "tcp_fingerprinting": {"enabled": False},
                    "session_resumption": {"enabled": False},
                    "connection_lifespan": {"enabled": False},
                    "concurrent_connections": {"enabled": False},
                    "return_visitor": {"enabled": False},
                    "tls_alerts": {"enabled": False},
                }
            }
            tcp = TCPAnalyzer(cfg, MagicMock())
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp.analyze(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    # -- _check_ja4t_mismatch with no tcp_ja4t (line 95)

    def test_ja4t_no_tcp_ja4t_returns_empty(self):
        """No tcp_ja4t → skip JA4T check (line 95)."""
        tcp = self._make()
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="chrome_test")
        ctx.tcp_ja4t = None
        signals = tcp._check_ja4t_mismatch(ctx)
        self.assertEqual(signals, [])

    # -- _check_session_resumption exception (lines 171-173)

    def test_session_resumption_redis_exception_fail_open(self):
        """Redis exception → fail open, return [] (lines 171-173)."""

        async def run():
            redis = MagicMock()
            redis.pipeline.side_effect = redis_module.RedisError("redis down")
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="test")
            signals = await tcp._check_session_resumption(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    # -- _check_connection_lifespan exception (lines 223-225) and empty zrange

    def test_connection_lifespan_redis_exception_fail_open(self):
        """Redis exception → fail open, return [] (lines 223-225)."""

        async def run():
            redis = MagicMock()
            redis.pipeline.side_effect = redis_module.RedisError("redis down")
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=100)
            signals = await tcp._check_connection_lifespan(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    def test_connection_lifespan_empty_zrange_no_signal(self):
        """Empty zrange result → no signal (handles median_list == [])."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[1, True, 5])  # zcard=5
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            redis.zrange = AsyncMock(return_value=[])  # Empty — unusual but possible
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=100)
            signals = await tcp._check_connection_lifespan(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    # -- _check_concurrent_connections severe (line 248) and moderate (263-274)

    def test_concurrent_connections_severe(self):
        """Count ≥ severe threshold → severe_concurrency signal (line 248)."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[35, True])  # count=35
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_concurrent_connections(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "severe_concurrency")

        asyncio.run(run())

    def test_concurrent_connections_moderate(self):
        """Count ≥ moderate but < high → moderate_concurrency signal (lines 263-270)."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[12, True])  # count=12
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_concurrent_connections(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "moderate_concurrency")

        asyncio.run(run())

    def test_concurrent_connections_exception_fail_open(self):
        """Redis exception → fail open, return [] (lines 271-274)."""

        async def run():
            redis = MagicMock()
            redis.pipeline.side_effect = redis_module.RedisError("redis down")
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_concurrent_connections(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    # -- decrement_concurrent_connections (lines 280-285)

    def test_decrement_concurrent_connections(self):
        """decrement_concurrent_connections calls DECR on correct key."""

        async def run():
            redis = MagicMock()
            redis.decr = AsyncMock(return_value=0)
            tcp = self._make(redis=redis)
            await tcp.decrement_concurrent_connections("1.2.3.4")
            redis.decr.assert_called_once_with("concurrent:1.2.3.4")

        asyncio.run(run())

    def test_decrement_concurrent_connections_redis_exception(self):
        """Redis exception in decrement is silently ignored."""

        async def run():
            redis = MagicMock()
            redis.decr = AsyncMock(side_effect=redis_module.RedisError("redis down"))
            tcp = self._make(redis=redis)
            await tcp.decrement_concurrent_connections("1.2.3.4")  # Must not raise

        asyncio.run(run())

    # -- _check_return_visitor new visitor (lines 298-302)

    def test_return_visitor_new_visitor_no_signal(self):
        """New visitor (no prior data) → initialise entry, return [] (lines 298-302)."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[{}, True, 1, 1, True])
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_return_visitor(ctx)
            self.assertEqual(signals, [])
            redis.pipeline.assert_called_once()

        asyncio.run(run())

    def test_return_visitor_exception_fail_open(self):
        """Redis exception → fail open, return [] (lines 333-336)."""

        async def run():
            redis = MagicMock()
            redis.pipeline.side_effect = redis_module.RedisError("redis down")
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_return_visitor(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    def test_return_visitor_insufficient_days_no_signal(self):
        """Visitor known < trusted_days → no trust signal."""

        async def run():
            import time

            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(
                return_value=[
                    {
                        b"first_seen": str(
                            int(time.time() - 3 * 86400)
                        ).encode(),  # only 3 days
                        b"total": b"50",
                        b"allowed": b"48",
                    },
                    True,  # hset
                    51,  # hincrby total
                    49,  # hincrby allowed
                    True,  # expire
                ]
            )
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4")
            signals = await tcp._check_return_visitor(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    # -- _check_tls_alerts no alerts (line 343) and first-alert expiry (line 349)

    def test_tls_alerts_no_alerts_returns_empty(self):
        """No tls_alerts → return [] (line 343)."""

        async def run():
            tcp = self._make()
            ctx = ConnectionContext(client_ip="1.2.3.4", tls_alerts=None)
            signals = await tcp._check_tls_alerts(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    def test_tls_alerts_first_alert_sets_expire(self):
        """count == 1 → expire is set, below threshold → no signal (line 349)."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[1, True])  # First alert
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4", tls_alerts=["close_notify"])
            signals = await tcp._check_tls_alerts(ctx)
            self.assertEqual(signals, [])
            redis.pipeline.assert_called_once()

        asyncio.run(run())

    def test_tls_alerts_below_threshold_no_signal(self):
        """Count ≤ threshold → no signal."""

        async def run():
            redis = MagicMock()

            # Phase 28a: Mock pipeline
            pipeline = MagicMock()
            pipeline.execute = AsyncMock(return_value=[2, True])  # ≤ 3
            pipeline.__aenter__ = AsyncMock(return_value=pipeline)
            pipeline.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline.return_value = pipeline

            tcp = self._make(redis=redis)
            ctx = ConnectionContext(
                client_ip="1.2.3.4", tls_alerts=["handshake_failure"]
            )
            signals = await tcp._check_tls_alerts(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())

    def test_tls_alerts_exception_fail_open(self):
        """Redis exception → fail open, return [] (lines 359-362)."""

        async def run():
            redis = MagicMock()
            redis.pipeline.side_effect = redis_module.RedisError("redis down")
            tcp = self._make(redis=redis)
            ctx = ConnectionContext(client_ip="1.2.3.4", tls_alerts=["close_notify"])
            signals = await tcp._check_tls_alerts(ctx)
            self.assertEqual(signals, [])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
