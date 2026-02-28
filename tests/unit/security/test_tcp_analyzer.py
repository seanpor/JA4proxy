import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from src.security.tcp_analyzer import TCPAnalyzer, generate_ja4t
from src.security.models import ConnectionContext, RiskSignal


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
            redis_client.hmget = AsyncMock(return_value=[4, 0])
            redis_client.hmset = AsyncMock()
            redis_client.expire = AsyncMock()
            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="some_ja4")
            signals = await tcp_analyzer._check_session_resumption(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "no_session_resumption")

        asyncio.run(run_test())

    def test_session_resumption_no_signal(self):
        async def run_test():
            redis_client = MagicMock()
            redis_client.hmget = AsyncMock(return_value=[4, 2])
            redis_client.hmset = AsyncMock()
            redis_client.expire = AsyncMock()
            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="some_ja4")
            signals = await tcp_analyzer._check_session_resumption(ctx)
            self.assertEqual(len(signals), 0)

        asyncio.run(run_test())

    def test_connection_lifespan_signal(self):
        async def run_test():
            redis_client = MagicMock()
            redis_client.zcard = AsyncMock(return_value=5)
            redis_client.zrange = AsyncMock(return_value=[(b"200:12345", 200.0)])
            redis_client.zadd = AsyncMock()
            redis_client.expire = AsyncMock()
            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=200)
            signals = await tcp_analyzer._check_connection_lifespan(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "short_connection_lifespan")

        asyncio.run(run_test())

    def test_connection_lifespan_no_signal(self):
        async def run_test():
            redis_client = MagicMock()
            redis_client.zcard = AsyncMock(return_value=5)
            redis_client.zrange = AsyncMock(return_value=[(b"600:12345", 600.0)])
            redis_client.zadd = AsyncMock()
            redis_client.expire = AsyncMock()
            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(client_ip="1.2.3.4", connection_lifespan_ms=600)
            signals = await tcp_analyzer._check_connection_lifespan(ctx)
            self.assertEqual(len(signals), 0)

        asyncio.run(run_test())

    def test_concurrent_connections_signal(self):
        async def run_test():
            redis_client = MagicMock()
            redis_client.incr = AsyncMock(return_value=25)
            redis_client.expire = AsyncMock()
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
            redis_client.hgetall = AsyncMock(
                return_value={
                    b"first_seen": str(int(now - 8 * 86400)).encode(),
                    b"total": b"100",
                    b"allowed": b"95",
                }
            )
            redis_client.hmset = AsyncMock()
            redis_client.hset = AsyncMock()
            redis_client.hincrby = AsyncMock()
            redis_client.expire = AsyncMock()
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
            redis_client.incr = AsyncMock(return_value=5)
            redis_client.expire = AsyncMock()
            tcp_analyzer = self._create_tcp_analyzer(redis_client)
            ctx = ConnectionContext(
                client_ip="1.2.3.4", tls_alerts=["handshake_failure"]
            )
            signals = await tcp_analyzer._check_tls_alerts(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "high_tls_alert_rate")

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
