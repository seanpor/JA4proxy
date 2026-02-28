import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.cache.local_cache import LocalCache


class TestTCPAnalyzerChaos(unittest.TestCase):
    def setUp(self):
        self.config = {
            "security_policy": {},
            "tcp_analyzer": {
                "concurrent_connections": {
                    "enabled": True,
                    "thresholds": {"moderate": 1, "high": 2, "severe": 3},
                    "risk_scores": {"moderate": 10, "high": 25, "severe": 40},
                }
            },
        }
        self.local_cache = LocalCache(self.config)
        self.redis_client = MagicMock()
        self.pipeline = Pipeline(self.config, self.local_cache, self.redis_client)

        # Mock scorer and decider
        self.scorer = MagicMock()
        self.decider = MagicMock()
        self.decider.decide.return_value = "allow"
        self.pipeline.update_scorer(self.scorer, self.decider)

    def test_redis_failure_during_counter_incr(self):
        # Simulate Redis connection failure by raising an exception
        async def raise_connection_error(*args, **kwargs):
            raise ConnectionError("Redis connection refused")

        self.redis_client.incr = AsyncMock(side_effect=raise_connection_error)
        ctx = ConnectionContext(client_ip="1.2.3.4")

        async def run_test():
            result = await self.pipeline.process(ctx)
            # Should fail open (allow)
            self.assertEqual(result.action, "allow")
            # Scorer should still be called, but with no concurrency signal
            self.scorer.score.assert_called()
            signals = self.scorer.score.call_args[0][0]
            self.assertFalse(any(s.name.endswith("_concurrency") for s in signals))

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
