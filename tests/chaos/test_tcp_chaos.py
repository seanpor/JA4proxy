import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

import redis as redis_lib
from src.cache.local_cache import LocalCache
from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.security.risk_scorer import RiskAssessment


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
        # Pipeline mock for Phase 28 pipeline-based methods
        pipe = MagicMock()
        pipe.incr = MagicMock(return_value=None)
        pipe.expire = MagicMock(return_value=None)
        pipe.execute = AsyncMock(return_value=[1, True])
        pipeline_cm = MagicMock()
        pipeline_cm.__aenter__ = AsyncMock(return_value=pipe)
        pipeline_cm.__aexit__ = AsyncMock(return_value=None)
        self.redis_client.pipeline = MagicMock(return_value=pipeline_cm)
        self.redis_client._test_pipe = pipe
        self.pipeline = Pipeline(self.config, self.local_cache, self.redis_client)

        # Mock scorer and decider — scorer returns proper RiskAssessment to avoid
        # JSON serialization failures in _emit_log
        self.scorer = MagicMock()
        self.scorer.score.return_value = RiskAssessment(
            total_score=0, signals=[], recommended_action="allow", explanation=""
        )
        self.decider = MagicMock()
        self.decider.decide.return_value = "allow"
        self.decider.counterfactuals.return_value = {}
        self.pipeline.update_scorer(self.scorer, self.decider)

    def test_redis_failure_during_counter_incr(self):
        # Simulate Redis pipeline failure during concurrent connections check
        self.redis_client._test_pipe.execute = AsyncMock(
            side_effect=redis_lib.exceptions.ConnectionError("Redis connection refused")
        )
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
