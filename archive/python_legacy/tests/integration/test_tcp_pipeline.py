import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives import serialization

from src.cache.local_cache import LocalCache
from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.security.risk_scorer import RiskAssessment
from tests.unit.security.test_mtls import generate_self_signed_ca, generate_signed_cert


class TestTCPPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.config = {
            "security_policy": {"mtls_bypass": {"enabled": True}},
            "tcp_analyzer": {
                "concurrent_connections": {
                    "enabled": True,
                    "thresholds": {"moderate": 1, "high": 2, "severe": 3},
                    "risk_scores": {"moderate": 10, "high": 25, "severe": 40},
                }
            },
            "mtls": {
                "enabled": True,
                "ca_cert_path": "test_ca.pem",
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
        # Generate certs first, so the file exists when the pipeline is created
        self.ca_cert, self.ca_key = generate_self_signed_ca()
        self.client_cert, self.client_key = generate_signed_cert(
            self.ca_cert, self.ca_key
        )
        with open("test_ca.pem", "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

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

    def tearDown(self):
        import os

        if os.path.exists("test_ca.pem"):
            os.remove("test_ca.pem")

    def test_mtls_bypass(self):
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
        ctx = ConnectionContext(client_ip="1.2.3.4", client_certificate=client_cert_pem)

        async def run_test():
            result = await self.pipeline.process(ctx)
            self.assertTrue(result.bypassed)
            self.assertEqual(result.bypass_reason, "mtls")

        asyncio.run(run_test())

    def test_tcp_signals_in_pipeline(self):
        async def run_test():
            # count=5 exceeds severe threshold (3) → severe_concurrency signal
            self.redis_client._test_pipe.execute = AsyncMock(return_value=[5, True])

            ctx = ConnectionContext(client_ip="1.2.3.4")

            # Disable mtls bypass for this test
            self.pipeline._policy["mtls_bypass"]["enabled"] = False
            await self.pipeline.process(ctx)

            # Check that the scorer was called with the tcp signal
            self.scorer.score.assert_called()
            signals = self.scorer.score.call_args[0][0]
            self.assertTrue(any(s.name == "severe_concurrency" for s in signals))

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
