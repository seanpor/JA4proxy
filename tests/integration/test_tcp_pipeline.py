import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.cache.local_cache import LocalCache
from tests.unit.security.test_mtls import generate_self_signed_ca, generate_signed_cert
from cryptography.hazmat.primitives import serialization


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
        # Generate certs first, so the file exists when the pipeline is created
        self.ca_cert, self.ca_key = generate_self_signed_ca()
        self.client_cert, self.client_key = generate_signed_cert(
            self.ca_cert, self.ca_key
        )
        with open("test_ca.pem", "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self.pipeline = Pipeline(self.config, self.local_cache, self.redis_client)

        # Mock scorer and decider
        self.scorer = MagicMock()
        self.decider = MagicMock()
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
            # Set up async mock for incr
            self.redis_client.incr = AsyncMock(return_value=5)
            self.redis_client.expire = AsyncMock()

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
