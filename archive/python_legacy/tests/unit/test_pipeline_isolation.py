"""Pipeline isolation tests — verify Pipeline works correctly with injected
mock collectors via the ``collectors=`` parameter.

Uses unittest.TestCase + asyncio.run(). No pytest-asyncio dependency.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from src.security.models import ConnectionContext, PipelineResult, RiskSignal
from src.security.pipeline import Pipeline
from src.security.protocols import SignalCollector

# ---------------------------------------------------------------------------
# Helpers
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


def _make_redis():
    r = MagicMock()
    r.get = MagicMock(return_value=None)
    return r


def _make_config():
    return {
        "security_policy": {},
        "monitor_mode": {"log_counterfactuals": False},
        "blocklists": {},
    }


def _make_ctx(ip="10.0.0.1"):
    return ConnectionContext(client_ip=ip, alpn=None, ja4="", sni=None)


class MockCollector:
    """Minimal class satisfying the SignalCollector protocol."""

    def __init__(self, signal=None, raises=None):
        self._signal = signal
        self._raises = raises
        self.called = False

    async def get_signal(self, ctx: ConnectionContext) -> "RiskSignal | None":
        self.called = True
        if self._raises:
            raise self._raises
        return self._signal

    async def initialize(self) -> None:  # pragma: no cover
        pass

    async def shutdown(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# TestPipelineIsolation
# ---------------------------------------------------------------------------


class TestPipelineIsolation(unittest.TestCase):

    def test_pipeline_accepts_mock_collectors(self):
        """Pipeline.__init__ succeeds with collectors=[MockCollector()]."""
        collector = MockCollector()
        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[collector],
        )
        self.assertIsNotNone(pipeline)
        self.assertEqual(pipeline._injected_collectors, [collector])

    def test_pipeline_calls_all_collectors(self):
        """All collectors in the list are called during _collect_signals."""
        c1 = MockCollector(signal=None)
        c2 = MockCollector(signal=None)
        c3 = MockCollector(signal=None)

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[c1, c2, c3],
        )
        ctx = _make_ctx()
        asyncio.run(pipeline.process(ctx))

        self.assertTrue(c1.called)
        self.assertTrue(c2.called)
        self.assertTrue(c3.called)

    def test_pipeline_handles_collector_returning_none(self):
        """None return from a collector → not appended to signals list."""
        c = MockCollector(signal=None)
        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[c],
        )
        ctx = _make_ctx()
        result = asyncio.run(pipeline.process(ctx))

        self.assertEqual(result.action, "allow")
        self.assertEqual(result.signals, [])

    def test_pipeline_handles_collector_raising_exception(self):
        """Exception in one collector → logged, not re-raised; other collectors called."""
        bad = MockCollector(raises=RuntimeError("boom"))
        good = MockCollector(signal=None)

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[bad, good],
        )
        ctx = _make_ctx()

        # Must not raise
        result = asyncio.run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")

        # Both collectors were attempted
        self.assertTrue(bad.called)
        self.assertTrue(good.called)

    def test_risk_scorer_receives_all_signals(self):
        """Two collectors each returning a signal → scorer receives both signals."""
        sig1 = RiskSignal(name="signal_one", score=10, reason="first")
        sig2 = RiskSignal(name="signal_two", score=15, reason="second")

        c1 = MockCollector(signal=sig1)
        c2 = MockCollector(signal=sig2)

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[c1, c2],
        )

        # Wire a mock scorer that records what it receives
        received_signals = []

        def mock_score(signals):
            received_signals.extend(signals)
            return 25, "flag", list(signals), {}

        mock_scorer = MagicMock()
        mock_scorer.score = MagicMock(side_effect=mock_score)
        mock_decider = MagicMock()
        mock_decider.decide = MagicMock(return_value="flag")
        pipeline.update_scorer(mock_scorer, mock_decider)

        ctx = _make_ctx()
        asyncio.run(pipeline.process(ctx))

        signal_names = [s.name for s in received_signals]
        self.assertIn("signal_one", signal_names)
        self.assertIn("signal_two", signal_names)

    def test_signalcollector_protocol_satisfied(self):
        """MockCollector satisfies the SignalCollector Protocol (isinstance check)."""
        collector = MockCollector()
        # SignalCollector is a @runtime_checkable Protocol
        self.assertIsInstance(collector, SignalCollector)

    def test_pipeline_with_no_collectors_uses_builtin_path(self):
        """collectors=None → _injected_collectors is None (uses built-in module path)."""
        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=None,
        )
        self.assertIsNone(pipeline._injected_collectors)

    def test_pipeline_empty_collectors_list_returns_no_signals(self):
        """collectors=[] (empty list) → _collect_signals returns [], pipeline allows."""
        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[],
        )
        ctx = _make_ctx()
        result = asyncio.run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")
        self.assertEqual(result.signals, [])

    def test_pipeline_exception_in_all_collectors_still_returns_allow(self):
        """All collectors raise → pipeline still returns allow (fail open)."""
        bad1 = MockCollector(raises=RuntimeError("boom 1"))
        bad2 = MockCollector(raises=ValueError("boom 2"))
        bad3 = MockCollector(raises=KeyError("boom 3"))

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[bad1, bad2, bad3],
        )
        ctx = _make_ctx()
        result = asyncio.run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")

    def test_pipeline_signal_error_counter_incremented_per_failing_collector(self):
        """Each collector that raises increments _SIGNAL_ERROR counter once each."""
        from src.security.pipeline import _SIGNAL_ERROR

        class IsolationCollectorAlpha:
            async def get_signal(self, ctx):
                raise RuntimeError("error alpha")

        class IsolationCollectorBeta:
            async def get_signal(self, ctx):
                raise RuntimeError("error beta")

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[IsolationCollectorAlpha(), IsolationCollectorBeta()],
        )

        # Read counter values directly from the counter object (immune to REGISTRY cleanup)
        before_a = _SIGNAL_ERROR.labels(module="IsolationCollectorAlpha")._value.get()
        before_b = _SIGNAL_ERROR.labels(module="IsolationCollectorBeta")._value.get()

        ctx = _make_ctx()
        asyncio.run(pipeline.process(ctx))

        after_a = _SIGNAL_ERROR.labels(module="IsolationCollectorAlpha")._value.get()
        after_b = _SIGNAL_ERROR.labels(module="IsolationCollectorBeta")._value.get()

        self.assertGreaterEqual(after_a - before_a, 1.0)
        self.assertGreaterEqual(after_b - before_b, 1.0)

    def test_pipeline_result_has_correct_dial_value(self):
        """PipelineResult.dial reflects the cache.dial value."""
        cache = _make_local_cache(dial=42)
        pipeline = Pipeline(
            config=_make_config(),
            local_cache=cache,
            redis_client=_make_redis(),
            collectors=[],
        )
        ctx = _make_ctx()
        result = asyncio.run(pipeline.process(ctx))
        self.assertEqual(result.dial, 42)

    def test_pipeline_collector_signal_score_reaches_scorer(self):
        """Signal with score=70 from collector → scorer.score called with that signal."""
        sig = RiskSignal(name="high_risk", score=70, reason="test signal")
        c = MockCollector(signal=sig)

        pipeline = Pipeline(
            config=_make_config(),
            local_cache=_make_local_cache(),
            redis_client=_make_redis(),
            collectors=[c],
        )

        seen = []

        def capture_score(signals):
            seen.extend(signals)
            return 70, "block", list(signals), {}

        mock_scorer = MagicMock()
        mock_scorer.score = MagicMock(side_effect=capture_score)
        mock_decider = MagicMock()
        mock_decider.decide = MagicMock(return_value="block")
        pipeline.update_scorer(mock_scorer, mock_decider)

        ctx = _make_ctx()
        asyncio.run(pipeline.process(ctx))

        self.assertTrue(any(s.name == "high_risk" for s in seen))


if __name__ == "__main__":
    unittest.main()
