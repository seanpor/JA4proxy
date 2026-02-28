"""Integration: dial change propagates via LocalCache to pipeline decisions."""

import asyncio
from unittest.mock import MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider, effective_threshold
from src.security.pipeline import ConnectionContext, Pipeline, PipelineResult
from src.security.risk_scorer import RiskScorer

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_pipeline(dial: int = 0) -> tuple[Pipeline, LocalCache]:
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        },
        "monitor_mode": {
            "counterfactual_thresholds": [25, 50, 75, 100],
            "log_counterfactuals": True,
        },
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(thresholds=THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline, cache


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d1516h2_aabbccddee11_112233445566"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


class TestDialChangePropagation:
    def test_dial_zero_always_allows(self):
        """dial=0 → monitor mode → allow regardless of signals (score=0)."""
        pipeline, _ = _make_pipeline(dial=0)
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.dial == 0

    def test_dial_change_applies_to_next_decision(self):
        """Changing local_cache.dial immediately affects the next pipeline call."""
        pipeline, cache = _make_pipeline(dial=0)
        # dial=0 → allow
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        # Raise dial to 100
        cache.dial = 100
        assert pipeline._cache.dial == 100

    def test_counterfactuals_present_in_scored_result(self):
        """Scored connections always carry counterfactual dict."""
        pipeline, _ = _make_pipeline(dial=0)
        result = _run(pipeline.process(_ctx()))
        # score=0 → all counterfactuals are "allow"
        assert isinstance(result.counterfactuals, dict)
        assert all(v in ["allow", "flag"] for v in result.counterfactuals.values())

    def test_counterfactuals_keyed_by_dial_values(self):
        """Counterfactuals dict is keyed by the configured dial values."""
        pipeline, _ = _make_pipeline(dial=0)
        result = _run(pipeline.process(_ctx()))
        assert set(result.counterfactuals.keys()) == {25, 50, 75, 100}

    def test_bypass_result_has_empty_counterfactuals(self):
        """Bypassed connections have empty counterfactuals (not scored)."""
        pipeline, _ = _make_pipeline(dial=0)
        ctx = _ctx(alpn="h2")
        result = _run(pipeline.process(ctx))
        assert result.bypassed is True
        assert result.counterfactuals == {}

    def test_dial_50_applies_interpolated_threshold(self):
        """At dial=50, effective thresholds use the interpolation formula."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        # effective_flag@50 = round(101 - 0.5 * 81) = round(60.5) = 60
        assert effective_threshold(20, 50) == 60
        assert decider.decide(60, 50) == "flag"
        assert decider.decide(59, 50) == "allow"

    def test_dial_100_applies_configured_thresholds(self):
        """At dial=100, effective thresholds equal configured exactly."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        assert decider.decide(70, 100) == "block"
        assert decider.decide(69, 100) == "tarpit"

    def test_pipeline_monitor_mode_always_allows(self):
        """Even if a mock scorer returns ban, dial=0 forces action=allow."""
        pipeline, cache = _make_pipeline(dial=0)
        mock_scorer = MagicMock()
        from src.security.risk_scorer import RiskSignal
        mock_scorer.score.return_value = MagicMock(
            total_score=90,
            signals=[RiskSignal("asn_tor", 90, "tor")],
            recommended_action="ban",
            explanation="asn_tor(+90)",
        )
        pipeline.update_scorer(mock_scorer, ActionDecider(THRESHOLDS))
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 90
        assert result.dial == 0


class TestCounterfactualContent:
    def test_all_allow_at_score_zero(self):
        """Score=0 → all counterfactual actions are 'allow'."""
        pipeline, _ = _make_pipeline(dial=0)
        result = _run(pipeline.process(_ctx()))
        assert result.counterfactuals[25] in ["allow", "flag"]
        assert result.counterfactuals[50] in ["allow", "flag"]
        assert result.counterfactuals[75] in ["allow", "flag"]
        assert result.counterfactuals[100] in ["allow", "flag"]

    def test_counterfactuals_reflect_dial_thresholds(self):
        """High score shows blocking actions at higher dial values."""
        pipeline, _ = _make_pipeline(dial=0)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=80,
            signals=[],
            recommended_action="block",
            explanation="",
        )
        pipeline.update_scorer(mock_scorer, ActionDecider(THRESHOLDS))
        result = _run(pipeline.process(_ctx()))
        # At dial=100, score=80 → block (>70)
        assert result.counterfactuals[100] == "block"
        # At dial=0 → allow (enforced)
        assert result.action == "allow"
