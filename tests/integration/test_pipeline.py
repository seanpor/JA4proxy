"""Integration tests for the full pipeline with Phase 1 scorer + decider.

Tests that the pipeline wires scorer and decider correctly and that
bypass, scoring, and monitor-mode paths all produce correct results.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer, RiskSignal

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_pipeline(dial: int = 75) -> Pipeline:
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        }
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(
        config=config, local_cache=cache, redis_client=MagicMock()
    )
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "185.220.101.5", "ja4": "t13d_bad_fingerprint_aa"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


class TestPipelineBypasses:
    """Bypass paths produce correct PipelineResult."""

    def test_h2_alpn_bypass_logged_correctly(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn="h2")))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "alpn_browser"
        assert result.score is None
        assert result.signals == []

    def test_known_bad_ja4_blocked(self):
        pipeline = _make_pipeline()
        pipeline._blacklist = {"t13d_bad_fingerprint_aa"}
        result = _run(pipeline.process(_ctx()))
        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_blacklist"


class TestPipelineScoring:
    """End-to-end scoring with real RiskScorer + ActionDecider."""

    def test_zero_signals_allows(self):
        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 0

    def test_dial_zero_allows_even_high_score(self):
        """dial=0 → MONITOR; action=allow regardless of score."""
        pipeline = _make_pipeline(dial=0)
        # Inject high-scoring signals manually via a mock scorer
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=90,
            signals=[RiskSignal("asn_tor", 90, "tor")],
            recommended_action="ban",
            explanation="asn_tor(+90)",
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "ban"
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"  # Monitor mode overrides
        assert result.score == 90  # Score is recorded

    def test_dial_100_high_score_blocks(self):
        """dial=100 + score above block threshold → block action."""
        pipeline = _make_pipeline(dial=100)
        # Inject a scorer that returns score=78 (between block=70 and ban=85)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=78,
            signals=[RiskSignal("rdap_known_bad_org", 45, "bad org"),
                     RiskSignal("missing_sni", 30, "no sni")],
            recommended_action="block",
            explanation="rdap_known_bad_org(+45), missing_sni(+30)",
        )
        decider = ActionDecider(THRESHOLDS)
        pipeline.update_scorer(mock_scorer, decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "block"
        assert result.score == 78

    def test_signals_list_populated(self):
        """Signals from scorer appear in PipelineResult."""
        pipeline = _make_pipeline(dial=100)
        signals = [RiskSignal("missing_sni", 30, "no sni")]
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=30,
            signals=signals,
            recommended_action="flag",
            explanation="missing_sni(+30)",
        )
        decider = ActionDecider(THRESHOLDS)
        pipeline.update_scorer(mock_scorer, decider)

        result = _run(pipeline.process(_ctx()))
        assert len(result.signals) == 1
        assert result.signals[0].name == "missing_sni"


class TestPipelineMonitorMode:
    """dial=0 produces monitor log lines, not blocking actions."""

    def test_monitor_result_has_score_but_allow_action(self):
        pipeline = _make_pipeline(dial=0)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=61,
            signals=[],
            recommended_action="tarpit",
            explanation="",
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "tarpit"
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 61
        assert result.dial == 0
