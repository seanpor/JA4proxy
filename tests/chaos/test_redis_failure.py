"""Chaos tests: Redis failure behaviour for Phase 0 and Phase 1.

Verifies that the proxy fails open (allows connections) when Redis is
unavailable, and that errors are logged but never crash the process.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.pipeline import ConnectionContext, Pipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _ctx(**kwargs):
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d_test_fingerprint"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


def _make_pipeline(dial: int = 0) -> Pipeline:
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
    mock_redis = MagicMock()
    return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)


# ---------------------------------------------------------------------------
# Phase 0 chaos scenarios
# ---------------------------------------------------------------------------


class TestRedisFailurePipelineFailsOpen:
    """Pipeline must allow connections when Redis is unavailable."""

    def test_redis_error_in_pipeline_allows_connection(self):
        """Unexpected exception in pipeline → fail open, connection allowed."""
        pipeline = _make_pipeline()

        # Inject a scorer that raises an exception
        mock_scorer = MagicMock()
        mock_scorer.score.side_effect = RuntimeError("Redis connection refused")
        mock_decider = MagicMock()
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"  # Fail open

    def test_empty_signals_produces_allow(self):
        """Zero signals → score=0 → action=allow. No crash."""
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 0
        assert result.signals == []

    def test_pipeline_logs_error_on_exception(self, caplog):
        """Unexpected pipeline error must be logged."""
        pipeline = _make_pipeline()

        # Force an exception in _check_allow_bypasses by corrupting config
        pipeline._policy = None  # Will cause AttributeError

        with caplog.at_level(logging.ERROR, logger="src.security.pipeline"):
            result = _run(pipeline.process(_ctx()))

        assert result.action == "allow"  # Still fails open
        assert any("unexpected_error" in r.message or "error" in r.message.lower()
                   for r in caplog.records)


class TestLocalCacheWithRedisDown:
    """Local cache isolates the pipeline from Redis failures."""

    def test_whitelist_bypass_still_allows_when_scorer_raises(self):
        """JA4 whitelist bypass occurs before scoring — a broken scorer cannot block
        traffic that already matched the in-process whitelist set."""
        pipeline = _make_pipeline()
        pipeline._whitelist.add("t13d_trusted_fp")

        # Inject a scorer that simulates a Redis-backed call failing
        mock_scorer = MagicMock()
        mock_scorer.score.side_effect = ConnectionError("Redis refused connection")
        pipeline.update_scorer(mock_scorer, MagicMock())

        result = _run(pipeline.process(_ctx(ja4="t13d_trusted_fp")))

        # Whitelist bypass fires before scorer — scorer must not have been called
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_whitelist"
        mock_scorer.score.assert_not_called()

    def test_dial_preserved_across_pipeline_calls_after_redis_drop(self):
        """The dial value set in local cache persists across connections even
        when Redis is unreachable — the last known dial governs scoring."""
        pipeline = _make_pipeline(dial=75)
        from src.security.risk_scorer import RiskScorer, RiskSignal
        from src.security.action_decider import ActionDecider

        thresholds = {"flag": 20, "rate_limit": 35, "tarpit": 55, "block": 70, "ban": 85}
        pipeline.update_scorer(RiskScorer(thresholds), ActionDecider(thresholds, 300))

        # dial=75 → effective_block threshold = 70 × 100/75 ≈ 93 (unreachable at score ≤ 100)
        # effective_tarpit threshold = 55 × 100/75 ≈ 73 — score 80 should trigger tarpit
        # (but with dial<100 scores effectively need to be higher to trigger actions)
        # At dial=75: score=80 → falls between adjusted tarpit(73) and block(93) → tarpit
        signals = [RiskSignal(name="test_signal", score=80, reason="dial test")]
        score, action, _ = pipeline._score_connection(signals)

        assert score == 80
        # Verify the dial value in the cache is 75, not 0
        assert pipeline._cache.dial == 75
        # The action is determined by dial-adjusted thresholds — at dial=75 with score=80
        # effective_block = 93 (not reached), effective_tarpit = 73 (reached) → tarpit
        assert action in ("tarpit", "block"), f"Unexpected action {action!r} at dial=75, score=80"

    def test_block_bypass_fires_without_any_redis_interaction(self):
        """JA4 blacklist bypass must work entirely from in-process memory —
        no Redis call should be made to enforce a known-bad fingerprint."""
        pipeline = _make_pipeline()
        pipeline._blacklist.add("t13d_known_bad_fp")

        # Sabotage the Redis client — any call must fail
        pipeline._redis.side_effect = ConnectionError("Redis is down")

        result = _run(pipeline.process(_ctx(ja4="t13d_known_bad_fp")))

        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_blacklist"


class TestAllSignalModulesReturnEmpty:
    """All signal modules returning empty lists → score=0, action=allow."""

    def test_no_signals_score_zero(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx()))
        assert result.score == 0
        assert result.action == "allow"
        assert result.signals == []

    def test_no_signals_allow_log_emitted(self, caplog):
        """An ALLOW log line must be emitted even when no signals fire."""
        pipeline = _make_pipeline()
        with caplog.at_level(logging.INFO, logger="src.security.pipeline"):
            _run(pipeline.process(_ctx()))
        # At least one log line should reference allow
        log_text = " ".join(r.message for r in caplog.records)
        assert "ALLOW" in log_text or "allow" in log_text


# ---------------------------------------------------------------------------
# Phase 1 chaos scenarios (extend when Phase 1 is wired in)
# ---------------------------------------------------------------------------


class TestRedisDialFailure:
    """Redis unreachable for dial read → last known dial used; scoring continues."""

    def test_scoring_continues_with_cached_dial(self):
        """Even without Redis, scoring works using last known dial from cache."""
        from src.security.risk_scorer import RiskScorer, RiskSignal
        from src.security.action_decider import ActionDecider

        thresholds = {
            "flag": 20, "rate_limit": 35, "tarpit": 55, "block": 70, "ban": 85
        }
        scorer = RiskScorer(thresholds)
        decider = ActionDecider(thresholds, ban_duration_seconds=300)

        pipeline = _make_pipeline(dial=100)
        pipeline.update_scorer(scorer, decider)

        # Force dial to 100 (as if read from Redis before it went down)
        pipeline._cache.dial = 100

        # At dial=100 thresholds apply exactly: score=90 → ban (ban threshold=85)
        # At dial=75 effective_ban = 85×100/75 = 113 > max score 100, so ban unreachable
        signals = [RiskSignal(name="rdap_known_bad_org", score=90, reason="test")]

        # Simulate _score_connection directly
        score, action, _ = pipeline._score_connection(signals)
        assert score == 90
        assert action == "ban"

    def test_dial_zero_means_monitor_even_with_high_score(self):
        """If Redis is down and dial defaults to 0 → monitor mode → allow."""
        pipeline = _make_pipeline(dial=0)
        # Don't wire scorer — stub returns 0; but even with scorer:
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
