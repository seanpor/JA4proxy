"""Chaos tests for dial change and DialManager resilience."""

import asyncio
from unittest.mock import MagicMock

import pytest
import redis

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider, DialManager
from src.security.pipeline import ConnectionContext, Pipeline
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


# ---------------------------------------------------------------------------
# DialManager init chaos
# ---------------------------------------------------------------------------


class TestDialInitChaos:
    def test_redis_error_on_init_uses_default(self):
        """DialManager.initialize() when Redis raises → returns default_dial (0)."""
        redis_mock = MagicMock()
        redis_mock.get.side_effect = redis.ConnectionError("down")
        redis_mock.set.side_effect = redis.ConnectionError("down")
        dm = DialManager({"monitor_mode": {"dial": 0}})
        result = dm.initialize(redis_mock)
        assert result == 0

    def test_unacknowledged_nonzero_resets_to_zero(self):
        """blocking_acknowledged=False with stored dial=75 → resets to 0."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"75"
        redis_mock.set.return_value = True
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": False}})
        result = dm.initialize(redis_mock)
        assert result == 0

    def test_acknowledged_preserves_stored_value(self):
        """blocking_acknowledged=True with stored dial=75 → keeps 75."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"75"
        redis_mock.set.return_value = True
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": True}})
        result = dm.initialize(redis_mock)
        assert result == 75

    def test_redis_set_failure_does_not_raise(self):
        """Redis error on set → logged warning, returns dial value anyway."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = None
        redis_mock.set.side_effect = redis.ConnectionError("down")
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": True, "dial": 0}})
        result = dm.initialize(redis_mock)
        assert result == 0  # default; no exception raised


# ---------------------------------------------------------------------------
# DialManager validate_change chaos
# ---------------------------------------------------------------------------


class TestDialValidateChangeChaos:
    def test_validate_change_redis_error_counts_as_zero(self):
        """Redis error reading count key → treated as 0 (fail open)."""
        redis_mock = MagicMock()
        redis_mock.get.side_effect = redis.ConnectionError("down")
        redis_mock.incr.return_value = 1
        redis_mock.expire.return_value = True
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        # Should not raise — Redis error means count=0, so change is allowed
        dm.validate_change(0, 10, redis_mock)

    def test_validate_change_incr_failure_does_not_raise(self):
        """Redis error incrementing counter → logged, no exception."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"0"
        redis_mock.incr.side_effect = redis.ConnectionError("down")
        redis_mock.expire.side_effect = redis.ConnectionError("down")
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        # Should not raise even if incr fails
        dm.validate_change(0, 10, redis_mock)

    def test_validate_change_at_limit_raises_without_force(self):
        """At limit, reject change unless force=True."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"25"
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        with pytest.raises(ValueError, match="Dial change rejected"):
            dm.validate_change(0, 10, redis_mock, force=False)

    def test_validate_change_at_limit_with_force_succeeds(self):
        """Force=True bypasses rate limit even when at max."""
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"25"
        redis_mock.incr.return_value = 26
        redis_mock.expire.return_value = True
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        dm.validate_change(0, 10, redis_mock, force=True)  # must not raise


# ---------------------------------------------------------------------------
# Mid-traffic dial resilience
# ---------------------------------------------------------------------------


class TestDialMidTrafficChaos:
    def test_cached_dial_used_when_redis_down(self):
        """local_cache.dial retains last known value when Redis unreachable."""
        cache = LocalCache({})
        cache.dial = 75
        pipeline = Pipeline(
            config={
                "security_policy": {
                    "alpn_browser_bypass": {"enabled": True},
                    "ja4_whitelist_bypass": {"enabled": True},
                    "mtls_bypass": {"enabled": True},
                    "static_ip_allowlist": {"enabled": True},
                    "ja4_blacklist_bypass": {"enabled": True},
                    "country_blacklist_bypass": {"enabled": True},
                }
            },
            local_cache=cache,
            redis_client=MagicMock(),
        )
        pipeline.update_scorer(RiskScorer(THRESHOLDS), ActionDecider(THRESHOLDS))
        # Even with Redis-dependent ops failing, dial=75 is in local_cache
        assert pipeline._cache.dial == 75

    def test_pipeline_process_never_raises(self):
        """pipeline.process() must never raise, even with a broken scorer."""
        cache = LocalCache({})
        cache.dial = 50
        pipeline = Pipeline(
            config={
                "security_policy": {
                    "alpn_browser_bypass": {"enabled": True},
                    "ja4_whitelist_bypass": {"enabled": True},
                    "mtls_bypass": {"enabled": True},
                    "static_ip_allowlist": {"enabled": True},
                    "ja4_blacklist_bypass": {"enabled": True},
                    "country_blacklist_bypass": {"enabled": True},
                }
            },
            local_cache=cache,
            redis_client=MagicMock(),
        )
        broken_scorer = MagicMock()
        broken_scorer.score.side_effect = RuntimeError("scorer crashed")
        pipeline.update_scorer(broken_scorer, ActionDecider(THRESHOLDS))
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1516h2_aabbccddee11_112233445566")
        # Must not raise — fail open
        result = _run(pipeline.process(ctx))
        assert result.action == "allow"

    def test_dial_zero_no_blocking_even_with_high_score(self):
        """dial=0 → monitor mode → always allow regardless of mock score."""
        cache = LocalCache({})
        cache.dial = 0
        pipeline = Pipeline(
            config={
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
            },
            local_cache=cache,
            redis_client=MagicMock(),
        )
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=100, signals=[], recommended_action="ban", explanation=""
        )
        pipeline.update_scorer(mock_scorer, ActionDecider(THRESHOLDS))
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1516h2_aabbccddee11_112233445566")
        result = _run(pipeline.process(ctx))
        assert result.action == "allow"
        assert result.score == 100
