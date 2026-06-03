"""Chaos tests: analytics node down / Redis read failures for Phase 12b.

Verifies that the proxy:
- Continues to process connections when Redis analytics keys are unreadable
- Returns allow (fail open) with zero analytics score contribution
- Does not cache partial results on Redis errors
- Recovers and reads signals once Redis is available again
- Handles all Redis exception types without propagation
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from src.cache.local_cache import LocalCache
from src.security.models import ConnectionContext, RiskSignal
from src.security.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(redis_mock=None):
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        },
        "geoip": {"country_blacklist": []},
        "mtls": {"enabled": False, "ca_cert_path": None},
    }
    cache = LocalCache({})
    if redis_mock is None:
        redis_mock = MagicMock()
        redis_mock.get.return_value = None
    return Pipeline(config=config, local_cache=cache, redis_client=redis_mock)


def _ctx(ip="1.2.3.4"):
    return ConnectionContext(
        client_ip=ip,
        ja4="t13d1516h2_aabbccddee11_112233445566",
    )


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fail open on Redis errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionError("Redis unreachable"),
        TimeoutError("Redis timeout"),
        OSError("network error"),
        Exception("unknown Redis error"),
    ],
)
async def test_redis_exception_returns_empty_signals(exc):
    """Any Redis exception must yield empty analytics signals, not propagate."""
    redis_mock = MagicMock()

    async def _get_error(key):
        raise exc

    redis_mock.get.side_effect = _get_error
    pipeline = _make_pipeline(redis_mock)

    result = await pipeline._get_analytics_signals("10.0.0.1")

    assert result == []


async def test_redis_down_does_not_cache_partial_result():
    """On Redis error, the cache must stay empty so the next request retries."""
    redis_mock = MagicMock()

    async def _get_error(key):
        raise ConnectionError("Redis down")

    redis_mock.get.side_effect = _get_error
    pipeline = _make_pipeline(redis_mock)

    await pipeline._get_analytics_signals("10.0.0.5")

    cached = pipeline._cache.analytics_signals.get("10.0.0.0/24")
    assert cached is None


def test_pipeline_process_allows_when_analytics_redis_down():
    """Full pipeline must return allow (ALPN bypass) even when analytics Redis is down."""
    redis_mock = MagicMock()
    redis_mock.get.side_effect = ConnectionError("Redis down")
    pipeline = _make_pipeline(redis_mock)

    ctx = _ctx("1.2.3.4")
    ctx.alpn = "h2"
    result = _run(pipeline.process(ctx))

    # ALPN h2 → bypass; score N/A, action allow/bypass
    assert result.action in ("allow", "bypass")


def test_pipeline_scores_correctly_when_analytics_redis_down():
    """Signal collection must not raise when analytics Redis is down; scorer still runs."""
    redis_mock = MagicMock()
    redis_mock.get.side_effect = ConnectionError("Redis down")

    from src.security.action_decider import ActionDecider
    from src.security.risk_scorer import RiskScorer

    pipeline = _make_pipeline(redis_mock)
    pipeline.update_scorer(RiskScorer({}), ActionDecider({}))

    ctx = _ctx("2.3.4.5")
    result = _run(pipeline.process(ctx))

    # No score contribution from analytics (Redis down) — should be low
    assert result.score < 35  # campaign threshold would be 35


# ---------------------------------------------------------------------------
# Recovery: Redis becomes available again
# ---------------------------------------------------------------------------


async def test_recovery_after_redis_error():
    """After Redis recovers, analytics signals should be readable again."""
    redis_mock = MagicMock()

    # Make redis.get async
    async def _get_error(key):
        raise ConnectionError("Redis down")

    redis_mock.get.side_effect = _get_error
    pipeline = _make_pipeline(redis_mock)

    # First call — Redis down
    result1 = await pipeline._get_analytics_signals("192.168.5.1")
    assert result1 == []

    # Redis recovers; campaign key is now present
    async def _get_recovered(key):
        if "campaign" in key:
            return b"1"
        return None

    redis_mock.get.side_effect = _get_recovered
    result2 = await pipeline._get_analytics_signals("192.168.5.2")  # same /24
    # Still empty — the first call (success path) was not cached (error path),
    # so this call hits Redis and gets the campaign signal.
    assert any(s.name == "analytics_campaign" for s in result2)


# ---------------------------------------------------------------------------
# Correct score contributions when signals ARE present
# ---------------------------------------------------------------------------


async def test_campaign_signal_score_is_35():
    async def _get(key):
        if "campaign" in key:
            return b"1"
        return None

    redis_mock = MagicMock()
    redis_mock.get.side_effect = _get
    pipeline = _make_pipeline(redis_mock)

    signals = await pipeline._get_analytics_signals("10.1.2.3")
    campaign = next(s for s in signals if s.name == "analytics_campaign")
    assert campaign.score == 35


async def test_slowscan_signal_score_is_30():
    async def _get(key):
        if "slowscan" in key:
            return b"1"
        return None

    redis_mock = MagicMock()
    redis_mock.get.side_effect = _get
    pipeline = _make_pipeline(redis_mock)

    signals = await pipeline._get_analytics_signals("10.2.3.4")
    slowscan = next(s for s in signals if s.name == "analytics_slowscan")
    assert slowscan.score == 30


async def test_both_signals_total_score_is_65():
    """Campaign(35) + subnet_campaign(25) + slowscan(30) = 90 risk score contribution.

    Phase 34 (APT Hardening — subnet correlation) added subnet_campaign(25) as a
    corroborating signal that fires alongside analytics_campaign whenever a campaign
    key is present.  The total is now 35 + 25 + 30 = 90.
    """

    async def _get(key):
        if "campaign" in key or "slowscan" in key:
            return b"1"
        return None

    redis_mock = MagicMock()
    redis_mock.get.side_effect = _get
    pipeline = _make_pipeline(redis_mock)

    signals = await pipeline._get_analytics_signals("172.20.0.1")
    names = {s.name for s in signals}
    assert "analytics_campaign" in names
    assert "subnet_campaign" in names
    assert "analytics_slowscan" in names
    total = sum(s.score for s in signals)
    assert (
        total == 90
    )  # 35 (analytics_campaign) + 25 (subnet_campaign) + 30 (analytics_slowscan)
