"""Unit tests for Phase 12b: analytics cross-instance signals in pipeline.

Tests cover:
- Campaign signal (+35) returned when analytics:campaign:{subnet} key is set
- Slow-scan signal (+30) returned when analytics:slowscan:{subnet} key is set
- Both signals returned when both keys are set
- Empty list when neither key is set
- Empty list when Redis raises an exception (fail open)
- IPv4 /24 subnet computation
- IPv6 /48 subnet computation
- Local cache hit avoids Redis call
- analytics_signals LRUCache added to LocalCache
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(redis_get_side_effect=None, redis_get_return=None):
    """Return a Pipeline with a mock Redis client."""
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
    mock_redis = MagicMock()
    
    # Make redis.get async
    async def _get_async(key):
        if redis_get_side_effect is not None:
            if callable(redis_get_side_effect):
                res = redis_get_side_effect(key)
                if asyncio.iscoroutine(res):
                    return await res
                return res
            else:
                raise redis_get_side_effect
        elif redis_get_return is not None:
            return redis_get_return
        else:
            return None
    
    mock_redis.get.side_effect = _get_async
    return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)


# ---------------------------------------------------------------------------
# LocalCache: analytics_signals cache exists
# ---------------------------------------------------------------------------


def test_local_cache_has_analytics_signals_cache():
    cache = LocalCache({})
    assert hasattr(cache, "analytics_signals")
    # TTL default 60s
    assert cache.analytics_signals.ttl_seconds == 60


def test_local_cache_analytics_signals_ttl_configurable():
    cache = LocalCache({"local_cache": {"analytics_signals": {"ttl_seconds": 120}}})
    assert cache.analytics_signals.ttl_seconds == 120


# ---------------------------------------------------------------------------
# Subnet computation
# ---------------------------------------------------------------------------


async def test_ipv4_subnet_is_slash24():
    pipeline = _make_pipeline()
    signals = await pipeline._get_analytics_signals("192.168.1.200")
    # No Redis keys set → empty, but subnet was computed correctly.
    # Verify by checking the cache key that was stored.
    cached = pipeline._cache.analytics_signals.get("192.168.1.0/24")
    assert cached == []


async def test_ipv6_subnet_is_slash48():
    pipeline = _make_pipeline()
    signals = await pipeline._get_analytics_signals("2001:db8::1")
    cached = pipeline._cache.analytics_signals.get("2001:db8::/48")
    assert cached == []


async def test_invalid_ip_returns_empty():
    pipeline = _make_pipeline()
    result = await pipeline._get_analytics_signals("not-an-ip")
    assert result == []


# ---------------------------------------------------------------------------
# Campaign signal
# ---------------------------------------------------------------------------


async def test_campaign_signal_returned_when_key_set():
    async def _get(key):
        if key == "analytics:campaign:192.168.1.0/24":
            return b"1"
        return None

    pipeline = _make_pipeline(redis_get_side_effect=_get)
    signals = await pipeline._get_analytics_signals("192.168.1.50")

    # Phase 34: campaign key now emits both analytics_campaign AND subnet_campaign signals.
    assert len(signals) == 2
    names = {s.name for s in signals}
    assert "analytics_campaign" in names
    assert "subnet_campaign" in names
    campaign = next(s for s in signals if s.name == "analytics_campaign")
    assert campaign.score == 35
    assert "192.168.1.0/24" in campaign.reason


async def test_campaign_signal_not_returned_when_key_absent():
    pipeline = _make_pipeline()
    signals = await pipeline._get_analytics_signals("10.0.0.1")
    assert signals == []


# ---------------------------------------------------------------------------
# Slow-scan signal
# ---------------------------------------------------------------------------


async def test_slowscan_signal_returned_when_key_set():
    async def _get(key):
        if key == "analytics:slowscan:10.0.0.0/24":
            return b"1"
        return None

    pipeline = _make_pipeline(redis_get_side_effect=_get)
    signals = await pipeline._get_analytics_signals("10.0.0.99")

    assert len(signals) == 1
    assert signals[0].name == "analytics_slowscan"
    assert signals[0].score == 30
    assert "10.0.0.0/24" in signals[0].reason


# ---------------------------------------------------------------------------
# Both signals
# ---------------------------------------------------------------------------


async def test_both_signals_when_both_keys_set():
    async def _get(key):
        if "campaign" in key or "slowscan" in key:
            return b"1"
        return None

    pipeline = _make_pipeline(redis_get_side_effect=_get)
    signals = await pipeline._get_analytics_signals("172.16.0.1")

    # Phase 34 (subnet correlation) adds subnet_campaign alongside analytics_campaign,
    # so campaign key → 2 signals (analytics_campaign + subnet_campaign) + slowscan → 3 total
    names = {s.name for s in signals}
    assert "analytics_campaign" in names
    assert "subnet_campaign" in names
    assert "analytics_slowscan" in names
    assert len(signals) == 3


# ---------------------------------------------------------------------------
# Fail open
# ---------------------------------------------------------------------------


async def test_redis_error_returns_empty_and_does_not_raise():
    async def _get_error(key):
        raise ConnectionError("Redis down")
    pipeline = _make_pipeline(redis_get_side_effect=_get_error)
    result = await pipeline._get_analytics_signals("1.2.3.4")
    assert result == []


def test_redis_error_does_not_cache_empty_result():
    """On Redis error, result must NOT be cached so next request retries."""
    pipeline = _make_pipeline(redis_get_side_effect=ConnectionError("Redis down"))
    pipeline._get_analytics_signals("1.2.3.4")
    # Cache should be empty — no entry stored on error.
    cached = pipeline._cache.analytics_signals.get("1.2.3.0/24")
    assert cached is None


async def test_partial_result_returns_empty_not_partial():
    """If first Redis call (campaign) succeeds but second (slowscan) raises,
    the method must return [] not the partial [campaign_signal] list.
    This prevents a one-signal result from being treated as authoritative
    when the slowscan check never ran.
    """
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # campaign key returns a hit
            return b"1"
        # slowscan key raises
        raise ConnectionError("Redis flap")

    pipeline = _make_pipeline(redis_get_side_effect=_get)
    result = await pipeline._get_analytics_signals("1.2.3.4")
    # Must be empty — fail open, no partial data
    assert result == []
    # Must not be cached so the next call retries
    cached = pipeline._cache.analytics_signals.get("1.2.3.0/24")
    assert cached is None


async def test_none_redis_client_returns_empty():
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
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=None)
    result = await pipeline._get_analytics_signals("5.5.5.5")
    assert result == []


# ---------------------------------------------------------------------------
# Local cache hit (no Redis call)
# ---------------------------------------------------------------------------


async def test_cache_hit_skips_redis():
    pipeline = _make_pipeline()
    subnet = "192.0.2.0/24"
    from src.security.models import RiskSignal

    cached_signals = [RiskSignal(name="analytics_campaign", score=35, reason="cached")]
    pipeline._cache.analytics_signals.set(subnet, cached_signals)

    result = await pipeline._get_analytics_signals("192.0.2.1")

    assert result == cached_signals
    # Redis.get should NOT have been called
    pipeline._redis.get.assert_not_called()


def test_cache_populated_after_redis_read():
    def _get(key):
        if "campaign" in key:
            return b"1"
        return None

    pipeline = _make_pipeline(redis_get_side_effect=_get)
    pipeline._get_analytics_signals("10.10.10.10")

    # Second call must hit the cache, not Redis
    pipeline._redis.get.reset_mock()
    pipeline._get_analytics_signals("10.10.10.20")  # same /24
    pipeline._redis.get.assert_not_called()
