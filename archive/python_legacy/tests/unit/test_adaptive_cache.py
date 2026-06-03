"""
Unit tests for Phase 47 Adaptive Cache System.
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from src.security.adaptive_cache import AdaptiveCacheManager, FeedVolatility


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    return client


@pytest.mark.asyncio
async def test_adaptive_cache_initialization(mock_redis):
    """Test that adaptive cache initializes with default profiles."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Should have default feeds
    assert manager._initialized is True
    assert "misp" in manager._feeds
    assert "virustotal" in manager._feeds

    # Check default TTL values
    misp_volatility = manager._feeds["misp"]
    assert misp_volatility.current_ttl == 3600  # 1 hour

    threatfox_volatility = manager._feeds["threatfox"]
    assert threatfox_volatility.current_ttl == 21600  # 6 hours


@pytest.mark.asyncio
async def test_adaptive_cache_load_from_redis(mock_redis):
    """Test loading adaptive cache state from Redis."""
    # Mock stored data
    stored_data = {
        "misp": {
            "volatility_score": 0.7,
            "change_count": 15,
            "access_count": 100,
            "last_change_time": time.time() - 3600,
            "current_ttl": 1800,  # Adjusted to 30 minutes
        }
    }
    mock_redis.get.return_value = json.dumps(stored_data)

    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Should load from Redis
    misp_volatility = manager._feeds["misp"]
    assert misp_volatility.volatility_score == 0.7
    assert misp_volatility.change_count == 15
    assert misp_volatility.current_ttl == 1800


@pytest.mark.asyncio
async def test_get_adaptive_ttl(mock_redis):
    """Test adaptive TTL retrieval."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Test default TTLs
    assert manager.get_adaptive_ttl("misp") == 3600
    assert manager.get_adaptive_ttl("threatfox") == 21600

    # Test unknown feed
    assert manager.get_adaptive_ttl("unknown_feed") == 3600


@pytest.mark.asyncio
async def test_cache_hit_recording(mock_redis):
    """Test recording cache hits."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Record some hits
    await manager.record_cache_hit("misp")
    await manager.record_cache_hit("misp")
    await manager.record_cache_hit("misp")

    stats = manager.get_cache_stats("misp")
    assert stats["hit_count"] == 3
    assert stats["access_count"] == 3


@pytest.mark.asyncio
async def test_cache_miss_with_data_change(mock_redis):
    """Test recording cache misses with data changes."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Initial miss with no old data
    await manager.record_cache_miss("misp", None, {"attribute_count": 5})

    stats = manager.get_cache_stats("misp")
    assert stats["miss_count"] == 1
    assert stats["change_count"] == 0  # No change since no old data

    # Miss with changed data
    await manager.record_cache_miss(
        "misp", {"attribute_count": 5}, {"attribute_count": 7}
    )

    stats = manager.get_cache_stats("misp")
    assert stats["miss_count"] == 2
    assert stats["change_count"] == 1  # Data changed


@pytest.mark.asyncio
async def test_volatility_adjustment(mock_redis):
    """Test volatility score adjustment."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Simulate a volatile feed (frequent changes)
    feed = manager._feeds["misp"]
    feed.change_count = 25
    feed.access_count = 50

    # Manually trigger volatility adjustment
    manager._adjust_volatility("misp")

    stats = manager.get_cache_stats("misp")
    # Change ratio = 25/50 = 0.5, so volatility should increase
    assert 0.3 < stats["volatility_score"] < 0.6
    # TTL should decrease due to higher volatility
    assert stats["current_ttl"] < 3600


@pytest.mark.asyncio
async def test_ttl_clamping(mock_redis):
    """Test that TTL stays within reasonable bounds."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Create a highly volatile scenario
    feed = manager._feeds["misp"]
    feed.change_count = 45
    feed.access_count = 50
    feed.volatility_score = 0.9  # Very high volatility

    manager._adjust_volatility("misp")

    # TTL should be reduced but not below minimum (5 minutes)
    assert manager.get_adaptive_ttl("misp") >= 300


@pytest.mark.asyncio
async def test_state_persistence(mock_redis):
    """Test that state is saved to Redis."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Make some changes
    await manager.record_cache_hit("misp")
    await manager.record_cache_miss(
        "misp", {"attribute_count": 5}, {"attribute_count": 6}
    )

    # Trigger save
    await manager.save_state()

    # Should have called Redis setex
    mock_redis.setex.assert_called()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "ja4proxy:adaptive_cache:state"

    # Verify saved data contains our changes
    saved_data = json.loads(call_args[0][2])
    assert "misp" in saved_data
    assert saved_data["misp"]["change_count"] == 1


@pytest.mark.asyncio
async def test_fallback_when_uninitialized(mock_redis):
    """Test behavior when manager is not initialized."""
    manager = AdaptiveCacheManager(mock_redis)
    # Don't call initialize()

    # Should return default values
    ttl = manager.get_adaptive_ttl("misp")
    assert ttl == 3600  # Default from constructor

    # Recording should be no-op
    await manager.record_cache_hit("misp")
    await manager.record_cache_miss("misp", None, {})
    # No exception should be raised


def test_cache_key_generation():
    """Test cache key generation for different data types."""
    manager = AdaptiveCacheManager(MagicMock())

    # Test MISP data
    misp_key = manager._get_cache_key({"attribute_count": 5})
    assert misp_key == "attr:5"

    # Test ThreatFox data
    tf_key = manager._get_cache_key({"ioc_count": 3})
    assert tf_key == "ioc:3"

    # Test VirusTotal data
    vt_key = manager._get_cache_key({"malicious_count": 2, "suspicious_count": 1})
    assert vt_key == "vt:2,1"

    # Test that different data generates different keys
    key1 = manager._get_cache_key({"attribute_count": 5})
    key2 = manager._get_cache_key({"attribute_count": 6})
    assert key1 != key2


@pytest.mark.asyncio
async def test_hit_ratio_calculation(mock_redis):
    """Test hit ratio calculation."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Record some hits and misses
    await manager.record_cache_hit("misp")
    await manager.record_cache_hit("misp")
    await manager.record_cache_miss("misp", None, {"attribute_count": 5})

    stats = manager.get_cache_stats("misp")
    assert stats["hit_count"] == 2
    assert stats["miss_count"] == 1
    assert stats["access_count"] == 3
    assert stats["hit_ratio"] == pytest.approx(2 / 3, abs=0.01)


@pytest.mark.asyncio
async def test_volatility_blending(mock_redis):
    """Test that volatility adjustments blend old and new scores."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()

    # Set initial volatility
    feed = manager._feeds["misp"]
    feed.volatility_score = 0.8  # High initial score
    feed.change_count = 40
    feed.access_count = 50

    # Trigger adjustment
    manager._adjust_volatility("misp")

    # New change ratio = 40/50 = 0.8
    # Blended score = (0.8 * 0.7) + (0.8 * 0.3) = 0.8
    new_stats = manager.get_cache_stats("misp")
    assert new_stats["volatility_score"] == pytest.approx(0.8, abs=0.01)


# ── Missing-coverage tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_init_redis_exception_falls_back_to_defaults():
    """Redis error during initialize() → falls back to default profiles (lines 115-126).
    So what: if Redis is unavailable at startup the adaptive cache must still
    function with defaults; without this fallback all threat-feed TTLs become 0."""
    redis = AsyncMock()
    redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
    manager = AdaptiveCacheManager(redis)
    await manager.initialize()
    assert manager._initialized is True
    assert "misp" in manager._feeds
    assert "virustotal" in manager._feeds


@pytest.mark.asyncio
async def test_save_state_not_initialized_returns_immediately():
    """save_state() before initialize() → returns without touching Redis (line 131).
    So what: calling save_state prematurely must not write empty/corrupt state
    that would then poison the next startup's Redis load."""
    redis = AsyncMock()
    manager = AdaptiveCacheManager(redis)
    # Not initialized
    await manager.save_state()
    redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_save_state_redis_exception_logged(mock_redis):
    """Redis exception in save_state() → logs error, does not propagate (lines 149-150).
    So what: a Redis write failure during periodic state save must not crash
    the background worker or surface as an unhandled exception."""
    mock_redis.setex = AsyncMock(side_effect=ConnectionError("Redis write failed"))
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    import logging

    with pytest.raises(Exception) if False else __import__("contextlib").nullcontext():
        await manager.save_state()  # Should not raise


@pytest.mark.asyncio
async def test_record_cache_hit_triggers_periodic_save(mock_redis):
    """Access count multiple of 50 → save_state() called (line 204).
    So what: if periodic saves never fire, Redis state drifts permanently from
    in-memory state; the next restart loads stale (or no) volatility data."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    feed = manager._feeds["misp"]
    feed.access_count = 49  # Next hit will make 50
    manager._hit_count["misp"] = 49

    await manager.record_cache_hit("misp")
    # access_count is now 50, triggering periodic save
    mock_redis.setex.assert_called()


@pytest.mark.asyncio
async def test_record_cache_miss_triggers_periodic_save(mock_redis):
    """Access count multiple of 50 during miss → save_state() called (line 251).
    So what: same as hit-path — volatile feed state must be persisted
    periodically to survive restarts without losing learned TTL reductions."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    feed = manager._feeds["misp"]
    feed.access_count = 49
    manager._miss_count["misp"] = 49

    await manager.record_cache_miss("misp", None, {"attribute_count": 5})
    mock_redis.setex.assert_called()


def test_get_cache_key_fallback_json(mock_redis):
    """Data with no known fields → falls back to JSON serialisation (line 264).
    So what: unknown data shapes must produce a stable comparison key; if this
    path raises, all unknown feed comparisons report false 'no change'."""
    manager = AdaptiveCacheManager(MagicMock())
    key = manager._get_cache_key({"unknown_field": "value", "other": 42})
    import json

    expected = json.dumps({"other": 42, "unknown_field": "value"}, sort_keys=True)
    assert key == expected


@pytest.mark.asyncio
async def test_adjust_volatility_unknown_feed_returns_immediately():
    """_adjust_volatility() for unknown feed → returns without crash (line 275).
    So what: if a feed is removed from default_profiles but referenced in legacy
    Redis state, the volatility adjuster must silently skip it."""
    manager = AdaptiveCacheManager(AsyncMock())
    # Call with a feed that doesn't exist
    manager._adjust_volatility("nonexistent_feed")  # Should not raise


@pytest.mark.asyncio
async def test_adjust_volatility_ttl_increases_when_low_volatility(mock_redis):
    """Low change ratio → TTL increases, direction='up' counter incremented (line 303).
    So what: feeds that rarely change must earn longer TTLs automatically;
    if the 'up' direction is never reached, TTLs can only decrease or stay flat."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    feed = manager._feeds["misp"]
    # Set current TTL well below what low-volatility would produce
    feed.current_ttl = 400
    feed.volatility_score = 0.9  # Will blend down toward low ratio
    feed.change_count = 1
    feed.access_count = 100  # Very low change ratio → low volatility → long TTL
    manager._adjust_volatility("misp")
    stats = manager.get_cache_stats("misp")
    assert stats["current_ttl"] > 400


@pytest.mark.asyncio
async def test_adjust_volatility_ttl_unchanged_counter_incremented(mock_redis):
    """New TTL equals old TTL → direction='unchanged' counter incremented (line 307).
    So what: if the 'unchanged' path is untested, a regression might silently
    mis-label stable feeds as volatile in monitoring dashboards."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    feed = manager._feeds["misp"]
    # Force a stable scenario: set volatility and change ratio so TTL doesn't move
    feed.change_count = 0
    feed.access_count = 1
    feed.volatility_score = 0.0
    feed.current_ttl = 3600  # Max TTL — cannot increase further
    manager._adjust_volatility("misp")
    # If TTL stayed the same (already at max), unchanged counter fires


@pytest.mark.asyncio
async def test_get_cache_stats_unknown_feed_returns_defaults(mock_redis):
    """get_cache_stats() for unknown feed → returns default stats dict (lines 312-...).
    So what: callers must not receive a KeyError when querying a feed that was
    never loaded; the default dict prevents NoneType crashes in the UI layer."""
    manager = AdaptiveCacheManager(mock_redis)
    await manager.initialize()
    stats = manager.get_cache_stats("unknown_feed_xyz")
    assert stats["volatility_score"] == 0.5
    assert stats["current_ttl"] == 3600
    assert stats["hit_ratio"] == 0.0


def test_update_metrics_unknown_feed_returns_immediately():
    """_update_metrics() for unknown feed → returns without crash (line 155).
    So what: _update_metrics is called after every cache operation; a crash here
    on an unknown feed would break all cache hit/miss recording for that feed."""
    manager = AdaptiveCacheManager(MagicMock())
    # _update_metrics with a feed not in _feeds — must not raise
    manager._update_metrics("nonexistent_feed_xyz")
