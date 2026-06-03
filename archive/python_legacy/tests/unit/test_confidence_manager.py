"""
Unit tests for Phase 47 Confidence Manager.
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.security.confidence_manager import ConfidenceManager, FeedConfidence


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    return client


@pytest.mark.asyncio
async def test_confidence_manager_initialization(mock_redis):
    """Test that confidence manager initializes with default values."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Should have default feeds
    assert manager._initialized is True
    assert "misp" in manager._feeds
    assert "virustotal" in manager._feeds

    # Check default confidence values
    misp_confidence = manager._feeds["misp"]
    assert misp_confidence.accuracy_score == 0.9


@pytest.mark.asyncio
async def test_confidence_manager_load_from_redis(mock_redis):
    """Test loading confidence state from Redis."""
    # Mock stored data
    stored_data = {
        "misp": {
            "accuracy_score": 0.95,
            "true_positives": 100,
            "false_positives": 5,
            "last_updated": time.time() - 3600,
            "manual_override": None,
        }
    }
    mock_redis.get.return_value = json.dumps(stored_data)

    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Should load from Redis
    misp_confidence = manager._feeds["misp"]
    assert misp_confidence.accuracy_score == 0.95
    assert misp_confidence.true_positives == 100
    assert misp_confidence.false_positives == 5


@pytest.mark.asyncio
async def test_get_confidence_weight(mock_redis):
    """Test confidence weight calculation."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Test default weights
    assert manager.get_confidence_weight("misp") == 0.9 * 1.0 + 0.5  # 0.5 + (0.9 * 1.0)
    assert manager.get_confidence_weight("virustotal") == 0.95 * 1.0 + 0.5

    # Test unknown feed
    assert manager.get_confidence_weight("unknown_feed") == 1.0


@pytest.mark.asyncio
async def test_record_validation(mock_redis):
    """Test recording validation events."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Record some validations
    await manager.record_validation("misp", is_true_positive=True)  # TP
    await manager.record_validation("misp", is_true_positive=True)  # TP
    await manager.record_validation("misp", is_true_positive=False)  # FP

    stats = manager.get_feed_stats("misp")
    assert stats["true_positives"] == 2
    assert stats["false_positives"] == 1
    assert stats["accuracy_score"] > 0.5  # Should be 2/3 = 0.666...


@pytest.mark.asyncio
async def test_manual_override(mock_redis):
    """Test manual confidence override."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Set manual override
    await manager.set_manual_override("misp", 1.2)

    stats = manager.get_feed_stats("misp")
    assert stats["manual_override"] == 1.2
    assert stats["effective_weight"] == 1.2

    # Clear override
    await manager.clear_manual_override("misp")
    stats = manager.get_feed_stats("misp")
    assert stats["manual_override"] is None


@pytest.mark.asyncio
async def test_confidence_adjustment_blending(mock_redis):
    """Test that confidence adjustments blend old and new scores."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Start with a feed that has some history
    feed = manager._feeds["misp"]
    feed.true_positives = 10
    feed.false_positives = 0
    feed.accuracy_score = 1.0  # Perfect so far

    # Add a false positive
    await manager.record_validation("misp", is_true_positive=False)

    # Score should blend: (1.0 * 0.8) + (0.909 * 0.2) ≈ 0.9818
    stats = manager.get_feed_stats("misp")
    assert 0.95 < stats["accuracy_score"] < 1.0


@pytest.mark.asyncio
async def test_state_persistence(mock_redis):
    """Test that state is saved to Redis."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Make some changes
    await manager.record_validation("misp", is_true_positive=True)
    await manager.set_manual_override("virustotal", 1.1)

    # Trigger save
    await manager.save_state()

    # Should have called Redis setex
    mock_redis.setex.assert_called()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "ja4proxy:confidence:state"

    # Verify saved data contains our changes
    saved_data = json.loads(call_args[0][2])
    assert "misp" in saved_data
    assert "virustotal" in saved_data
    assert saved_data["virustotal"]["manual_override"] == 1.1


@pytest.mark.asyncio
async def test_weight_clamping(mock_redis):
    """Test that weights are properly clamped to 0.5-1.5 range."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Test manual override clamping
    await manager.set_manual_override("misp", 2.0)  # Too high
    assert manager.get_confidence_weight("misp") == 1.5

    await manager.set_manual_override("misp", 0.1)  # Too low
    assert manager.get_confidence_weight("misp") == 0.5


@pytest.mark.asyncio
async def test_fallback_when_uninitialized(mock_redis):
    """Test behavior when manager is not initialized."""
    manager = ConfidenceManager(mock_redis)
    # Don't call initialize()

    # Should return default values
    weight = manager.get_confidence_weight("misp")
    assert weight == 0.9  # Default from constructor

    # Validation should be no-op
    await manager.record_validation("misp", is_true_positive=True)
    # No exception should be raised


def test_feed_stats(mock_redis):
    """Test get_feed_stats method."""
    manager = ConfidenceManager(mock_redis)

    # Test with unknown feed
    stats = manager.get_feed_stats("unknown")
    assert stats["accuracy_score"] == 1.0
    assert stats["effective_weight"] == 1.0


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_redis_error_falls_back_to_defaults(mock_redis):
    """Redis error during initialize() falls back to defaults (lines 101-109).
    So what: if the fallback is broken, a Redis outage at startup leaves all
    feeds with zero confidence weight, silently disabling all TI signals."""
    mock_redis.get.side_effect = Exception("Redis down")

    manager = ConfidenceManager(mock_redis)
    await manager.initialize()  # must not raise

    assert manager._initialized is True
    # Default feeds must be populated from _default_confidence
    assert "misp" in manager._feeds
    assert manager._feeds["misp"].accuracy_score == 0.9


@pytest.mark.asyncio
async def test_save_state_not_initialized_returns_early(mock_redis):
    """save_state() before initialize() returns immediately (line 114).
    So what: calling save_state() before init must not crash or write garbage
    state to Redis, which would corrupt future load."""
    manager = ConfidenceManager(mock_redis)
    # Do NOT call initialize()

    await manager.save_state()
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_save_state_redis_error_swallowed(mock_redis):
    """Redis error in save_state() is logged and swallowed (lines 132-133).
    So what: a Redis outage during periodic save must not propagate to the
    caller — persistence failures are non-fatal."""
    mock_redis.setex.side_effect = Exception("Redis write failed")

    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    await manager.save_state()  # must not raise


@pytest.mark.asyncio
async def test_record_validation_creates_new_feed_entry(mock_redis):
    """record_validation() for unknown feed creates FeedConfidence (line 182).
    So what: a new feed getting its first validation must not KeyError — silently
    dropping the record would prevent confidence from building for that feed."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    # Feed not previously known
    await manager.record_validation("brand_new_feed", is_true_positive=True)
    assert "brand_new_feed" in manager._feeds
    assert manager._feeds["brand_new_feed"].true_positives == 1


@pytest.mark.asyncio
async def test_record_validation_periodic_save_triggered(mock_redis):
    """save_state() is called every 10 validations (line 215).
    So what: without periodic saves, a crash between explicit saves loses all
    confidence state, resetting every feed to defaults on restart."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()
    mock_redis.setex.reset_mock()

    # Record 10 validations → triggers save at total=10
    for _ in range(10):
        await manager.record_validation("misp", is_true_positive=True)

    mock_redis.setex.assert_called()


@pytest.mark.asyncio
async def test_set_manual_override_creates_new_feed_entry(mock_redis):
    """set_manual_override() for unknown feed creates FeedConfidence (line 226).
    So what: a manual override on an unseen feed must not KeyError — the secops
    operator must be able to pin confidence for any feed at any time."""
    manager = ConfidenceManager(mock_redis)
    await manager.initialize()

    await manager.set_manual_override("unknown_new_feed", 1.3)
    assert "unknown_new_feed" in manager._feeds
    assert manager._feeds["unknown_new_feed"].manual_override == 1.3
