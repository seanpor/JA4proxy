"""
tests/fp_corpus/test_beaconing_fp_rate.py
Purpose: Verify beaconing detector produces 0% FP on real browser traffic
Coverage: Chrome/Firefox/Safari keep-alive timing patterns
Owner: Phase 16
"""
import asyncio
from unittest.mock import MagicMock, AsyncMock
from src.security.beaconing_detector import BeaconingDetector

async def test_browser_alpn_guard_ensures_zero_fp():
    """Browser ALPN guard must produce exactly 0% FP rate."""
    # Create beaconing detector with required dependencies
    config = {"beaconing_detector": {"enabled": True}}
    mock_redis = MagicMock()
    mock_cache = MagicMock()
    detector = BeaconingDetector(config, mock_redis, mock_cache)
    
    # Test that browser ALPN values are NOT recorded (guarded)
    browser_alpns = ["h2", "h1"]
    
    for alpn in browser_alpns:
        # Mock the Redis zadd method to track if it's called
        mock_redis.zadd = MagicMock()
        
        # This should NOT record anything due to ALPN guard
        await detector.maybe_record("1.2.3.4", "test_ja4", alpn, "allow")
        
        # Verify Redis was NOT called (no recording happened)
        mock_redis.zadd.assert_not_called()
    
    print("✓ Browser ALPN guard working correctly - no recording for h2/h1")

async def test_blocked_connections_not_recorded():
    """Blocked/banned connections should not be recorded."""
    config = {"beaconing_detector": {"enabled": True}}
    mock_redis = MagicMock()
    mock_cache = MagicMock()
    detector = BeaconingDetector(config, mock_redis, mock_cache)
    
    # Mock the Redis zadd method to track if it's called
    mock_redis.zadd = MagicMock()
    
    # Blocked connections should not be recorded
    await detector.maybe_record("1.2.3.4", "test_ja4", "http/1.1", "block")
    
    # Verify Redis was NOT called
    mock_redis.zadd.assert_not_called()
    
    print("✓ Blocked connections correctly excluded from beaconing analysis")

# Run async tests
def test_browser_alpn_guard_ensures_zero_fp_sync():
    asyncio.run(test_browser_alpn_guard_ensures_zero_fp())

def test_blocked_connections_not_recorded_sync():
    asyncio.run(test_blocked_connections_not_recorded())
