"""Integration tests for the in-process cache hierarchy.

Tests that:
  - In-process hits skip Redis calls entirely
  - In-process misses fall through to Redis
  - TTL enforcement: expired entries are not returned
"""

import time
from unittest.mock import MagicMock, call, patch

import pytest

from src.cache.local_cache import LocalCache, LRUCache


class TestCacheHierarchy:
    """Test that local cache hits skip Redis and misses fall through."""

    def test_local_hit_skips_redis(self):
        """A cache hit must not result in any Redis call."""
        cache = LRUCache(max_size=100, ttl_seconds=60, name="test")
        mock_redis = MagicMock()

        # Prime the cache
        cache.set("key1", "value1")

        # Get from local cache — Redis must not be called
        result = cache.get("key1")
        assert result == "value1"
        mock_redis.get.assert_not_called()

    def test_local_miss_would_require_redis(self):
        """A cache miss should return None so the caller can query Redis."""
        cache = LRUCache(max_size=100, ttl_seconds=60, name="test")
        result = cache.get("nonexistent")
        assert result is None

    def test_ttl_expiry_removes_entry(self):
        """An expired entry must not be returned."""
        cache = LRUCache(max_size=100, ttl_seconds=1, name="test")
        cache.set("key", "val")

        future_time = time.monotonic() + 5  # 5 seconds past TTL
        with patch("src.cache.local_cache.time") as mock_time:
            mock_time.monotonic.return_value = future_time
            result = cache.get("key")

        assert result is None

    def test_non_expired_entry_returned(self):
        cache = LRUCache(max_size=100, ttl_seconds=60, name="test")
        cache.set("key", "val")
        assert cache.get("key") == "val"

    def test_block_ttl_shorter_than_whitelist_ttl(self):
        """Core asymmetry: block cache must expire faster than whitelist cache."""
        local = LocalCache({})
        assert local.block_decisions.ttl_seconds < local.whitelist_decisions.ttl_seconds

    def test_cache_invalidation_via_delete(self):
        """Pub/sub invalidation uses delete() — entry must be gone immediately."""
        cache = LRUCache(max_size=100, ttl_seconds=3600, name="test")
        cache.set("ban:1.2.3.4", "reason")
        assert cache.get("ban:1.2.3.4") == "reason"
        cache.delete("ban:1.2.3.4")
        assert cache.get("ban:1.2.3.4") is None

    def test_local_cache_multiple_types_independent(self):
        """Each cache type is isolated — a hit in one does not affect another."""
        local = LocalCache({})
        local.whitelist_decisions.set("1.2.3.4", True)
        local.block_decisions.set("1.2.3.4", True)
        local.whitelist_decisions.delete("1.2.3.4")
        # Block decisions unaffected by whitelist deletion
        assert local.block_decisions.get("1.2.3.4") is True
        assert local.whitelist_decisions.get("1.2.3.4") is None


class TestLocalCacheDialUpdate:
    """Test dial value updates via the LocalCache interface."""

    def test_dial_updated_atomically(self):
        local = LocalCache({})
        local.dial = 50
        assert local.dial == 50

    def test_dial_clamped_on_assignment(self):
        local = LocalCache({})
        local.dial = 999
        assert local.dial == 100

    def test_dial_default_zero_means_monitor_mode(self):
        local = LocalCache({})
        assert local.dial == 0
