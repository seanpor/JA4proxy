"""Unit tests for src/cache/local_cache.py — LRUCache and LocalCache."""

import time
from unittest.mock import patch

import pytest

from src.cache.local_cache import LocalCache, LRUCache


class TestLRUCache:
    """Test LRUCache hit/miss/eviction/TTL behaviour."""

    @pytest.fixture
    def cache(self):
        return LRUCache(max_size=3, ttl_seconds=60, name="test")

    def test_hit_returns_value(self, cache):
        cache.set("k1", "v1")
        assert cache.get("k1") == "v1"

    def test_miss_returns_none(self, cache):
        assert cache.get("nonexistent") is None

    def test_set_and_get_multiple(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.get("a") == 1
        assert cache.get("b") == 2

    def test_overwrite_key(self, cache):
        cache.set("k", "old")
        cache.set("k", "new")
        assert cache.get("k") == "new"
        assert len(cache) == 1

    def test_eviction_drops_lru_entry(self):
        cache = LRUCache(max_size=3, ttl_seconds=60, name="test")
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        # Access "a" to make it recently used; "b" is now LRU
        cache.get("a")
        cache.set("d", 4)  # Should evict "b"
        assert cache.get("b") is None
        assert cache.get("a") == 1
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_lru_eviction_order_insert_only(self):
        cache = LRUCache(max_size=2, ttl_seconds=60, name="test")
        cache.set("first", 1)
        cache.set("second", 2)
        cache.set("third", 3)  # Should evict "first"
        assert cache.get("first") is None
        assert cache.get("second") == 2
        assert cache.get("third") == 3

    def test_ttl_expiry_returns_none(self):
        cache = LRUCache(max_size=10, ttl_seconds=1, name="test")
        cache.set("k", "v")
        # Mock time advancement past TTL
        future = time.monotonic() + 2
        with patch("src.cache.local_cache.time") as mock_time:
            mock_time.monotonic.return_value = future
            assert cache.get("k") is None

    def test_ttl_not_expired_returns_value(self):
        cache = LRUCache(max_size=10, ttl_seconds=60, name="test")
        cache.set("k", "v")
        assert cache.get("k") == "v"

    def test_delete_removes_entry(self, cache):
        cache.set("k", "v")
        cache.delete("k")
        assert cache.get("k") is None

    def test_delete_missing_key_no_error(self, cache):
        cache.delete("does_not_exist")  # Must not raise

    def test_len_tracks_size(self, cache):
        assert len(cache) == 0
        cache.set("a", 1)
        assert len(cache) == 1
        cache.set("b", 2)
        assert len(cache) == 2

    def test_hit_ratio_initially_zero(self, cache):
        assert cache.hit_ratio() == 0.0

    def test_hit_ratio_all_hits(self, cache):
        cache.set("k", "v")
        cache.get("k")
        cache.get("k")
        ratio = cache.hit_ratio()
        assert ratio == 1.0

    def test_hit_ratio_mixed(self, cache):
        cache.set("k", "v")
        cache.get("k")  # hit
        cache.get("miss1")  # miss
        cache.get("miss2")  # miss
        ratio = cache.hit_ratio()
        assert abs(ratio - 1 / 3) < 0.01

    def test_none_value_stored_correctly(self, cache):
        """None is a valid cache value (e.g. cached negative lookup)."""
        # set stores None; get returns None; but we can't distinguish from cache miss
        # that's OK — callers use a sentinel or separate existence check
        cache.set("k", None)
        # Value was set, but get returns None for both miss and None-value
        # The cache still contains the entry (len > 0)
        assert len(cache) == 1


class TestLocalCache:
    """Test LocalCache configuration and dial behaviour."""

    @pytest.fixture
    def default_config(self):
        return {}  # All defaults

    @pytest.fixture
    def custom_config(self):
        return {
            "local_cache": {
                "whitelist_decisions": {"max_size": 100, "ttl_seconds": 900},
                "block_decisions": {"max_size": 200, "ttl_seconds": 10},
                "abuseipdb_scores": {"max_size": 300, "ttl_seconds": 7200},
                "asn_class": {"max_size": 400, "ttl_seconds": 1800},
            }
        }

    def test_default_whitelist_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.whitelist_decisions.ttl_seconds == 1800

    def test_default_block_decisions_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.block_decisions.ttl_seconds == 30

    def test_default_abuseipdb_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.abuseipdb_scores.ttl_seconds == 14400

    def test_default_asn_class_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.asn_class.ttl_seconds == 3600

    def test_default_geoip_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.geoip_country.ttl_seconds == 3600

    def test_default_rdap_ttl(self, default_config):
        cache = LocalCache(default_config)
        assert cache.rdap_data.ttl_seconds == 3600

    def test_custom_whitelist_ttl(self, custom_config):
        cache = LocalCache(custom_config)
        assert cache.whitelist_decisions.ttl_seconds == 900

    def test_custom_block_decisions_ttl(self, custom_config):
        cache = LocalCache(custom_config)
        assert cache.block_decisions.ttl_seconds == 10

    def test_block_ttl_shorter_than_whitelist_ttl(self, default_config):
        """Core asymmetry: block cache must expire much faster than allow cache."""
        cache = LocalCache(default_config)
        assert cache.block_decisions.ttl_seconds < cache.whitelist_decisions.ttl_seconds

    def test_dial_default_is_zero(self, default_config):
        cache = LocalCache(default_config)
        assert cache.dial == 0

    def test_dial_setter_updates_value(self, default_config):
        cache = LocalCache(default_config)
        cache.dial = 50
        assert cache.dial == 50

    def test_dial_clamps_above_100(self, default_config):
        cache = LocalCache(default_config)
        cache.dial = 150
        assert cache.dial == 100

    def test_dial_clamps_below_zero(self, default_config):
        cache = LocalCache(default_config)
        cache.dial = -10
        assert cache.dial == 0

    def test_dial_boundary_100(self, default_config):
        cache = LocalCache(default_config)
        cache.dial = 100
        assert cache.dial == 100

    def test_dial_boundary_0(self, default_config):
        cache = LocalCache(default_config)
        cache.dial = 0
        assert cache.dial == 0

    def test_whitelist_decisions_store_and_retrieve(self, default_config):
        cache = LocalCache(default_config)
        cache.whitelist_decisions.set("1.2.3.4", True)
        assert cache.whitelist_decisions.get("1.2.3.4") is True

    def test_block_decisions_delete_on_ban_release(self, default_config):
        cache = LocalCache(default_config)
        cache.block_decisions.set("ban:1.2.3.4", "banned")
        cache.block_decisions.delete("ban:1.2.3.4")
        assert cache.block_decisions.get("ban:1.2.3.4") is None
