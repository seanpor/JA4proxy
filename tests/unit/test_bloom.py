"""Unit tests for src/cache/bloom.py — BloomFilter with RedisBloom and SET fallback.

Every test exercises the actual BloomFilter code path.  No test simply
asserts True or checks a default value without going through the logic.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cache.bloom import BloomFilter, _FALLBACK_TTL_SECONDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("_run() should not be called from within an async context")
    except RuntimeError:
        return asyncio.new_event_loop().run_until_complete(coro)


def _make_bloom_redis(
    *,
    bf_reserve_ok=True,
    bf_add_result=1,
    bf_exists_result=0,
    reserve_error=None,
    already_exists=False,
):
    """Build a mock async Redis client with a .bf() sub-client."""
    bf_mock = MagicMock()

    if reserve_error:
        bf_mock.reserve = AsyncMock(side_effect=reserve_error)
    elif already_exists:
        bf_mock.reserve = AsyncMock(side_effect=Exception("item exists"))
    else:
        bf_mock.reserve = AsyncMock(return_value="OK")

    bf_mock.add = AsyncMock(return_value=bf_add_result)
    bf_mock.exists = AsyncMock(return_value=bf_exists_result)

    redis_mock = MagicMock()
    redis_mock.bf = MagicMock(return_value=bf_mock)
    redis_mock.sadd = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=1)
    redis_mock.sismember = AsyncMock(return_value=0)
    return redis_mock, bf_mock


# ---------------------------------------------------------------------------
# initialize() — RedisBloom available
# ---------------------------------------------------------------------------


class TestInitializeBloomAvailable:
    def test_sets_use_bloom_true_on_success(self):
        redis_mock, _ = _make_bloom_redis()
        bf = BloomFilter(redis_mock, "test:filter")
        assert bf._use_bloom is False  # default before initialize
        _run(bf.initialize())
        assert bf._use_bloom is True

    def test_calls_bf_reserve_with_correct_args(self):
        redis_mock, bf_mock = _make_bloom_redis()
        bf = BloomFilter(
            redis_mock, "bloom:rdap_enriched", error_rate=0.005, capacity=500_000
        )
        _run(bf.initialize())
        bf_mock.reserve.assert_called_once_with("bloom:rdap_enriched", 0.005, 500_000)

    def test_already_exists_still_sets_use_bloom_true(self):
        """BF.RESERVE 'item exists' → filter was created before → still use Bloom."""
        redis_mock, bf_mock = _make_bloom_redis(already_exists=True)
        bf = BloomFilter(redis_mock, "bloom:rdap_enriched")
        _run(bf.initialize())
        assert bf._use_bloom is True

    def test_already_exists_variant_casing(self):
        """'Already exists' (capital A) should also be caught."""
        redis_mock, _ = _make_bloom_redis()
        redis_mock.bf().reserve = AsyncMock(side_effect=Exception("Already exists"))
        bf = BloomFilter(redis_mock, "bloom:abuseipdb_enriched")
        _run(bf.initialize())
        assert bf._use_bloom is True


# ---------------------------------------------------------------------------
# initialize() — RedisBloom unavailable (fallback)
# ---------------------------------------------------------------------------


class TestInitializeFallback:
    def test_unavailable_sets_use_bloom_false(self):
        redis_mock, _ = _make_bloom_redis(
            reserve_error=Exception("ERR unknown command 'BF.RESERVE'")
        )
        bf = BloomFilter(redis_mock, "test:filter")
        _run(bf.initialize())
        assert bf._use_bloom is False

    def test_fallback_logs_warning(self, caplog):
        redis_mock, _ = _make_bloom_redis(
            reserve_error=Exception("ERR unknown command 'BF.RESERVE'")
        )
        bf = BloomFilter(redis_mock, "test:filter")
        with caplog.at_level(logging.WARNING, logger="src.cache.bloom"):
            _run(bf.initialize())
        assert any(
            "fallback" in r.message.lower() or "unavailable" in r.message.lower()
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# add() — Bloom path
# ---------------------------------------------------------------------------


class TestAddBloomPath:
    def setup_method(self):
        self.redis_mock, self.bf_mock = _make_bloom_redis(bf_add_result=1)
        self.bf = BloomFilter(self.redis_mock, "bloom:test")
        _run(self.bf.initialize())  # activates Bloom path

    def test_new_item_returns_true(self):
        self.bf_mock.add = AsyncMock(return_value=1)
        assert _run(self.bf.add("1.2.3.4")) is True

    def test_existing_item_returns_false(self):
        self.bf_mock.add = AsyncMock(return_value=0)
        assert _run(self.bf.add("1.2.3.4")) is False

    def test_calls_bf_add_with_correct_args(self):
        _run(self.bf.add("10.0.0.1"))
        self.bf_mock.add.assert_called_with("bloom:test", "10.0.0.1")

    def test_redis_error_returns_false_not_raises(self):
        """Redis failure must not propagate — fail open."""
        self.bf_mock.add = AsyncMock(side_effect=Exception("connection refused"))
        result = _run(self.bf.add("1.2.3.4"))
        assert result is False

    def test_error_logs_warning(self, caplog):
        self.bf_mock.add = AsyncMock(side_effect=Exception("timeout"))
        with caplog.at_level(logging.WARNING, logger="src.cache.bloom"):
            _run(self.bf.add("bad"))
        assert any("add error" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# add() — SET fallback path
# ---------------------------------------------------------------------------


class TestAddFallbackPath:
    def setup_method(self):
        # Initialize with RedisBloom unavailable to activate fallback
        self.redis_mock, _ = _make_bloom_redis(
            reserve_error=Exception("ERR BF.RESERVE not available")
        )
        self.bf = BloomFilter(self.redis_mock, "bloom:rdap_enriched")
        _run(self.bf.initialize())
        assert self.bf._use_bloom is False

    def test_new_item_calls_sadd(self):
        self.redis_mock.sadd = AsyncMock(return_value=1)
        result = _run(self.bf.add("1.1.1.1"))
        self.redis_mock.sadd.assert_called_once_with(
            "bloom_fallback:bloom:rdap_enriched", "1.1.1.1"
        )
        assert result is True

    def test_new_item_sets_ttl(self):
        self.redis_mock.sadd = AsyncMock(return_value=1)
        _run(self.bf.add("1.1.1.1"))
        self.redis_mock.expire.assert_called_once_with(
            "bloom_fallback:bloom:rdap_enriched", _FALLBACK_TTL_SECONDS
        )

    def test_existing_item_returns_false_no_expire_called(self):
        self.redis_mock.sadd = AsyncMock(return_value=0)
        result = _run(self.bf.add("1.1.1.1"))
        assert result is False
        self.redis_mock.expire.assert_not_called()

    def test_sadd_error_returns_false(self):
        self.redis_mock.sadd = AsyncMock(side_effect=Exception("redis down"))
        result = _run(self.bf.add("1.1.1.1"))
        assert result is False


# ---------------------------------------------------------------------------
# contains() — Bloom path
# ---------------------------------------------------------------------------


class TestContainsBloomPath:
    def setup_method(self):
        self.redis_mock, self.bf_mock = _make_bloom_redis()
        self.bf = BloomFilter(self.redis_mock, "bloom:test")
        _run(self.bf.initialize())

    def test_present_item_returns_true(self):
        self.bf_mock.exists = AsyncMock(return_value=1)
        assert _run(self.bf.contains("1.2.3.4")) is True

    def test_absent_item_returns_false(self):
        self.bf_mock.exists = AsyncMock(return_value=0)
        assert _run(self.bf.contains("1.2.3.4")) is False

    def test_calls_bf_exists_with_correct_args(self):
        _run(self.bf.contains("9.9.9.9"))
        self.bf_mock.exists.assert_called_with("bloom:test", "9.9.9.9")

    def test_redis_error_returns_false_triggers_enrichment(self):
        """On error, return False so enrichment is triggered rather than skipped."""
        self.bf_mock.exists = AsyncMock(side_effect=Exception("connection lost"))
        result = _run(self.bf.contains("1.2.3.4"))
        assert result is False

    def test_error_logs_warning(self, caplog):
        self.bf_mock.exists = AsyncMock(side_effect=Exception("timeout"))
        with caplog.at_level(logging.WARNING, logger="src.cache.bloom"):
            _run(self.bf.contains("bad"))
        assert any("contains error" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# contains() — SET fallback path
# ---------------------------------------------------------------------------


class TestContainsFallbackPath:
    def setup_method(self):
        self.redis_mock, _ = _make_bloom_redis(
            reserve_error=Exception("ERR BF.RESERVE not available")
        )
        self.bf = BloomFilter(self.redis_mock, "bloom:abuseipdb_enriched")
        _run(self.bf.initialize())

    def test_present_item_returns_true(self):
        self.redis_mock.sismember = AsyncMock(return_value=1)
        assert _run(self.bf.contains("5.5.5.5")) is True

    def test_absent_item_returns_false(self):
        self.redis_mock.sismember = AsyncMock(return_value=0)
        assert _run(self.bf.contains("5.5.5.5")) is False

    def test_calls_sismember_with_correct_key(self):
        _run(self.bf.contains("5.5.5.5"))
        self.redis_mock.sismember.assert_called_once_with(
            "bloom_fallback:bloom:abuseipdb_enriched", "5.5.5.5"
        )

    def test_sismember_error_returns_false(self):
        self.redis_mock.sismember = AsyncMock(side_effect=Exception("redis down"))
        result = _run(self.bf.contains("5.5.5.5"))
        assert result is False


# ---------------------------------------------------------------------------
# add() before initialize() — defaults to fallback (use_bloom=False)
# ---------------------------------------------------------------------------


class TestAddBeforeInitialize:
    def test_add_before_initialize_uses_fallback_set(self):
        """If initialize() was never called, _use_bloom=False → fallback path."""
        redis_mock = MagicMock()
        redis_mock.sadd = AsyncMock(return_value=1)
        redis_mock.expire = AsyncMock(return_value=1)
        bf = BloomFilter(redis_mock, "bloom:test")
        # Don't call initialize()
        result = _run(bf.add("1.2.3.4"))
        redis_mock.sadd.assert_called_once()
        assert result is True
