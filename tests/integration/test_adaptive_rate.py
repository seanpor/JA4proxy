"""Integration tests for Phase 16h — Adaptive Rate Limiting.

Tests the full pipeline:
- AdaptiveRateComputer.compute_and_publish() writes rate:adaptive:{subnet} to Redis
- SecurityManager._get_adaptive_rate_threshold() reads and applies the data
- Confidence gate: confidence < 0.7 → fallback to static config
- Key eviction: Redis returns nothing → fallback to static config
- Disabled path: adaptive.enabled=false → _get_adaptive_rate_threshold not consulted

All tests are in-process using a shared async dict as a fake Redis store.
No Docker or network required.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analytics.aggregation import AdaptiveRateComputer


# ---------------------------------------------------------------------------
# Shared in-memory Redis stub
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal async Redis stub backed by a plain dict.

    Supports only the operations used by AdaptiveRateComputer and
    SecurityManager._get_adaptive_rate_threshold.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[bytes, bytes]] = {}
        self._ttls: dict[str, int] = {}

    async def hset(self, key: str, mapping: dict[str, str]) -> None:
        self._store[key] = {k.encode(): v.encode() for k, v in mapping.items()}

    async def expire(self, key: str, ttl: int) -> None:
        self._ttls[key] = ttl

    async def hgetall(self, key: str) -> dict[bytes, bytes]:
        return dict(self._store.get(key, {}))

    async def incr(self, key: str) -> int:
        return 1

    def evict(self, key: str) -> None:
        """Simulate TTL expiration."""
        self._store.pop(key, None)
        self._ttls.pop(key, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_security_manager(config: dict | None = None) -> Any:
    """Return a SecurityManager stub with the given config."""
    from proxy import SecurityManager  # type: ignore[import]

    default_config = {
        "security": {"max_requests_per_minute": 100, "rate_limit_window": 60},
        "rate_limiter": {
            "adaptive": {
                "enabled": True,
                "min_threshold_rps": 5,
                "max_threshold_rps": 1000,
            }
        },
    }
    if config:
        # Deep-merge override
        for k, v in config.items():
            if isinstance(v, dict) and k in default_config:
                default_config[k].update(v)
            else:
                default_config[k] = v

    fake_redis = _FakeRedis()
    sm = SecurityManager(default_config, fake_redis)
    return sm, fake_redis


# ---------------------------------------------------------------------------
# Test: full publish → read path
# ---------------------------------------------------------------------------


class TestAdaptiveRatePublishReadIntegration:
    """AdaptiveRateComputer publishes; SecurityManager reads the same key."""

    @pytest.mark.asyncio
    async def test_published_threshold_used_by_proxy(self) -> None:
        """Compute+publish a high-confidence threshold; proxy uses it, not static."""
        sm, fake_redis = _make_security_manager()

        computer = AdaptiveRateComputer(
            min_threshold_rps=5,
            max_threshold_rps=1000,
            window_seconds=1,
        )
        # Record 20 events for the subnet → EWMA ≈ 20/1s = 20 rps → threshold = 40
        for _ in range(20):
            computer.record_event("192.168.1.0")

        # Manually advance windows to push confidence above 0.7
        # confidence = 1 - 1/(1 + windows); for confidence >= 0.7 need windows >= 3
        for _ in range(5):
            computer._rotate()
            for _ in range(20):
                computer.record_event("192.168.1.0")

        published = await computer.compute_and_publish(fake_redis)
        assert published == 1

        # Check Redis key was written
        key = "rate:adaptive:192.168.1.0"
        data = await fake_redis.hgetall(key)
        assert b"confidence" in data
        assert float(data[b"confidence"]) >= 0.7

        # Now let the proxy read the adaptive threshold for 192.168.1.1 (/24 = .0)
        threshold = await sm._get_adaptive_rate_threshold("192.168.1.1")
        # Should NOT be the static 100 — should be the adaptive threshold (clamped)
        assert threshold != 100

    @pytest.mark.asyncio
    async def test_adaptive_threshold_clamped_to_min(self) -> None:
        """Threshold below min_threshold_rps is clamped up."""
        sm, fake_redis = _make_security_manager(
            {"rate_limiter": {"adaptive": {"enabled": True, "min_threshold_rps": 50, "max_threshold_rps": 1000}}}
        )

        # Inject a key with very low threshold but high confidence directly
        await fake_redis.hset(
            "rate:adaptive:10.0.0.0",
            {"threshold_rps": "3", "confidence": "0.95", "ewma_rps": "1.5", "windows": "10"},
        )

        threshold = await sm._get_adaptive_rate_threshold("10.0.0.1")
        assert threshold == 50  # clamped to min

    @pytest.mark.asyncio
    async def test_adaptive_threshold_clamped_to_max(self) -> None:
        """Threshold above max_threshold_rps is clamped down."""
        sm, fake_redis = _make_security_manager(
            {"rate_limiter": {"adaptive": {"enabled": True, "min_threshold_rps": 5, "max_threshold_rps": 200}}}
        )

        await fake_redis.hset(
            "rate:adaptive:172.16.1.0",
            {"threshold_rps": "9999", "confidence": "0.99", "ewma_rps": "4999", "windows": "20"},
        )

        threshold = await sm._get_adaptive_rate_threshold("172.16.1.1")
        assert threshold == 200  # clamped to max


# ---------------------------------------------------------------------------
# Test: confidence gate
# ---------------------------------------------------------------------------


class TestAdaptiveRateConfidenceGate:
    """Low confidence → fallback to static; high confidence → adaptive used."""

    @pytest.mark.asyncio
    async def test_low_confidence_falls_back_to_static(self) -> None:
        """confidence < 0.7 → static threshold (100) returned."""
        sm, fake_redis = _make_security_manager()

        # Inject key with low confidence
        await fake_redis.hset(
            "rate:adaptive:1.2.3.0",
            {"threshold_rps": "25", "confidence": "0.5", "ewma_rps": "12", "windows": "1"},
        )

        threshold = await sm._get_adaptive_rate_threshold("1.2.3.4")
        assert threshold == 100  # static fallback

    @pytest.mark.asyncio
    async def test_high_confidence_uses_adaptive_threshold(self) -> None:
        """confidence >= 0.7 → adaptive threshold returned."""
        sm, fake_redis = _make_security_manager()

        await fake_redis.hset(
            "rate:adaptive:1.2.3.0",
            {"threshold_rps": "42", "confidence": "0.85", "ewma_rps": "21", "windows": "6"},
        )

        threshold = await sm._get_adaptive_rate_threshold("1.2.3.4")
        assert threshold == 42

    @pytest.mark.asyncio
    async def test_exact_boundary_confidence_uses_adaptive(self) -> None:
        """confidence == 0.7 exactly → adaptive threshold returned (boundary inclusive)."""
        sm, fake_redis = _make_security_manager()

        await fake_redis.hset(
            "rate:adaptive:5.6.7.0",
            {"threshold_rps": "60", "confidence": "0.7000", "ewma_rps": "30", "windows": "3"},
        )

        threshold = await sm._get_adaptive_rate_threshold("5.6.7.8")
        assert threshold == 60


# ---------------------------------------------------------------------------
# Test: Redis key eviction / missing key
# ---------------------------------------------------------------------------


class TestAdaptiveRateKeyEviction:
    """If the Redis key is missing or evicted, proxy falls back to static config."""

    @pytest.mark.asyncio
    async def test_missing_key_falls_back_to_static(self) -> None:
        """No key in Redis → returns static max_requests_per_minute."""
        sm, fake_redis = _make_security_manager()
        threshold = await sm._get_adaptive_rate_threshold("9.9.9.9")
        assert threshold == 100

    @pytest.mark.asyncio
    async def test_evicted_key_falls_back_to_static(self) -> None:
        """Key present, then evicted → returns static threshold."""
        sm, fake_redis = _make_security_manager()

        await fake_redis.hset(
            "rate:adaptive:9.9.9.0",
            {"threshold_rps": "75", "confidence": "0.9", "ewma_rps": "37", "windows": "8"},
        )
        # Confirm it was picked up
        threshold_before = await sm._get_adaptive_rate_threshold("9.9.9.1")
        assert threshold_before == 75

        # Simulate TTL expiration
        fake_redis.evict("rate:adaptive:9.9.9.0")

        threshold_after = await sm._get_adaptive_rate_threshold("9.9.9.1")
        assert threshold_after == 100  # fallback to static

    @pytest.mark.asyncio
    async def test_redis_exception_falls_back_to_static(self) -> None:
        """Redis.hgetall raises an exception → fallback to static (fail-open)."""
        from proxy import SecurityManager  # type: ignore[import]

        config = {
            "security": {"max_requests_per_minute": 100, "rate_limit_window": 60},
            "rate_limiter": {"adaptive": {"enabled": True}},
        }
        broken_redis = MagicMock()
        broken_redis.hgetall = AsyncMock(side_effect=ConnectionError("Redis down"))
        sm = SecurityManager(config, broken_redis)

        threshold = await sm._get_adaptive_rate_threshold("1.1.1.1")
        assert threshold == 100


# ---------------------------------------------------------------------------
# Test: disabled path
# ---------------------------------------------------------------------------


class TestAdaptiveRateDisabledConfig:
    """When adaptive.enabled=false, _get_adaptive_rate_threshold is never called."""

    @pytest.mark.asyncio
    async def test_disabled_uses_static_threshold(self) -> None:
        """adaptive.enabled=false → _check_rate_limit uses static max_requests_per_minute."""
        from proxy import SecurityManager  # type: ignore[import]

        config = {
            "security": {"max_requests_per_minute": 77, "rate_limit_window": 60},
            "rate_limiter": {"adaptive": {"enabled": False}},
        }
        fake_redis = _FakeRedis()
        # Inject an adaptive key — should NOT be consulted
        await fake_redis.hset(
            "rate:adaptive:2.3.4.0",
            {"threshold_rps": "10", "confidence": "0.99", "ewma_rps": "5", "windows": "10"},
        )
        # Also mock incr/expire for rate limit check
        fake_redis_mock = MagicMock()
        fake_redis_mock.incr = AsyncMock(return_value=1)
        fake_redis_mock.expire = AsyncMock()
        fake_redis_mock.hgetall = AsyncMock(return_value={})

        sm = SecurityManager(config, fake_redis_mock)
        # _check_rate_limit should pass (count=1 < 77) using static threshold
        result = await sm._check_rate_limit("2.3.4.5")
        assert result is True
        # hgetall should NOT have been called (adaptive disabled)
        fake_redis_mock.hgetall.assert_not_called()

    @pytest.mark.asyncio
    async def test_disabled_never_reads_adaptive_key(self) -> None:
        """With adaptive disabled, _get_adaptive_rate_threshold returns static immediately."""
        from proxy import SecurityManager  # type: ignore[import]

        config = {
            "security": {"max_requests_per_minute": 55},
            "rate_limiter": {"adaptive": {"enabled": False}},
        }
        sm = SecurityManager(config, MagicMock())
        # _get_adaptive_rate_threshold itself still works (it's called from _check_rate_limit
        # only when adaptive enabled). Calling directly: no key → static fallback.
        result = await sm._get_adaptive_rate_threshold("3.4.5.6")
        assert result == 55


# ---------------------------------------------------------------------------
# Test: IPv6 subnet extraction
# ---------------------------------------------------------------------------


class TestAdaptiveRateIPv6:
    """IPv6 addresses use /64 prefix for adaptive key lookup."""

    @pytest.mark.asyncio
    async def test_ipv6_uses_64_prefix(self) -> None:
        """IPv6 adaptive key is rate:adaptive:{/64 network address}."""
        sm, fake_redis = _make_security_manager()

        # /64 of 2001:db8::1 is 2001:db8::
        await fake_redis.hset(
            "rate:adaptive:2001:db8::",
            {"threshold_rps": "88", "confidence": "0.9", "ewma_rps": "44", "windows": "5"},
        )

        threshold = await sm._get_adaptive_rate_threshold("2001:db8::1")
        assert threshold == 88
