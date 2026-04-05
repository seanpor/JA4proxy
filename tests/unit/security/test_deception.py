"""Unit tests for honey-fingerprint and honey-SNI detection (Phase 56).

The deception module (src/security/deception.py) detects when a client
presents a JA4 fingerprint or SNI that matches a configured honeypot value.
Matching clients are:
  1. Banned immediately (ban:{ip} key written to Redis with TTL).
  2. The pipeline returns action="silent_drop".

The DeceptionChecker loads its config from a YAML file specified by
``deception.config_path`` in proxy.yml.  When the file is absent, all
checks are silently skipped (fail open).

Tests use DeceptionChecker directly and via the Pipeline, injecting
test state via attribute assignment to avoid file-system dependencies.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.deception import DeceptionChecker
from src.security.models import ConnectionContext, PipelineResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_redis() -> MagicMock:
    """Return a mock async Redis client with all methods stubbed."""
    redis = MagicMock()
    redis.set = AsyncMock(return_value=True)
    redis.setex = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.sismember = AsyncMock(return_value=False)
    redis.smembers = AsyncMock(return_value=set())
    redis.evalsha = AsyncMock(return_value=[0, 0])
    redis.zrangebyscore = AsyncMock(return_value=[])
    redis.zadd = AsyncMock(return_value=1)
    redis.zremrangebyscore = AsyncMock(return_value=0)
    redis.zcard = AsyncMock(return_value=0)
    redis.incr = AsyncMock(return_value=1)
    redis.decr = AsyncMock(return_value=0)
    redis.expire = AsyncMock(return_value=True)
    redis.exists = AsyncMock(return_value=0)
    redis.hgetall = AsyncMock(return_value={})
    redis.hincrby = AsyncMock(return_value=1)
    redis.xadd = AsyncMock(return_value=b"0-1")
    redis.pfadd = AsyncMock(return_value=1)
    redis.pfcount = AsyncMock(return_value=1)
    return redis


def _make_checker(
    enabled: bool = True,
    honey_fingerprints: list | None = None,
    honey_snis: list | None = None,
    ban_ttl: int = 3600,
    redis: MagicMock | None = None,
) -> DeceptionChecker:
    """Build a DeceptionChecker with injected state (no file I/O)."""
    if redis is None:
        redis = _make_redis()
    # Construct with a non-existent config path so _load_deception_config is a no-op
    checker = DeceptionChecker(proxy_config={}, redis_client=redis)
    # Directly inject test state
    checker._enabled = enabled
    checker._honey_fingerprints = frozenset(honey_fingerprints or [])
    checker._honey_snis = frozenset(
        s.lower() for s in (honey_snis or [])
    )
    checker._ban_ttl = ban_ttl
    checker._silent_drop = True
    return checker


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Feature disabled
# ---------------------------------------------------------------------------


class TestDeceptionDisabled:
    def test_disabled_fingerprint_match_returns_none(self):
        """When enabled=False, even a matching fingerprint → check() returns None."""
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=False,
            honey_fingerprints=[honey_ja4],
        )
        result = _run(checker.check("10.0.0.1", honey_ja4, "www.example.com"))
        assert result is None

    def test_disabled_sni_match_returns_none(self):
        """When enabled=False, even a matching honey SNI → check() returns None."""
        checker = _make_checker(
            enabled=False,
            honey_snis=["trap.internal"],
        )
        result = _run(checker.check("10.0.0.1", "t13d...", "trap.internal"))
        assert result is None

    def test_disabled_no_ban_written(self):
        """When disabled, no ban key is written to Redis."""
        redis = _make_redis()
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=False,
            honey_fingerprints=[honey_ja4],
            redis=redis,
        )
        _run(checker.check("10.0.0.1", honey_ja4, None))
        redis.set.assert_not_called()


# ---------------------------------------------------------------------------
# Empty honey lists
# ---------------------------------------------------------------------------


class TestEmptyHoneyLists:
    def test_empty_lists_no_match(self):
        """Empty honey lists → check() returns None for any input."""
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[],
            honey_snis=[],
        )
        result = _run(checker.check("10.0.0.1", "t13d030500_55b375c5d22e_a80244f201c9", "www.example.com"))
        assert result is None

    def test_empty_lists_no_ban_written(self):
        """Empty honey lists → no ban key written."""
        redis = _make_redis()
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[],
            honey_snis=[],
            redis=redis,
        )
        _run(checker.check("10.0.0.1", "t13d030500_55b375c5d22e_a80244f201c9", None))
        redis.set.assert_not_called()


# ---------------------------------------------------------------------------
# Honey fingerprint match
# ---------------------------------------------------------------------------


class TestHoneyFingerprintMatch:
    def test_matching_ja4_triggers_ban_key(self):
        """Client JA4 matching a honey fingerprint → ban:{ip} written to Redis."""
        redis = _make_redis()
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[honey_ja4],
            redis=redis,
        )
        _run(checker.check("10.0.0.42", honey_ja4, "www.example.com"))

        # Confirm ban key was written
        redis.set.assert_called_once()
        call_args = redis.set.call_args
        assert call_args.args[0] == "ban:10.0.0.42" or (
            len(call_args.args) > 0 and "ban:10.0.0.42" in str(call_args.args[0])
        ), f"Expected ban:10.0.0.42 key; got {call_args}"

    def test_matching_ja4_returns_fingerprint_trigger(self):
        """Client JA4 matching a honey fingerprint → returns dict with trigger=fingerprint."""
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[honey_ja4],
        )
        result = _run(checker.check("10.0.0.42", honey_ja4, "www.example.com"))
        assert result is not None
        assert result["trigger"] == "fingerprint"

    def test_matching_ja4_includes_silent_drop_flag(self):
        """Honey fingerprint match result includes silent_drop key."""
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[honey_ja4],
        )
        result = _run(checker.check("10.0.0.42", honey_ja4, None))
        assert result is not None
        assert "silent_drop" in result

    def test_non_matching_ja4_returns_none(self):
        """Client JA4 not in honey list → check() returns None."""
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=["t13d030500_deadbeef0000_000000000000"],
        )
        result = _run(checker.check(
            "10.0.0.1",
            "t13d030500_55b375c5d22e_a80244f201c9",
            "www.example.com",
        ))
        assert result is None

    def test_none_ja4_does_not_match(self):
        """None JA4 → no match, no exception."""
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=["t13d030500_deadbeef0000_000000000000"],
        )
        result = _run(checker.check("10.0.0.1", None, None))
        assert result is None


# ---------------------------------------------------------------------------
# Honey SNI match
# ---------------------------------------------------------------------------


class TestHoneySNIMatch:
    def test_matching_sni_triggers_ban_key(self):
        """Client SNI matching a honey SNI → ban:{ip} written to Redis."""
        redis = _make_redis()
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
            redis=redis,
        )
        _run(checker.check("10.0.0.99", "t13d030500_55b375c5d22e_a80244f201c9", "trap.internal.company.com"))

        redis.set.assert_called_once()
        call_args = redis.set.call_args
        assert "ban:10.0.0.99" in str(call_args.args[0]), (
            f"Expected ban:10.0.0.99 key; got {call_args}"
        )

    def test_matching_sni_returns_sni_trigger(self):
        """Client SNI matching a honey SNI → returns dict with trigger=sni."""
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
        )
        result = _run(checker.check(
            "10.0.0.99",
            "t13d030500_55b375c5d22e_a80244f201c9",
            "trap.internal.company.com",
        ))
        assert result is not None
        assert result["trigger"] == "sni"

    def test_sni_match_is_case_insensitive(self):
        """SNI matching is case-insensitive (stored as lowercase)."""
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
        )
        # Client sends uppercase variant
        result = _run(checker.check(
            "10.0.0.99",
            None,
            "TRAP.INTERNAL.COMPANY.COM",
        ))
        assert result is not None, "SNI match must be case-insensitive"
        assert result["trigger"] == "sni"

    def test_non_matching_sni_returns_none(self):
        """Client SNI not in honey list → check() returns None."""
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
        )
        result = _run(checker.check("10.0.0.1", None, "www.example.com"))
        assert result is None

    def test_none_sni_does_not_match(self):
        """None SNI → no match, no exception."""
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
        )
        result = _run(checker.check("10.0.0.1", None, None))
        assert result is None


# ---------------------------------------------------------------------------
# Redis unavailability — fail open
# ---------------------------------------------------------------------------


class TestRedisUnavailableDuringBan:
    def test_redis_error_on_set_does_not_raise(self):
        """When Redis.set raises, _ban_ip fails open — no exception propagates."""
        redis = _make_redis()
        redis.set = AsyncMock(side_effect=ConnectionError("Redis down"))
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[honey_ja4],
            redis=redis,
        )
        # Must not raise
        result = _run(checker.check("10.0.0.7", honey_ja4, None))
        # The ban may not have been written, but the match detection still fires
        assert result is not None
        assert result["trigger"] == "fingerprint"

    def test_redis_none_ban_skipped_gracefully(self):
        """When Redis client is None, ban write is skipped without exception."""
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=["t13d030500_deadbeef0000_000000000000"],
            redis=None,  # No Redis client
        )
        checker._redis = None  # Ensure it's really None
        result = _run(checker.check(
            "10.0.0.7",
            "t13d030500_deadbeef0000_000000000000",
            None,
        ))
        # Still detects the match (fail open means no crash, not no detection)
        assert result is not None


# ---------------------------------------------------------------------------
# Pipeline integration — deception leads to silent_drop action
# ---------------------------------------------------------------------------


class TestPipelineDeceptionIntegration:
    """Test that the pipeline routes deception hits to action='silent_drop'."""

    def _make_pipeline_with_checker(self, checker: DeceptionChecker):
        from src.security.pipeline import Pipeline
        from src.cache.local_cache import LocalCache

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
            "mtls": {"enabled": True, "ca_cert_path": None},
        }
        cache = LocalCache({})
        cache.dial = 0
        redis = _make_redis()
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=redis)
        # Inject the pre-configured checker
        pipeline._deception_checker = checker
        return pipeline

    def test_matching_ja4_pipeline_returns_silent_drop(self):
        """Honey fingerprint match → pipeline action is 'silent_drop'."""
        honey_ja4 = "t13d030500_deadbeef0000_000000000000"
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=[honey_ja4],
        )
        pipeline = self._make_pipeline_with_checker(checker)

        ctx = ConnectionContext(
            client_ip="10.0.0.42",
            ja4=honey_ja4,
            sni="www.example.com",
        )
        result = _run(pipeline.process(ctx))
        assert result.action == "silent_drop", (
            f"Expected 'silent_drop' for honey fingerprint match; got {result.action!r}"
        )

    def test_matching_sni_pipeline_returns_silent_drop(self):
        """Honey SNI match → pipeline action is 'silent_drop'."""
        checker = _make_checker(
            enabled=True,
            honey_snis=["trap.internal.company.com"],
        )
        pipeline = self._make_pipeline_with_checker(checker)

        ctx = ConnectionContext(
            client_ip="10.0.0.99",
            ja4="t13d030500_55b375c5d22e_a80244f201c9",
            sni="trap.internal.company.com",
        )
        result = _run(pipeline.process(ctx))
        assert result.action == "silent_drop", (
            f"Expected 'silent_drop' for honey SNI match; got {result.action!r}"
        )

    def test_no_match_pipeline_returns_allow(self):
        """No honey match → pipeline continues normally (allow at dial=0)."""
        checker = _make_checker(
            enabled=True,
            honey_fingerprints=["t13d030500_deadbeef0000_000000000000"],
        )
        pipeline = self._make_pipeline_with_checker(checker)

        ctx = ConnectionContext(
            client_ip="10.0.0.1",
            ja4="t13d030500_55b375c5d22e_a80244f201c9",
            sni="www.example.com",
        )
        result = _run(pipeline.process(ctx))
        # dial=0 → monitor mode → allow
        assert result.action == "allow"
