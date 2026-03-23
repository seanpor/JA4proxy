"""Unit tests for src/pubsub.py — PubSubHandler message dispatch and reconnection.

Every test exercises the real PubSubHandler._dispatch() code path.
The run() loop is tested via task cancellation to verify the reconnection
and backoff logic without actually connecting to Redis.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.pubsub import CHANNEL, PubSubHandler

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_handler(dial: int = 0):
    """Create a PubSubHandler with mocked dependencies."""
    cache = LocalCache({})
    cache.dial = dial
    config_loader = MagicMock()
    config_loader.reload = AsyncMock()
    blacklist: set[str] = set()
    whitelist: set[str] = set()
    redis_mock = MagicMock()
    handler = PubSubHandler(
        redis_client=redis_mock,
        local_cache=cache,
        config_loader=config_loader,
        blacklist_set=blacklist,
        whitelist_set=whitelist,
    )
    return handler, cache, blacklist, whitelist, config_loader


def _msg(msg_type: str, value=None) -> bytes:
    return json.dumps({"type": msg_type, "value": value}).encode()


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _dispatch() — whitelist_remove
# ---------------------------------------------------------------------------


class TestDispatchWhitelistRemove:
    def test_removes_from_cache(self):
        handler, cache, _, whitelist, _ = _make_handler()
        cache.whitelist_decisions.set("t13d_fingerprint_aa", True)
        _run(handler._dispatch(_msg("whitelist_remove", "t13d_fingerprint_aa")))
        assert cache.whitelist_decisions.get("t13d_fingerprint_aa") is None

    def test_discards_from_whitelist_set(self):
        handler, cache, _, whitelist, _ = _make_handler()
        whitelist.add("t13d_fingerprint_aa")
        _run(handler._dispatch(_msg("whitelist_remove", "t13d_fingerprint_aa")))
        assert "t13d_fingerprint_aa" not in whitelist

    def test_null_value_does_nothing(self):
        """value=None must not crash."""
        handler, cache, _, whitelist, _ = _make_handler()
        whitelist.add("some_fp")
        _run(handler._dispatch(_msg("whitelist_remove", None)))
        assert "some_fp" in whitelist  # unchanged


# ---------------------------------------------------------------------------
# _dispatch() — ban_release
# ---------------------------------------------------------------------------


class TestDispatchBanRelease:
    def test_removes_ban_key_from_cache(self):
        handler, cache, _, _, _ = _make_handler()
        cache.block_decisions.set("ban:1.2.3.4", "banned")
        _run(handler._dispatch(_msg("ban_release", "1.2.3.4")))
        assert cache.block_decisions.get("ban:1.2.3.4") is None

    def test_ban_key_uses_ip_prefix(self):
        """The cache key must be 'ban:{ip}', not just '{ip}'."""
        handler, cache, _, _, _ = _make_handler()
        cache.block_decisions.set("ban:10.0.0.1", "banned")
        cache.block_decisions.set("10.0.0.1", "other")  # different key, must survive
        _run(handler._dispatch(_msg("ban_release", "10.0.0.1")))
        assert cache.block_decisions.get("ban:10.0.0.1") is None
        assert cache.block_decisions.get("10.0.0.1") == "other"

    def test_null_value_does_nothing(self):
        handler, cache, _, _, _ = _make_handler()
        cache.block_decisions.set("ban:1.2.3.4", "banned")
        _run(handler._dispatch(_msg("ban_release", None)))
        assert cache.block_decisions.get("ban:1.2.3.4") == "banned"


# ---------------------------------------------------------------------------
# _dispatch() — ja4_blacklist_add
# ---------------------------------------------------------------------------


class TestDispatchJa4BlacklistAdd:
    def test_adds_to_blacklist_set(self):
        handler, _, blacklist, _, _ = _make_handler()
        assert "t13d_bad_bot" not in blacklist
        _run(handler._dispatch(_msg("ja4_blacklist_add", "t13d_bad_bot")))
        assert "t13d_bad_bot" in blacklist

    def test_multiple_adds_accumulate(self):
        handler, _, blacklist, _, _ = _make_handler()
        _run(handler._dispatch(_msg("ja4_blacklist_add", "fp_a")))
        _run(handler._dispatch(_msg("ja4_blacklist_add", "fp_b")))
        assert {"fp_a", "fp_b"}.issubset(blacklist)

    def test_null_value_does_nothing(self):
        handler, _, blacklist, _, _ = _make_handler()
        _run(handler._dispatch(_msg("ja4_blacklist_add", None)))
        assert len(blacklist) == 0


# ---------------------------------------------------------------------------
# _dispatch() — dial_change
# ---------------------------------------------------------------------------


class TestDispatchDialChange:
    def test_updates_dial_in_cache(self):
        handler, cache, _, _, _ = _make_handler(dial=0)
        _run(handler._dispatch(_msg("dial_change", 75)))
        assert cache.dial == 75

    def test_dial_clamped_to_100(self):
        """LocalCache.dial property clamps at 100."""
        handler, cache, _, _, _ = _make_handler(dial=0)
        _run(handler._dispatch(_msg("dial_change", 999)))
        assert cache.dial == 100

    def test_dial_zero_accepted(self):
        handler, cache, _, _, _ = _make_handler(dial=50)
        _run(handler._dispatch(_msg("dial_change", 0)))
        assert cache.dial == 0

    def test_string_number_parsed(self):
        """value may arrive as a string from JSON."""
        handler, cache, _, _, _ = _make_handler(dial=0)
        _run(handler._dispatch(_msg("dial_change", "50")))
        assert cache.dial == 50

    def test_invalid_value_does_not_crash(self, caplog):
        """Non-numeric dial value must be logged and ignored."""
        handler, cache, _, _, _ = _make_handler(dial=42)
        with caplog.at_level(logging.WARNING, logger="src.pubsub"):
            _run(handler._dispatch(_msg("dial_change", "not_a_number")))
        assert cache.dial == 42  # unchanged
        assert any(
            "dial_change" in r.message and "invalid" in r.message
            for r in caplog.records
        )

    def test_none_value_does_not_crash(self, caplog):
        handler, cache, _, _, _ = _make_handler(dial=30)
        with caplog.at_level(logging.WARNING, logger="src.pubsub"):
            _run(handler._dispatch(_msg("dial_change", None)))
        assert cache.dial == 30


# ---------------------------------------------------------------------------
# _dispatch() — config_reload
# ---------------------------------------------------------------------------


class TestDispatchConfigReload:
    def test_calls_config_loader_reload(self):
        handler, _, _, _, config_loader = _make_handler()
        _run(handler._dispatch(_msg("config_reload")))
        config_loader.reload.assert_called_once()

    def test_reload_exception_does_not_propagate(self, caplog):
        """A failed reload must log an error but never crash the pub/sub loop."""
        handler, _, _, _, config_loader = _make_handler()
        config_loader.reload = AsyncMock(side_effect=Exception("bad yaml"))
        with caplog.at_level(logging.ERROR, logger="src.pubsub"):
            _run(handler._dispatch(_msg("config_reload")))
        assert any(
            "reload_failed" in r.message or "config_reload_failed" in r.message
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# _dispatch() — unknown message type
# ---------------------------------------------------------------------------


class TestDispatchUnknownType:
    def test_unknown_type_logs_warning(self, caplog):
        handler, _, _, _, _ = _make_handler()
        with caplog.at_level(logging.WARNING, logger="src.pubsub"):
            _run(handler._dispatch(_msg("totally_made_up_type", "value")))
        assert any(
            "unknown_message_type" in r.message or "unknown" in r.message.lower()
            for r in caplog.records
        )

    def test_unknown_type_does_not_crash(self):
        handler, _, _, _, _ = _make_handler()
        _run(handler._dispatch(_msg("xyzzy", "some_value")))  # must not raise


# ---------------------------------------------------------------------------
# _dispatch() — malformed input
# ---------------------------------------------------------------------------


class TestDispatchMalformedInput:
    def test_invalid_json_bytes_logs_warning(self, caplog):
        handler, _, _, _, _ = _make_handler()
        with caplog.at_level(logging.WARNING, logger="src.pubsub"):
            _run(handler._dispatch(b"{not valid json"))
        assert any("malformed" in r.message.lower() for r in caplog.records)

    def test_invalid_json_string_does_not_crash(self):
        handler, _, _, _, _ = _make_handler()
        _run(handler._dispatch("this is not json"))  # must not raise

    def test_bytes_decoded_correctly(self):
        """Valid UTF-8 bytes must be handled the same as a string."""
        handler, _, blacklist, _, _ = _make_handler()
        data = json.dumps({"type": "ja4_blacklist_add", "value": "fp_bytes"}).encode(
            "utf-8"
        )
        _run(handler._dispatch(data))
        assert "fp_bytes" in blacklist

    def test_empty_bytes_does_not_crash(self):
        handler, _, _, _, _ = _make_handler()
        _run(handler._dispatch(b""))


# ---------------------------------------------------------------------------
# run() — reconnection and backoff
# ---------------------------------------------------------------------------


class TestRunReconnection:
    def test_cancelled_error_propagates(self):
        """CancelledError must escape the loop so the Task shuts down cleanly."""
        handler, _, _, _, _ = _make_handler()

        pubsub_cm = MagicMock()
        pubsub_cm.__aenter__ = AsyncMock(side_effect=asyncio.CancelledError())
        pubsub_cm.__aexit__ = AsyncMock(return_value=False)
        handler._redis.pubsub = MagicMock(return_value=pubsub_cm)

        with pytest.raises(asyncio.CancelledError):
            _run(handler.run())

    def test_reconnects_after_connection_error(self):
        """A connection error triggers a reconnect attempt; CancelledError on second pass."""
        handler, _, _, _, _ = _make_handler()
        call_count = 0

        async def _fake_aenter():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("Redis went away")
            raise asyncio.CancelledError()

        pubsub_cm = MagicMock()
        pubsub_cm.__aenter__ = AsyncMock(side_effect=_fake_aenter)
        pubsub_cm.__aexit__ = AsyncMock(return_value=False)
        handler._redis.pubsub = MagicMock(return_value=pubsub_cm)

        with patch("src.pubsub.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            with pytest.raises(asyncio.CancelledError):
                _run(handler.run())
        # Backoff sleep must have been called once after the first failure
        mock_sleep.assert_called_once_with(1.0)

    def test_backoff_doubles_on_repeated_failures(self):
        """Backoff doubles each time: 1s → 2s → 4s → ..."""
        handler, _, _, _, _ = _make_handler()
        call_count = 0
        sleep_durations = []

        async def _fake_sleep(duration):
            sleep_durations.append(duration)

        async def _fake_aenter():
            nonlocal call_count
            call_count += 1
            if call_count < 4:
                raise ConnectionError("still down")
            raise asyncio.CancelledError()

        pubsub_cm = MagicMock()
        pubsub_cm.__aenter__ = AsyncMock(side_effect=_fake_aenter)
        pubsub_cm.__aexit__ = AsyncMock(return_value=False)
        handler._redis.pubsub = MagicMock(return_value=pubsub_cm)

        with patch("src.pubsub.asyncio.sleep", new=_fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                _run(handler.run())

        assert sleep_durations == [1.0, 2.0, 4.0]

    def test_backoff_capped_at_60s(self):
        """Backoff must not grow beyond 60 seconds."""
        handler, _, _, _, _ = _make_handler()
        call_count = 0
        sleep_durations = []

        async def _fake_sleep(duration):
            sleep_durations.append(duration)

        async def _fake_aenter():
            nonlocal call_count
            call_count += 1
            if call_count < 9:  # 1→2→4→8→16→32→64→... but capped at 60
                raise ConnectionError("down")
            raise asyncio.CancelledError()

        pubsub_cm = MagicMock()
        pubsub_cm.__aenter__ = AsyncMock(side_effect=_fake_aenter)
        pubsub_cm.__aexit__ = AsyncMock(return_value=False)
        handler._redis.pubsub = MagicMock(return_value=pubsub_cm)

        with patch("src.pubsub.asyncio.sleep", new=_fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                _run(handler.run())

        assert max(sleep_durations) == 60.0
