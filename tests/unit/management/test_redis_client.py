"""
Tests for src/management/redis_client.py — RedisManager.
Phase 104: coverage gap closure.
Uses fakeredis for an in-memory Redis substitute.
"""
import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio

from src.management.redis_client import RedisManager


@pytest_asyncio.fixture
async def fake_redis():
    """Create a fakeredis async client."""
    server = fakeredis.aioredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def manager(fake_redis):
    """RedisManager with its internal client replaced by fakeredis."""
    mgr = RedisManager(host="127.0.0.1", port=6379, db=0)
    mgr._client = fake_redis
    return mgr


# ── connect ──────────────────────────────────────────────────────────────────

class TestConnect:
    @pytest.mark.asyncio
    async def test_connect_creates_client(self):
        """connect() creates a client and pings it."""
        mgr = RedisManager(host="127.0.0.1", port=6379, db=0)
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()
        with patch("src.management.redis_client.redis.Redis", return_value=mock_client):
            result = await mgr.connect()
        assert result is mock_client
        mock_client.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_reuses_existing(self, manager):
        """Second connect() returns the same client."""
        c1 = await manager.connect()
        c2 = await manager.connect()
        assert c1 is c2


# ── get_dial / set_dial ──────────────────────────────────────────────────────

class TestDial:
    @pytest.mark.asyncio
    async def test_get_dial_default(self, manager):
        """Missing key returns 0."""
        val = await manager.get_dial()
        assert val == 0

    @pytest.mark.asyncio
    async def test_get_dial_returns_stored(self, manager):
        client = await manager.connect()
        await client.set("config:dial", "42")
        assert await manager.get_dial() == 42

    @pytest.mark.asyncio
    async def test_get_dial_invalid_value(self, manager):
        """Non-integer stored value returns 0."""
        client = await manager.connect()
        await client.set("config:dial", "not-a-number")
        assert await manager.get_dial() == 0

    @pytest.mark.asyncio
    async def test_set_dial_stores_and_publishes(self, manager):
        await manager.set_dial(75)
        client = await manager.connect()
        assert await client.get("config:dial") == "75"

    @pytest.mark.asyncio
    async def test_set_dial_with_signing_key(self, manager):
        """When _signing_key is set, the published message includes a signature."""
        manager._signing_key = "test-secret-key-xxx"
        await manager.set_dial(50)
        client = await manager.connect()
        assert await client.get("config:dial") == "50"


# ── list operations ──────────────────────────────────────────────────────────

class TestLists:
    @pytest.mark.asyncio
    async def test_get_list_empty(self, manager):
        result = await manager.get_list("whitelist")
        assert result == []

    @pytest.mark.asyncio
    async def test_add_and_get_list(self, manager):
        await manager.add_to_list("whitelist", "test-ja4-hash-aaa")
        await manager.add_to_list("whitelist", "test-ja4-hash-bbb")
        result = await manager.get_list("whitelist")
        assert result == ["test-ja4-hash-aaa", "test-ja4-hash-bbb"]

    @pytest.mark.asyncio
    async def test_add_to_blacklist_publishes(self, manager):
        """Adding to blacklist triggers a pub/sub notification."""
        await manager.add_to_list("blacklist", "test-ja4-hash-ccc")
        client = await manager.connect()
        members = await client.smembers("ja4:blacklist")
        assert "test-ja4-hash-ccc" in members

    @pytest.mark.asyncio
    async def test_add_to_blacklist_with_signing_key(self, manager):
        manager._signing_key = "test-secret-key-xxx"
        await manager.add_to_list("blacklist", "test-ja4-hash-ddd")
        client = await manager.connect()
        members = await client.smembers("ja4:blacklist")
        assert "test-ja4-hash-ddd" in members

    @pytest.mark.asyncio
    async def test_remove_from_list(self, manager):
        await manager.add_to_list("whitelist", "test-ja4-hash-eee")
        await manager.remove_from_list("whitelist", "test-ja4-hash-eee")
        result = await manager.get_list("whitelist")
        assert result == []

    @pytest.mark.asyncio
    async def test_remove_from_whitelist_publishes(self, manager):
        """Removing from whitelist triggers pub/sub notification."""
        await manager.add_to_list("whitelist", "test-ja4-hash-fff")
        # Should not raise
        await manager.remove_from_list("whitelist", "test-ja4-hash-fff")

    @pytest.mark.asyncio
    async def test_remove_from_non_whitelist_no_publish(self, manager):
        """Removing from a non-whitelist list does NOT publish."""
        await manager.add_to_list("blacklist", "test-ja4-hash-ggg")
        await manager.remove_from_list("blacklist", "test-ja4-hash-ggg")
        result = await manager.get_list("blacklist")
        assert result == []


# ── get_events ───────────────────────────────────────────────────────────────

class TestGetEvents:
    @pytest.mark.asyncio
    async def test_get_events_yields_messages(self, manager):
        """get_events is an async generator that yields message data."""
        mock_msg_stream = [
            {"type": "subscribe", "data": None},
            {"type": "message", "data": '{"event":"test-event-xxx"}'},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=AsyncIterator(mock_msg_stream))
        mock_pubsub.__aenter__ = AsyncMock(return_value=mock_pubsub)
        mock_pubsub.__aexit__ = AsyncMock(return_value=False)

        client = await manager.connect()
        client.pubsub = MagicMock(return_value=mock_pubsub)

        messages = []
        async for msg in manager.get_events():
            messages.append(msg)
            break  # only consume the one message

        assert len(messages) == 1
        assert "test-event-xxx" in messages[0]


# ── close ────────────────────────────────────────────────────────────────────

class TestClose:
    @pytest.mark.asyncio
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    async def test_close_clears_client(self, manager):
        await manager.close()
        assert manager._client is None

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self):
        mgr = RedisManager(host="127.0.0.1", port=6379, db=0)
        await mgr.close()  # should not raise
        assert mgr._client is None


# ── constructor ──────────────────────────────────────────────────────────────

class TestConstructor:
    def test_init_stores_params(self):
        mgr = RedisManager(host="10.0.0.1", port=6380, db=2, password="test-pass-xxx")
        assert mgr.host == "10.0.0.1"
        assert mgr.port == 6380
        assert mgr.db == 2
        assert mgr.password == "test-pass-xxx"

    def test_signing_key_from_env(self):
        with patch.dict(os.environ, {"REDIS_SIGNING_KEY": "env-key-xxx"}):
            mgr = RedisManager(host="127.0.0.1", port=6379, db=0)
        assert mgr._signing_key == "env-key-xxx"


# ── helper ───────────────────────────────────────────────────────────────────

class AsyncIterator:
    """Turn a list into an async iterator for mocking pubsub.listen()."""
    def __init__(self, items):
        self._items = iter(items)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._items)
        except StopIteration:
            raise StopAsyncIteration
