"""Shared fixtures for all unit tests.

Ensures the management API has an initialized Redis client so that
get_redis() does not raise RuntimeError in tests that don't supply one.
Tests that need specific Redis behaviour should use app.dependency_overrides.
"""
import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def _management_api_redis():
    try:
        import fakeredis
        import fakeredis.aioredis

        from management.api import redis_client as _rc

        server = fakeredis.FakeServer()
        client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
        await _rc.init_redis(override_client=client)
        yield client
        await _rc.close_redis()
    except ImportError:
        yield None
