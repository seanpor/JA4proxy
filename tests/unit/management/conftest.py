"""Shared fixtures for management unit tests."""

from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def operator_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    ac = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("operator", role="operator")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def admin_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    ac = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin", role="admin")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def auditor_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    ac = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("auditor", role="auditor")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()
