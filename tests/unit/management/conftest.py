"""Shared fixtures for management unit tests."""

from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio


def _import_management_modules():
    """Lazy import — avoids collection failures when management deps are absent."""
    import importlib

    return (
        importlib.import_module("httpx"),
        importlib.import_module("management.api"),
        importlib.import_module("management.api.auth"),
        importlib.import_module("management.api.main"),
    )


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def operator_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator["httpx.AsyncClient", None]:
    httpx_mod, _, auth_mod, main_mod = _import_management_modules()
    app = main_mod.create_app()
    from management.api import redis_client as _redis_module

    await _redis_module.init_redis(override_client=fake_redis)
    ac = httpx_mod.AsyncClient(
        transport=httpx_mod.ASGITransport(app=app),
        base_url="http://test",
        cookies={
            "token": auth_mod._create_access_token("operator", role="operator")
        },
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def admin_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator["httpx.AsyncClient", None]:
    httpx_mod, _, auth_mod, main_mod = _import_management_modules()
    app = main_mod.create_app()
    from management.api import redis_client as _redis_module

    await _redis_module.init_redis(override_client=fake_redis)
    ac = httpx_mod.AsyncClient(
        transport=httpx_mod.ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": auth_mod._create_access_token("admin", role="admin")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def auditor_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator["httpx.AsyncClient", None]:
    httpx_mod, _, auth_mod, main_mod = _import_management_modules()
    app = main_mod.create_app()
    from management.api import redis_client as _redis_module

    await _redis_module.init_redis(override_client=fake_redis)
    ac = httpx_mod.AsyncClient(
        transport=httpx_mod.ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": auth_mod._create_access_token("auditor", role="auditor")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()
