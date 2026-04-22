"""Regression tests for JA4PROXY-2026-0007 — Webhook URL SSRF.

The Management API webhook CRUD used to accept any URL. An authenticated
operator could therefore point a webhook at:

    - http://localhost:6379                       (Redis admin socket)
    - http://127.0.0.1/                           (proxy internals)
    - http://169.254.169.254/latest/meta-data/    (cloud IMDS)
    - http://10.0.0.1/, http://192.168.1.1/,
      http://172.16.0.1/                          (RFC1918)
    - http://[::1]/, http://[fe80::1]/            (IPv6 loopback / link-local)

and the dispatcher would happily leak response bodies back via the retry
queue. The fix rejects such URLs at the Pydantic model layer so the
dangerous target never touches Redis.

These tests exercise the validator directly (no network) and also confirm
that the POST/PUT routes surface the failure as HTTP 422.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

import fakeredis.aioredis  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402
from management.api.routes.webhooks import (  # noqa: E402
    WebhookCreate,
    WebhookUpdate,
    _validate_webhook_url,
)


# ── Validator-level regression (no network, deterministic) ────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/hook",
        "http://LOCALHOST/hook",
        "http://localhost:6379/",
        "http://something.localhost/",
        "http://internal.local/",
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://172.31.255.254/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:127.0.0.1]/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http:///no-host",
    ],
)
def test_regression_JA4PROXY_2026_0007_validator_rejects_ssrf_url(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_webhook_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://8.8.8.8/",
        "http://1.1.1.1/hook",
    ],
)
def test_regression_JA4PROXY_2026_0007_validator_allows_public_ip(url: str) -> None:
    # Public IP literals must not trip the internal-range check.
    assert _validate_webhook_url(url) == url


def test_regression_JA4PROXY_2026_0007_pydantic_model_rejects_ssrf_url() -> None:
    # The Pydantic layer must surface the validator error.
    with pytest.raises(Exception):
        WebhookCreate(url="http://169.254.169.254/latest/meta-data/", events=[])
    with pytest.raises(Exception):
        WebhookUpdate(url="http://localhost:6379/")


def test_regression_JA4PROXY_2026_0007_pydantic_update_none_ok() -> None:
    # PUT with no url change must still validate cleanly.
    WebhookUpdate(url=None, events=["ban.created"])


# ── End-to-end regression on the HTTP surface ─────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> "fakeredis.aioredis.FakeRedis":
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


async def _admin_client(fake_redis: "fakeredis.aioredis.FakeRedis") -> AsyncClient:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    cookie = {"token": _create_access_token("admin")}
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookie,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:6379/",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "ftp://example.com/",
    ],
)
async def test_regression_JA4PROXY_2026_0007_post_rejects_ssrf_url(
    fake_redis: "fakeredis.aioredis.FakeRedis", url: str
) -> None:
    client = await _admin_client(fake_redis)
    try:
        r = await client.post(
            "/api/v1/webhooks",
            json={"url": url, "events": ["ban.created"]},
        )
        assert r.status_code == 422, (
            f"expected 422 Unprocessable Entity for SSRF target {url!r}, got "
            f"{r.status_code}: {r.text}"
        )
        # Nothing should have been written to Redis.
        assert await fake_redis.scard("webhook:idx") == 0
    finally:
        await client.aclose()
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_regression_JA4PROXY_2026_0007_put_rejects_ssrf_url(
    fake_redis: "fakeredis.aioredis.FakeRedis",
) -> None:
    client = await _admin_client(fake_redis)
    try:
        # Seed a benign record directly (bypassing the POST validator).
        await fake_redis.hset(
            "webhook:w1",
            mapping={
                "id": "w1",
                "url": "https://webhook.example.com/hook",
                "events": "[]",
                "secret_hash": "dummy",
                "active": "true",
                "created_at": "2026-04-20T00:00:00Z",
                "managed_by": "admin",
            },
        )
        await fake_redis.sadd("webhook:idx", "w1")

        r = await client.put(
            "/api/v1/webhooks/w1",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert r.status_code == 422, r.text
        fields = await fake_redis.hgetall("webhook:w1")
        assert fields["url"] == "https://webhook.example.com/hook"
    finally:
        await client.aclose()
        await _redis_module.close_redis()
