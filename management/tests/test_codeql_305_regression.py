"""Regression tests for the Phase 305 CodeQL triage fixes.

Two genuine findings were confirmed (the rest were verified false positives
or intentional test tooling — see docs/phases/PHASE_305.md):

1. **Reflected XSS — py/reflective-xss** in
   ``management/api/routes/partials.py`` (``/api/v1/partials/list-table``).
   The unvalidated ``list`` query parameter was interpolated *raw* into the
   returned HTML on the unknown-list error path:

       f'<div ...>Unknown list: {list}</div>'

   so ``?list=<script>...`` reflected attacker HTML into the operator's
   browser. The fix escapes the value with ``html.escape`` before
   reflecting it.

2. **Error-detail exposure — py/stack-trace-exposure** in
   ``management/api/routes/health.py`` (``/api/v1/health/deep`` and the
   *unauthenticated* ``/api/v1/ready``). Both returned ``str(exc)`` of a
   Redis failure to the client, leaking internal topology (host/port,
   connection errors). The fix logs the detail server-side and returns a
   generic status/reason to the caller.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import (  # noqa: E402
    _create_access_token,
    safe_relative_redirect,
)
from management.api.main import create_app  # noqa: E402
from management.api.redis_client import get_redis  # noqa: E402

# A secret-looking string that would be present in a real Redis connection
# error. The fixes must keep this out of any client-facing response body.
_SECRET_MARKER = "redis://:SUPERSECRETPW@internal-redis.prod.local:6379/0"


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


# ── XSS: list-table partial ───────────────────────────────────────────────────


@asynccontextmanager
async def _auditor_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[Tuple[AsyncClient, str], None]:
    """Yield an AsyncClient with an admin cookie (sufficient to reach the route)."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    cookies = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookies,
    ) as client:
        yield client, app
    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_list_table_unknown_list_escapes_html(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A hostile `list` value must be HTML-escaped, not reflected raw."""
    payload = "<script>alert(document.cookie)</script>"
    async with _auditor_client(fake_redis) as (client, _app):
        r = await client.get("/api/v1/partials/list-table", params={"list": payload})
    assert r.status_code == 400
    body = r.text
    # The raw, executable payload MUST NOT appear.
    assert "<script>alert(document.cookie)</script>" not in body, (
        "list-table reflected the raw `list` query param — reflected XSS "
        "(py/reflective-xss regression)"
    )
    # The escaped form SHOULD appear (proves the value is shown, but inert).
    assert "&lt;script&gt;" in body


@pytest.mark.asyncio
async def test_list_table_known_list_still_works(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A valid list name still renders its table (fix didn't break the happy path)."""
    async with _auditor_client(fake_redis) as (client, _app):
        r = await client.get(
            "/api/v1/partials/list-table", params={"list": "ja4_whitelist"}
        )
    assert r.status_code == 200


# ── Error exposure: /health/deep and /ready ───────────────────────────────────


class _FailingRedis:
    """A redis stand-in whose every op raises an error carrying a secret."""

    async def ping(self):  # noqa: ANN201
        raise ConnectionError(f"Error connecting to {_SECRET_MARKER}")

    async def get(self, *_a, **_k):  # noqa: ANN201
        raise ConnectionError(f"Error connecting to {_SECRET_MARKER}")


@asynccontextmanager
async def _client_with_failing_redis() -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    app.dependency_overrides[get_redis] = lambda: _FailingRedis()
    cookies = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookies,
    ) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_ready_does_not_leak_exception_detail() -> None:
    """Unauthenticated /ready must return a generic reason, never str(exc)."""
    async with _client_with_failing_redis() as client:
        r = await client.get("/api/v1/ready")
    assert r.status_code == 503
    body = r.text
    assert _SECRET_MARKER not in body, (
        "/ready leaked internal Redis connection detail to the client "
        "(py/stack-trace-exposure regression)"
    )
    assert r.json()["ready"] is False
    assert r.json()["reason"] == "redis_unavailable"


@pytest.mark.asyncio
async def test_health_deep_does_not_leak_exception_detail() -> None:
    """/health/deep must not echo str(exc) into the response body."""
    async with _client_with_failing_redis() as client:
        r = await client.get("/api/v1/health/deep")
    # 503 (degraded) when authed; some role configs may 401/403 — either way,
    # the secret must never be in the body.
    body = r.text
    assert _SECRET_MARKER not in body, (
        "/health/deep leaked internal Redis connection detail to the client "
        "(py/stack-trace-exposure regression)"
    )


# ── Open-redirect guard: safe_relative_redirect (OIDC/SAML, #89/#90) ───────────


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.com",
        "http://evil.com/path",
        "//evil.com",  # protocol-relative — browsers treat as absolute
        "/\\evil.com",  # backslash trick — some browsers normalise \ to /
        "\\\\evil.com",
        "javascript:alert(1)",
        "ftp://evil.com",
        "",
        None,
    ],
)
def test_safe_relative_redirect_rejects_offsite(hostile) -> None:
    """Any non-same-site target collapses to the safe default '/'."""
    assert safe_relative_redirect(hostile) == "/"


@pytest.mark.parametrize(
    "ok",
    ["/", "/dashboard", "/lists?tab=ja4_whitelist", "/a/b/c"],
)
def test_safe_relative_redirect_allows_same_site(ok) -> None:
    """Genuine same-site relative paths pass through unchanged."""
    assert safe_relative_redirect(ok) == ok


def test_safe_relative_redirect_custom_default() -> None:
    assert safe_relative_redirect("https://evil.com", default="/home") == "/home"
