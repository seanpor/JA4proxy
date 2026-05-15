"""Phase 85 — web-page + API tests for the /threat-intel surface.

Mirrors the ``test_pages.py`` pattern in ``CLAUDE.md`` (Web Service Phases —
Testing Standards): for every HTML-rendering route we assert both the
authenticated and unauthenticated paths, and for every JSON API route we
assert role enforcement and the success-path status code.

phase-85.1 (gap register cleanup): the previous incarnation of this file
was xfailed pending a Redis fixture for the management TestClient. The
fixture pattern is to inject a ``fakeredis`` instance via
``redis_client.init_redis(override_client=...)`` *before* the FastAPI
lifespan context runs, exactly as ``management/tests/conftest.py`` does.
We use httpx AsyncClient + ASGITransport so the lifespan honours the
pre-injection check.

Auth: the management API accepts both Bearer-token and JWT-cookie auth.
The cookie path is simpler from a test (no Redis-side bcrypt seeding
required), so we mint cookies via ``_create_access_token`` with the role
each test needs (auditor / operator / admin).
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio

# Phase 85 management API needs these set before any module import.
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
# phase-101 H8: bypass CSRF middleware (test predates it).
os.environ.setdefault("MANAGEMENT_DISABLE_CSRF", "1")

from httpx import ASGITransport, AsyncClient  # noqa: E402

try:
    from management.api import proxy_config as _proxy_config_module
    from management.api import redis_client as _redis_module
    from management.api.auth import _create_access_token
    from management.api.main import create_app
except ImportError:  # pragma: no cover
    pytest.skip(
        "Management API not importable; this test runs after Phase 79.",
        allow_module_level=True,
    )


# A minimal proxy_config dict containing the one feed-id the tests use.
# We monkey-patch _load_proxy_config (which is what get_proxy_config calls
# under the hood) so the threat_intel routes find "test-feed".
_FAKE_PROXY_CONFIG = {
    "threat_intel": {
        "enabled": True,
        "feeds": [
            {
                "id": "test-feed",
                "type": "taxii2",
                "enabled": True,
                "url": "https://example.invalid/taxii2/",
                "poll_interval_minutes": 60,
            }
        ],
    }
}


@pytest.fixture(autouse=True)
def _patch_proxy_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the threat-intel routes to see a single configured feed."""
    monkeypatch.setattr(
        _proxy_config_module,
        "_load_proxy_config",
        lambda: _FAKE_PROXY_CONFIG,
    )


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Fresh isolated FakeRedis async client per test."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


async def _make_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
    cookies: dict[str, str] | None = None,
) -> AsyncClient:
    """Build an httpx AsyncClient with redis pre-injected and cookies attached.

    httpx 0.27+ deprecates per-request cookies; cookies must be set on the
    client itself, which is why we have a factory rather than a single
    fixture parametrised by role.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookies or {},
    )


@pytest_asyncio.fixture()
async def client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated httpx AsyncClient against a fresh app + injected redis."""
    ac = await _make_client(fake_redis)
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def admin_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Admin-cookie-authenticated client."""
    ac = await _make_client(
        fake_redis, cookies={"token": _create_access_token("admin", role="admin")}
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def operator_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Operator-cookie-authenticated client."""
    ac = await _make_client(
        fake_redis,
        cookies={"token": _create_access_token("op-user", role="operator")},
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
    """Auditor-cookie-authenticated client."""
    ac = await _make_client(
        fake_redis,
        cookies={"token": _create_access_token("audit-user", role="auditor")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


# ── HTML page route ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_page_authenticated_200_html(
    admin_client: AsyncClient,
) -> None:
    """GET /threat-intel with valid auth → 200 + text/html + landmark."""
    resp = await admin_client.get("/threat-intel")
    assert (
        resp.status_code == 200
    ), f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
    assert "text/html" in resp.headers.get("content-type", "")
    assert "Threat Intelligence" in resp.text


@pytest.mark.asyncio
async def test_threat_intel_page_without_auth_redirects_browser(
    client: AsyncClient,
) -> None:
    """Browser GET /threat-intel without auth → 302 → /login.

    The previous incarnation asserted ``status_code < 500``, which silently
    accepts a 200 — i.e. a route that quietly leaks the page to anonymous
    callers would have passed. Tighten to the actual auth contract:
    ``_unauthenticated_response`` returns 302 with Location: /login when
    the request looks browser-shaped (Accept: text/html and path not under
    /api/).
    """
    resp = await client.get(
        "/threat-intel",
        headers={"Accept": "text/html"},
    )
    assert (
        resp.status_code == 302
    ), f"Expected 302 redirect for unauth browser request, got {resp.status_code}"
    assert resp.headers.get("location") == "/login"


@pytest.mark.asyncio
async def test_threat_intel_page_without_auth_api_client_returns_401(
    client: AsyncClient,
) -> None:
    """API-shaped GET /threat-intel without auth → 401, not a 5xx crash."""
    resp = await client.get(
        "/threat-intel",
        headers={"Accept": "application/json"},
    )
    assert (
        resp.status_code == 401
    ), f"Expected 401 for unauth API request, got {resp.status_code}"


# ── JSON API routes ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_feeds_api_list_auditor_role(
    auditor_client: AsyncClient,
) -> None:
    """GET /api/v1/threat-intel/feeds returns per-feed status for an Auditor."""
    resp = await auditor_client.get("/api/v1/threat-intel/feeds")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "feeds" in body and "count" in body
    assert isinstance(body["feeds"], list)
    assert body["count"] == len(body["feeds"]) == 1
    assert body["feeds"][0]["id"] == "test-feed"


@pytest.mark.asyncio
async def test_threat_intel_feed_enable_requires_operator_role(
    auditor_client: AsyncClient,
) -> None:
    """POST /enable with an Auditor token → 403."""
    resp = await auditor_client.post("/api/v1/threat-intel/feeds/test-feed/enable")
    assert (
        resp.status_code == 403
    ), f"Auditor role should be forbidden; got {resp.status_code}: {resp.text[:200]}"


@pytest.mark.asyncio
async def test_threat_intel_feed_poll_endpoint_returns_202(
    operator_client: AsyncClient,
) -> None:
    """POST /poll with an Operator token → 202 + a poll_id."""
    resp = await operator_client.post("/api/v1/threat-intel/feeds/test-feed/poll")
    assert (
        resp.status_code == 202
    ), f"Expected 202, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["feed_id"] == "test-feed"
    assert body.get("poll_id")


# ── PHASE_101 H7: manual-poll rate limit (6/min/feed_id) ────────────────────


@pytest.mark.asyncio
async def test_phase_101_h7_seventh_poll_in_window_returns_429(
    operator_client: AsyncClient,
) -> None:
    """6 polls in 60s succeed; the 7th returns 429 with Retry-After.

    PHASE_101 H7 — without this cap a compromised operator token can DoS
    an upstream TI vendor or amplify a misbehaving feed by hammering
    the manual-poll endpoint.
    """
    for i in range(6):
        resp = await operator_client.post("/api/v1/threat-intel/feeds/test-feed/poll")
        assert resp.status_code == 202, (
            f"poll #{i+1} should succeed within window, got "
            f"{resp.status_code}: {resp.text[:200]}"
        )
    # 7th in the same window must be rejected.
    resp = await operator_client.post("/api/v1/threat-intel/feeds/test-feed/poll")
    assert (
        resp.status_code == 429
    ), f"Expected 429 on 7th poll, got {resp.status_code}: {resp.text[:200]}"
    retry_after = resp.headers.get("Retry-After")
    assert retry_after is not None, "Retry-After header must be present on 429"
    assert (
        int(retry_after) > 0
    ), f"Retry-After must be a positive int, got {retry_after!r}"
    body = resp.json()
    assert "rate limit" in body.get("detail", "").lower()


@pytest.mark.asyncio
async def test_phase_101_h7_rate_limit_is_per_feed_id(
    operator_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hitting the limit on feed A must NOT throttle feed B.

    The cap is ``6/min/feed_id`` — the resource being protected is the
    upstream feed, not the operator token. Per-user throttling would
    coupling unrelated feeds together.
    """
    # Add a second feed-id to the fake config so /poll resolves it.
    fake_cfg = {
        "threat_intel": {
            "enabled": True,
            "feeds": [
                {
                    "id": "test-feed",
                    "type": "taxii2",
                    "url": "https://example.com/taxii2/",
                    "enabled": True,
                    "poll_interval_minutes": 60,
                },
                {
                    "id": "other-feed",
                    "type": "taxii2",
                    "url": "https://example.com/taxii2/",
                    "enabled": True,
                    "poll_interval_minutes": 60,
                },
            ],
        }
    }
    monkeypatch.setattr(_proxy_config_module, "_load_proxy_config", lambda: fake_cfg)

    # Saturate test-feed.
    for _ in range(6):
        r = await operator_client.post("/api/v1/threat-intel/feeds/test-feed/poll")
        assert r.status_code == 202
    r = await operator_client.post("/api/v1/threat-intel/feeds/test-feed/poll")
    assert r.status_code == 429, "test-feed should now be throttled"

    # other-feed must still be free.
    r = await operator_client.post("/api/v1/threat-intel/feeds/other-feed/poll")
    assert r.status_code == 202, (
        f"other-feed should NOT be throttled, got {r.status_code}: " f"{r.text[:200]}"
    )


@pytest.mark.asyncio
async def test_phase_101_h7_404_feed_does_not_consume_quota(
    operator_client: AsyncClient,
) -> None:
    """Polling a non-existent feed returns 404 and does not increment
    the rate-limit counter for that feed_id (the rate-limit check runs
    after the 404)."""
    # 10 attempts at a missing feed must all 404 — none should ever 429.
    for _ in range(10):
        r = await operator_client.post("/api/v1/threat-intel/feeds/nope-not-real/poll")
        assert (
            r.status_code == 404
        ), f"Missing feed should always 404, got {r.status_code}"
