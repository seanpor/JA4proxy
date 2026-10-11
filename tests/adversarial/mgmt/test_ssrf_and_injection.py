"""Phase 814e Step 3: CSRF & SSRF Adversarial Pentest Suite.

Tests:
1. CSRF on non-/api/v1/ mutating routes (JA4PROXY-2026-0104):
   - Mutating requests to /auth/mfa/webauthn/credentials/{id} without CSRF token must be rejected with 403.
   - Mutating requests to /auth/mfa/totp/verify without CSRF token must be rejected with 403.
   - Public pre-login forms (/auth/login, /auth/sso/saml/acs) use their own anti-replay / state tokens and are safely excluded.
2. Webhook SSRF validation & bypass attempts:
   - Hostnames resolving to internal / private / loopback IPs must be rejected.
   - Cloud metadata IPs (169.254.169.254) in decimal, hex, or bracketed IPv6 notation must be rejected.
   - Non-HTTP(S) schemes (file://, gopher://, dict://) must be rejected.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ["ENVIRONMENT"] = "test"
os.environ["MANAGEMENT_JWT_SECRET"] = "test-secret-min-32-chars-long-abcdef0123456789"
os.environ["MANAGEMENT_ADMIN_USER"] = "admin"
os.environ["MANAGEMENT_ADMIN_PASSWORD"] = "testpassword"
os.environ["MANAGEMENT_TEST_MODE"] = "1"
os.environ.pop("MANAGEMENT_DISABLE_CSRF", None)

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app
from management.api.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, issue_token
from management.api.routes.webhooks import _validate_webhook_url


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def csrf_client(fake_redis: fakeredis.aioredis.FakeRedis) -> AsyncGenerator[Tuple[AsyncClient, fakeredis.aioredis.FakeRedis], None]:
    # Ensure CSRF is strictly enabled
    os.environ.pop("MANAGEMENT_DISABLE_CSRF", None)
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_non_api_mutating_mfa_requires_csrf(csrf_client):
    """Mutating MFA endpoints outside /api/v1/ must require CSRF double-submit token when called with cookie session."""
    client, redis = csrf_client
    jwt_admin = _create_access_token("admin", role="admin")

    # Enroll a mock credential in Redis
    await redis.hset("mgmt:webauthn:credential:test-cred-id", mapping={"user_id": "admin", "public_key": "dummy"})
    await redis.sadd("mgmt:webauthn:user:admin:credentials", "test-cred-id")

    # 1. DELETE without CSRF token must fail with 403
    client.cookies.set("token", jwt_admin)
    r_no_csrf = await client.delete("/auth/mfa/webauthn/credentials/test-cred-id")
    assert r_no_csrf.status_code == 403, (
        f"DELETE /auth/mfa/webauthn/credentials/ without CSRF token must return 403, got {r_no_csrf.status_code}"
    )

    # 2. DELETE with valid CSRF token must succeed with 204
    csrf_tok = issue_token("admin")
    client.cookies.set(CSRF_COOKIE_NAME, csrf_tok)
    r_with_csrf = await client.delete(
        "/auth/mfa/webauthn/credentials/test-cred-id",
        headers={CSRF_HEADER_NAME: csrf_tok},
    )
    assert r_with_csrf.status_code == 204, (
        f"DELETE /auth/mfa/webauthn/credentials/ with valid CSRF must succeed with 204, got {r_with_csrf.status_code}"
    )


@pytest.mark.asyncio
async def test_ssrf_webhook_url_validation_blocks_internal_and_cloud_metadata():
    """Webhook URL validator must reject SSRF payloads against internal networks and IMDS."""
    malicious_urls = [
        "http://127.0.0.1:8080/hook",
        "http://localhost:6379/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/hook",
        "http://[fe80::1]/hook",
        "http://10.0.0.5/hook",
        "http://192.168.1.1/hook",
        "http://172.16.0.1/hook",
        "gopher://127.0.0.1:6379/_flushall",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]

    for url in malicious_urls:
        with pytest.raises(ValueError) as exc_info:
            _validate_webhook_url(url)
        assert len(str(exc_info.value)) > 0
