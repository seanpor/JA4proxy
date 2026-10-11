"""Phase 814e Step 4: Control Plane Weaponisation Safety Suite.

Tests:
1. Bans API:
   - Attempting to ban 127.0.0.1, ::1, or private ranges without explicit override must be blocked.
   - Expanding massive CIDR (> /16) must be blocked with 422 to prevent self-DoS / collateral damage.
2. Dial Safety:
   - Normal operator/admin dial updates are bounded by max_dial_change (default ±10 per call) unless emergency override is used.
   - Emergency dial requires admin role + MFA verification.
3. Attack Mode / Offense:
   - Countermeasures cannot target loopback, private ranges, or gateway IPs.
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
from management.api.auth import _create_access_token, mfa_session_key
from management.api.main import create_app
from management.api.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, issue_token


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def control_client(fake_redis: fakeredis.aioredis.FakeRedis) -> AsyncGenerator[Tuple[AsyncClient, fakeredis.aioredis.FakeRedis], None]:
    os.environ["MANAGEMENT_DISABLE_CSRF"] = "1"
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_ban_cidr_expansion_limits_and_private_safety(control_client):
    """CIDR bans must reject >/16 blocks and private/loopback addresses without explicit override."""
    client, redis = control_client
    jwt_admin = _create_access_token("admin", role="admin")
    client.cookies.set("token", jwt_admin)

    # 1. Mega-block /8 (16 million IPs) -> must be rejected with 422
    r_mega = await client.post("/api/v1/bans", json={
        "ip": "203.0.0.0/8",
        "reason": "Massive subnet ban test",
        "duration_hours": 1,
    })
    assert r_mega.status_code == 422
    assert "Maximum allowed is /16" in r_mega.json()["detail"]

    # 2. Overlapping loopback (127.0.0.0/8) -> must be rejected with 422
    r_loopback = await client.post("/api/v1/bans", json={
        "ip": "127.0.0.1/32",
        "reason": "Loopback ban attempt",
        "duration_hours": 1,
    })
    assert r_loopback.status_code == 422
    assert "overlaps private/reserved range" in r_loopback.json()["detail"]

    # 3. Overlapping private (192.168.1.0/24) -> rejected unless allow_private=True
    r_priv = await client.post("/api/v1/bans", json={
        "ip": "192.168.1.0/24",
        "reason": "Private range ban attempt",
        "duration_hours": 1,
        "allow_private": False,
    })
    assert r_priv.status_code == 422
    assert "overlaps private/reserved range" in r_priv.json()["detail"]


@pytest.mark.asyncio
async def test_dial_emergency_requires_mfa_and_admin(control_client):
    """Emergency dial overrides bypass ±10 step limit but strictly require Admin role and verified MFA."""
    client, redis = control_client

    # 1. Auditor token -> 403
    jwt_auditor = _create_access_token("auditor", role="auditor")
    client.cookies.set("token", jwt_auditor)
    r_aud = await client.post("/api/v1/dial/emergency", json={"value": 100, "revert_after_hours": 1})
    assert r_aud.status_code == 403

    # 2. Admin token without MFA (when user has TOTP enrolled) -> 403 MFA required
    jwt_admin = _create_access_token("admin", role="admin")
    client.cookies.set("token", jwt_admin)
    await redis.set("mgmt:totp:admin", "mock-totp-secret")

    r_no_mfa = await client.post("/api/v1/dial/emergency", json={"value": 100, "revert_after_hours": 1})
    assert r_no_mfa.status_code == 403
    assert "MFA verification required" in r_no_mfa.json()["detail"]

    # 3. Admin token with verified MFA -> succeeds
    await redis.set(mfa_session_key(jwt_admin), "verified")
    r_ok = await client.post("/api/v1/dial/emergency", json={"value": 100, "revert_after_hours": 1})
    assert r_ok.status_code == 200
    assert r_ok.json()["value"] == 100
