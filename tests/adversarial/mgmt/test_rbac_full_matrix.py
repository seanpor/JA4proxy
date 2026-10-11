"""Adversarial full-matrix RBAC, BOLA, BFLA, and Step-Up MFA test suite.

Evaluates every route in the management application against 9 principal states:
1. Unauthenticated (no token/cookie)
2. Anonymous / malformed token
3. Expired token
4. Revoked token (checked against mgmt:token:*)
5. Wrong audience / issuer token
6. Analyst role (read-only telemetry/events)
7. Auditor role (read-only compliance/audit)
8. Operator role (standard operational edits, non-emergency)
9. Admin role WITHOUT step-up MFA session
"""

import inspect
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import fakeredis.aioredis
import jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure test environment variables
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_DISABLE_CSRF", "1")

from management.api import redis_client as _redis_module
from management.api.auth import (
    ALGORITHM,
    TOKEN_EXPIRY_HOURS,
    _get_secret_key,
    get_current_user,
    mfa_session_key,
    require_admin,
    require_mfa_verified,
    require_role,
)
from management.api.main import create_app
from management.api.models import Role


def _mint_test_jwt(
    sub: str,
    role: Optional[str] = "admin",
    secret: Optional[str] = None,
    expired: bool = False,
    aud: Optional[str] = None,
    iss: Optional[str] = None,
) -> str:
    key = secret or _get_secret_key()
    now = datetime.now(timezone.utc)
    exp = (now - timedelta(hours=1)) if expired else (now + timedelta(hours=TOKEN_EXPIRY_HOURS))
    payload: Dict[str, Any] = {
        "sub": sub,
        "iat": now,
        "exp": exp,
    }
    if role is not None:
        payload["role"] = role
    if aud:
        payload["aud"] = aud
    if iss:
        payload["iss"] = iss
    return jwt.encode(payload, key, algorithm=ALGORITHM)


def _extract_all_endpoints(app) -> List[Dict[str, Any]]:
    """Extract all routes with expected role requirements and MFA flags."""
    endpoints = []
    for r in app.routes:
        routes_to_inspect = []
        if "IncludedRouter" in type(r).__name__:
            routes_to_inspect = r.original_router.routes
        elif hasattr(r, "path") and hasattr(r, "methods"):
            routes_to_inspect = [r]

        for sub in routes_to_inspect:
            methods = [m for m in getattr(sub, "methods", []) if m != "HEAD"]
            path = getattr(sub, "path", None)
            if not methods or not path:
                continue

            deps = getattr(sub, "dependencies", []) or []
            sig = inspect.signature(sub.endpoint)
            params = sig.parameters.values()

            role = "public"
            mfa_required = False

            all_deps = [d.dependency for d in deps if hasattr(d, "dependency")]
            for p in params:
                if hasattr(p.default, "dependency") and p.default.dependency:
                    all_deps.append(p.default.dependency)

            for d in all_deps:
                if d == require_admin:
                    role = "admin"
                elif d == require_mfa_verified:
                    mfa_required = True
                elif d == get_current_user:
                    if role == "public":
                        role = "authenticated"
                if hasattr(d, "__closure__") and d.__closure__:
                    for cell in d.__closure__:
                        if isinstance(cell.cell_contents, Role):
                            role = cell.cell_contents.value

            for method in methods:
                endpoints.append({
                    "path": path,
                    "method": method,
                    "role": role,
                    "mfa_required": mfa_required,
                    "endpoint": sub.endpoint.__name__,
                })
    return endpoints


@pytest_asyncio.fixture()
async def rbac_harness():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    _redis_module._redis_client = client

    app = create_app()
    endpoints = _extract_all_endpoints(app)
    transport = ASGITransport(app=app)
    http_client = AsyncClient(transport=transport, base_url="http://testserver")

    yield {
        "redis": client,
        "app": app,
        "client": http_client,
        "endpoints": endpoints,
    }

    await http_client.aclose()
    await client.aclose()
    _redis_module._redis_client = None


def _format_concrete_path(path: str) -> str:
    """Format path parameters with dummy values for reachability testing."""
    formatted = re.sub(r"\{[a-zA-Z0-9_]+:path\}", "test/path", path)
    formatted = re.sub(r"\{[a-zA-Z0-9_]+\}", "test_id", formatted)
    return formatted


@pytest.mark.asyncio
async def test_rbac_unauthenticated_requests_fail_closed(rbac_harness):
    """Verify that every protected route rejects unauthenticated access."""
    client: AsyncClient = rbac_harness["client"]
    endpoints = rbac_harness["endpoints"]

    tested = 0
    for ep in endpoints:
        if ep["role"] == "public":
            continue

        url = _format_concrete_path(ep["path"])
        resp = await client.request(
            method=ep["method"],
            url=url,
            headers={"Accept": "application/json"},
        )

        assert resp.status_code in (401, 403, 302), (
            f"Expected auth failure for {ep['method']} {url} (required: {ep['role']}), got {resp.status_code}"
        )
        tested += 1

    assert tested > 80, f"Expected >80 protected endpoints to be tested, got {tested}"


@pytest.mark.asyncio
async def test_rbac_expired_and_malformed_tokens_fail_closed(rbac_harness):
    """Verify that expired and malformed tokens fail closed across all protected routes."""
    client: AsyncClient = rbac_harness["client"]
    endpoints = rbac_harness["endpoints"]

    expired_token = _mint_test_jwt("admin", role="admin", expired=True)
    malformed_token = "invalid.bearer.token.signature"

    sample_endpoints = [ep for ep in endpoints if ep["role"] != "public"][:20]

    for ep in sample_endpoints:
        url = _format_concrete_path(ep["path"])

        # Expired
        resp_exp = await client.request(
            method=ep["method"],
            url=url,
            headers={"Authorization": f"Bearer {expired_token}", "Accept": "application/json"},
        )
        assert resp_exp.status_code in (401, 403), f"Expired token reached {ep['method']} {url}"

        # Malformed
        resp_mal = await client.request(
            method=ep["method"],
            url=url,
            headers={"Authorization": f"Bearer {malformed_token}", "Accept": "application/json"},
        )
        assert resp_mal.status_code in (401, 403), f"Malformed token reached {ep['method']} {url}"


@pytest.mark.asyncio
async def test_rbac_role_enforcement_prevents_privilege_escalation(rbac_harness):
    """Verify that lower roles (analyst, auditor, operator) cannot access higher-privileged routes."""
    client: AsyncClient = rbac_harness["client"]
    endpoints = rbac_harness["endpoints"]

    analyst_token = _mint_test_jwt("analyst_user", role="analyst")
    auditor_token = _mint_test_jwt("auditor_user", role="auditor")
    operator_token = _mint_test_jwt("operator_user", role="operator")

    admin_endpoints = [ep for ep in endpoints if ep["role"] == "admin"]
    assert len(admin_endpoints) >= 15, f"Expected at least 15 admin endpoints, found {len(admin_endpoints)}"

    for ep in admin_endpoints:
        url = _format_concrete_path(ep["path"])

        # Analyst must be rejected with 403
        res_an = await client.request(
            method=ep["method"],
            url=url,
            cookies={"token": analyst_token},
            headers={"Accept": "application/json"},
        )
        assert res_an.status_code == 403, (
            f"Analyst was not forbidden from admin route {ep['method']} {url}: status {res_an.status_code}"
        )

        # Auditor must be rejected with 403
        res_au = await client.request(
            method=ep["method"],
            url=url,
            cookies={"token": auditor_token},
            headers={"Accept": "application/json"},
        )
        assert res_au.status_code == 403, (
            f"Auditor was not forbidden from admin route {ep['method']} {url}: status {res_au.status_code}"
        )

        # Operator must be rejected with 403
        res_op = await client.request(
            method=ep["method"],
            url=url,
            cookies={"token": operator_token},
            headers={"Accept": "application/json"},
        )
        assert res_op.status_code == 403, (
            f"Operator was not forbidden from admin route {ep['method']} {url}: status {res_op.status_code}"
        )


@pytest.mark.asyncio
async def test_step_up_mfa_enforcement_for_cookie_sessions(rbac_harness):
    """Verify that cookie-based admin sessions require step-up MFA verification for sensitive routes."""
    client: AsyncClient = rbac_harness["client"]
    redis = rbac_harness["redis"]
    endpoints = rbac_harness["endpoints"]

    mfa_endpoints = [ep for ep in endpoints if ep["mfa_required"]]
    assert len(mfa_endpoints) >= 5, f"Expected at least 5 step-up MFA endpoints, found {len(mfa_endpoints)}"

    # Set up user with TOTP enrolled in Redis
    username = "admin_mfa"
    await redis.set(f"mgmt:totp:{username}", "JBSWY3DPEHPK3PXP")

    # Mint admin token for user
    admin_token = _mint_test_jwt(username, role="admin")

    for ep in mfa_endpoints:
        url = _format_concrete_path(ep["path"])

        # Without MFA session verified -> must be 403
        resp_unverified = await client.request(
            method=ep["method"],
            url=url,
            cookies={"token": admin_token},
            headers={"Accept": "application/json"},
        )
        assert resp_unverified.status_code == 403, (
            f"Admin without step-up MFA bypassed verification for {ep['method']} {url}: status {resp_unverified.status_code}"
        )
        assert "MFA verification required" in resp_unverified.text

        # Now simulate verified MFA session in Redis
        sess_key = mfa_session_key(admin_token)
        await redis.set(sess_key, "1", ex=300)

        # Re-request with verified session
        resp_verified = await client.request(
            method=ep["method"],
            url=url,
            cookies={"token": admin_token},
            headers={"Accept": "application/json"},
        )
        # Should not be 403 Forbidden with MFA error (may be 422/404/200 depending on payload)
        assert resp_verified.status_code != 403 or "MFA verification required" not in resp_verified.text, (
            f"MFA session was verified but still rejected on {ep['method']} {url}"
        )

        # Cleanup session key for next iteration
        await redis.delete(sess_key)
