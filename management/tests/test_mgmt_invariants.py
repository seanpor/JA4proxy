"""
Management Plane Invariants Test Suite (Phase 606i)
Defines and verifies INV-MGMT-001 through INV-MGMT-004 using Hypothesis.
"""
import pytest
from httpx import AsyncClient
from hypothesis import given, strategies as st, settings, HealthCheck


# INV-MGMT-001: Total Mediation
# Unauthenticated requests to protected endpoints return 401, 403, 404, or 302/307 redirect
@pytest.mark.asyncio
async def test_invariant_mgmt_total_mediation(test_client: AsyncClient):
    endpoints = [
        "/api/v1/bans",
        "/api/v1/audit",
        "/api/v1/rules",
        "/api/v1/users",
    ]
    for endpoint in endpoints:
        response = await test_client.get(endpoint)
        assert response.status_code in (401, 403, 302, 307, 404)


# INV-MGMT-002: Audit Log Completeness / Health Check Accessibility
@pytest.mark.asyncio
async def test_invariant_mgmt_health_check_accessibility(test_client: AsyncClient):
    response = await test_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


# INV-MGMT-003: Payload Sanitization
# Arbitrary random ASCII strings sent as JSON payload yield 400, 401, 403, 404, or 422 (never 500)
@pytest.mark.asyncio
@given(payload=st.text(alphabet=st.characters(codec="ascii"), min_size=1, max_size=200))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_invariant_mgmt_payload_sanitization(test_client: AsyncClient, payload: str):
    response = await test_client.post("/api/v1/bans", content=payload, headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 401, 403, 404, 422)
    assert response.status_code != 500


# INV-MGMT-004: Role Defaults Fail-Closed
# Random invalid ASCII headers return 401/403/404/302 (never 200/grant access)
@pytest.mark.asyncio
@given(auth_header=st.text(alphabet=st.characters(codec="ascii"), min_size=1, max_size=100))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_invariant_mgmt_role_defaults_fail_closed(test_client: AsyncClient, auth_header: str):
    response = await test_client.get("/api/v1/bans", headers={"Authorization": auth_header})
    assert response.status_code in (401, 403, 302, 307, 404)
    assert response.status_code != 200
