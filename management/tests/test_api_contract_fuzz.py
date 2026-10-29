"""Management API Contract & Schema-Driven Fuzzing Suite (Phase 853).

Validates:
- No-500 Invariant across datacenter policy, config reload, bans, and token auth.
- Clean 4xx/422 responses for malformed or oversized inputs.
- Standard JSON error schema compliance ({"detail": ...}).
"""

import urllib.parse

import pytest
from httpx import AsyncClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st


@pytest.mark.asyncio
@given(
    payload=st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.one_of(
            st.text(max_size=100),
            st.integers(),
            st.booleans(),
            st.lists(st.text(max_size=20), max_size=5),
        ),
        max_size=10,
    )
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_fuzz_datacenter_policy_endpoint(
    authenticated_client: AsyncClient, payload: dict
) -> None:
    """Fuzz PUT /api/v1/datacenter-policy with arbitrary dictionary structures.

    Must never return 500 Internal Server Error.
    """
    response = await authenticated_client.put(
        "/api/v1/datacenter-policy", json=payload
    )
    assert response.status_code != 500
    assert response.status_code in (200, 400, 422)
    if response.status_code in (400, 422):
        data = response.json()
        assert "detail" in data


@pytest.mark.asyncio
@given(
    payload=st.one_of(
        st.text(max_size=200),
        st.binary(max_size=200),
        st.dictionaries(keys=st.text(), values=st.text(), max_size=5),
    )
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_fuzz_config_reload_endpoint(
    authenticated_client: AsyncClient, payload: object
) -> None:
    """Fuzz POST /api/v1/config/reload with arbitrary payloads and headers.

    Must return 200 or 4xx, never 500.
    """
    if isinstance(payload, bytes):
        response = await authenticated_client.post(
            "/api/v1/config/reload", content=payload
        )
    elif isinstance(payload, str):
        response = await authenticated_client.post(
            "/api/v1/config/reload", content=payload, headers={"Content-Type": "application/json"}
        )
    else:
        response = await authenticated_client.post(
            "/api/v1/config/reload", json=payload
        )
    assert response.status_code != 500
    assert response.status_code in (200, 400, 422)


@pytest.mark.asyncio
@given(
    ip=st.text(min_size=1, max_size=100),
    ttl=st.integers(min_value=-1000, max_value=10_000_000),
    reason=st.text(max_size=200),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_fuzz_bans_crud_endpoints(
    authenticated_client: AsyncClient, ip: str, ttl: int, reason: str
) -> None:
    """Fuzz POST /api/v1/bans/{ip} with arbitrary IP strings and TTL bounds.

    Must return 200, 400, or 422 without throwing unhandled exceptions.
    """
    quoted_ip = urllib.parse.quote(ip, safe="")
    response = await authenticated_client.post(
        f"/api/v1/bans/{quoted_ip}",
        json={"ttl": ttl, "reason": reason},
    )
    assert response.status_code != 500
    assert response.status_code in (200, 201, 400, 404, 422)
    if response.status_code in (400, 422):
        data = response.json()
        assert "detail" in data


@pytest.mark.asyncio
@given(token=st.text(alphabet=st.characters(codec="ascii"), min_size=1, max_size=150))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_fuzz_auth_headers_and_tokens(
    test_client: AsyncClient, token: str
) -> None:
    """Fuzz Authorization header with arbitrary tokens.

    Must reject with 401/403 without 500 exceptions or disclosure.
    """
    response = await test_client.get(
        "/api/v1/bans",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code in (401, 403, 302, 307)
    assert response.status_code != 500


@pytest.mark.asyncio
@given(
    entries=st.lists(st.text(max_size=50), min_size=0, max_size=10),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_fuzz_canonical_lists_crud(
    authenticated_client: AsyncClient, entries: list[str]
) -> None:
    """Fuzz list creation/query endpoints with arbitrary strings and duplicates.

    Must return 2xx or 4xx, never 500.
    """
    response = await authenticated_client.post(
        "/api/v1/allowlist",
        json={"entries": entries},
    )
    assert response.status_code != 500
    assert response.status_code in (200, 201, 400, 404, 422)
