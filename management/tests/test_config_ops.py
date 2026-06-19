"""TDD tests for the config reload endpoint.

Covers
------
- POST /api/v1/config/reload publishes to the config:reload channel (colon —
  the channel the Go proxy actually subscribes to; a dot ``config.reload`` reaches
  no proxy)
- Audit log entry created
- Requires authentication
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_config_reload_success(authenticated_client: AsyncClient) -> None:
    """POST /api/v1/config/reload returns 200."""
    r = await authenticated_client.post("/api/v1/config/reload")
    assert r.status_code == 200
    data = r.json()
    assert "reload" in data["message"].lower()


@pytest.mark.asyncio
async def test_config_reload_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Config reload writes an audit log entry."""
    await authenticated_client.post("/api/v1/config/reload")

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    # MFA/SSO Hardening C5: enhanced audit schema
    assert entry["action_type"] == "config.reload"
    assert "timestamp" in entry
    assert "actor_id" in entry


@pytest.mark.asyncio
async def test_config_reload_requires_auth(test_client: AsyncClient) -> None:
    """POST /api/v1/config/reload requires authentication."""
    r = await test_client.post(
        "/api/v1/config/reload",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_config_reload_response_structure(
    authenticated_client: AsyncClient,
) -> None:
    """Config reload response includes expected fields."""
    r = await authenticated_client.post("/api/v1/config/reload")
    assert r.status_code == 200
    data = r.json()
    assert "message" in data
    assert "published_to" in data
    # Regression: must be the colon channel the Go proxy subscribes to, never
    # the dot form (config.reload), which reaches no proxy.
    assert data["published_to"] == "config:reload"
