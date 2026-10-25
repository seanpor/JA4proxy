"""Tests for /api/v1/health/ui endpoint (Phase 824d).

Verifies the four-state console health endpoint:
1. Requires authentication (401 when anonymous).
2. Healthy/empty baseline returns status GREEN with every panel OK or EMPTY, no BROKEN.
3. Redis stopped yields DEGRADED panels (e.g. health-cards), NOT RED (status remains GREEN).
4. Deliberately broken panel returns BROKEN and makes aggregate status RED (demonstrated).
5. Legitimate empty state (EMPTY) does NOT make aggregate RED.
6. Probes exclude /api/v1/health/ui itself (no recursion).
7. Error strings from upstream exceptions are never leaked in reasons.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import AsyncClient

from management.api.redis_client import get_redis


@pytest.mark.asyncio
async def test_ui_health_requires_auth(test_client: AsyncClient) -> None:
    """Anonymous request to /api/v1/health/ui must return 401."""
    resp = await test_client.get("/api/v1/health/ui")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ui_health_baseline_green(authenticated_client: AsyncClient) -> None:
    """In baseline test state, aggregate status must be GREEN (no BROKEN panels)."""
    resp = await authenticated_client.get("/api/v1/health/ui")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "GREEN"
    assert isinstance(data["degraded"], int)
    assert isinstance(data["panels"], list)
    assert len(data["panels"]) > 0

    # Ensure no panels are BROKEN
    broken_panels = [p for p in data["panels"] if p.get("state") == "BROKEN"]
    assert not broken_panels, f"Expected 0 broken panels, got: {broken_panels}"

    # Verify self-exclusion: /api/v1/health/ui is not in panels
    panel_ids = [p["id"] for p in data["panels"]]
    assert "ui" not in panel_ids
    assert "health/ui" not in panel_ids


@pytest.mark.asyncio
async def test_ui_health_redis_down_is_degraded_not_red(
    authenticated_client: AsyncClient,
) -> None:
    """When Redis is down, dependent panels report DEGRADED and status remains GREEN."""
    app = authenticated_client._transport.app  # type: ignore[attr-defined]

    class FailingRedis:
        def __getattr__(self, name: str):
            async def method(*args, **kwargs):
                raise ConnectionError("redis connection refused")
            return method

    async def fake_failing_redis():
        yield FailingRedis()

    orig_override = app.dependency_overrides.get(get_redis)
    app.dependency_overrides[get_redis] = fake_failing_redis
    try:
        resp = await authenticated_client.get("/api/v1/health/ui")
        assert resp.status_code == 200
        data = resp.json()
        # DEGRADED panels must not make the aggregate RED
        assert data["status"] == "GREEN"
        assert data["degraded"] > 0

        # health-cards should be marked DEGRADED with reason dependency_unavailable
        health_cards = next((p for p in data["panels"] if p["id"] == "health-cards"), None)
        assert health_cards is not None
        assert health_cards["state"] == "DEGRADED"
        assert health_cards["reason"] == "dependency_unavailable"
    finally:
        if orig_override is not None:
            app.dependency_overrides[get_redis] = orig_override
        else:
            app.dependency_overrides.pop(get_redis, None)


@pytest.mark.asyncio
async def test_ui_health_broken_panel_makes_status_red(
    authenticated_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Demonstrate failure: a 500 error on any partial causes aggregate RED."""
    from management.api.routes import ui_health as ui_health_module

    orig_get_target_panels = ui_health_module._get_target_panels

    # Inject a non-existent route into the probed panels
    def mocked_panels():
        panels = orig_get_target_panels()
        panels["deliberately-broken"] = "/api/v1/partials/non-existent-route-404"
        return panels

    monkeypatch.setattr(ui_health_module, "_get_target_panels", mocked_panels)

    resp = await authenticated_client.get("/api/v1/health/ui")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "RED"

    broken = next((p for p in data["panels"] if p["id"] == "deliberately-broken"), None)
    assert broken is not None
    assert broken["state"] == "BROKEN"
    assert broken["reason"] == "route_missing"


@pytest.mark.asyncio
async def test_ui_health_timeout_makes_status_red(
    authenticated_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Demonstrate timeout: a timed out partial causes aggregate RED."""
    from management.api.routes import ui_health as ui_health_module

    orig_get = AsyncClient.get

    async def mock_get(self, url, *args, **kwargs):
        # Only timeout on internal probe requests, not on /api/v1/health/ui itself
        if "deliberately-timeout" in str(url):
            raise httpx.TimeoutException("mock timeout")
        return await orig_get(self, url, *args, **kwargs)

    orig_get_target_panels = ui_health_module._get_target_panels

    def mocked_panels():
        panels = orig_get_target_panels()
        panels["deliberately-timeout"] = "/api/v1/partials/deliberately-timeout"
        return panels

    monkeypatch.setattr(ui_health_module, "_get_target_panels", mocked_panels)
    monkeypatch.setattr(AsyncClient, "get", mock_get)

    resp = await authenticated_client.get("/api/v1/health/ui")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "RED"
    timed_out = next((p for p in data["panels"] if p["id"] == "deliberately-timeout"), None)
    assert timed_out is not None
    assert timed_out["state"] == "BROKEN"
    assert timed_out["reason"] == "timeout"


@pytest.mark.asyncio
async def test_ui_health_no_exception_leakage(authenticated_client: AsyncClient) -> None:
    """Reason codes must be members of the fixed safe vocabulary, never str(exc)."""
    ALLOWED_REASONS = {
        "route_missing",
        "http_5xx",
        "non_html",
        "timeout",
        "empty",
        "dependency_unavailable",
    }
    resp = await authenticated_client.get("/api/v1/health/ui")
    assert resp.status_code == 200
    data = resp.json()
    for p in data["panels"]:
        reason = p.get("reason")
        if reason is not None:
            assert reason in ALLOWED_REASONS, f"Unexpected reason '{reason}' in panel {p['id']}"
