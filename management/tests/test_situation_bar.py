"""TDD tests for the threat posture situation bar partial.

Covers all 4 states (PROXY_DOWN, NOMINAL, ELEVATED, ACTIVE) by populating
fakeredis with appropriate heartbeat keys and stream entries.
"""

import json
import time

import pytest
from httpx import AsyncClient

from management.api.redis_client import get_redis_client


def _is_html(response) -> bool:
    return "text/html" in response.headers.get("content-type", "")


async def _seed_heartbeat():
    """Set a heartbeat key in the app's shared Redis."""
    r = get_redis_client()
    if r is not None:
        await r.set("proxy:heartbeat:testhost", str(int(time.time())), ex=90)


async def _add_event(action: str, risk_score: int = 0, src_ip: str = "10.0.0.1"):
    """Inject a connection event into the app's shared Redis stream."""
    r = get_redis_client()
    if r is None:
        return
    event = json.dumps({
        "event.action": action,
        "event.risk_score": risk_score,
        "source.ip": src_ip,
        "event.kind": "event",
        "event.category": "network",
    })
    await r.xadd("events:connection", {"event": event})


@pytest.mark.asyncio
async def test_situation_requires_auth(test_client: AsyncClient) -> None:
    """GET /api/v1/partials/situation without token must return 401."""
    response = await test_client.get("/api/v1/partials/situation")
    assert response.status_code == 401, (
        f"Expected 401, got {response.status_code}"
    )


@pytest.mark.asyncio
async def test_situation_returns_html(
    authenticated_client: AsyncClient,
) -> None:
    """GET /api/v1/partials/situation returns 200 with text/html."""
    await _seed_heartbeat()

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert _is_html(response), (
        f"Expected text/html, got: {response.headers.get('content-type')}"
    )


@pytest.mark.asyncio
async def test_state_nominal(
    authenticated_client: AsyncClient,
) -> None:
    """No blocking actions in last 5 min → NOMINAL."""
    await _seed_heartbeat()
    await _add_event("allow", risk_score=0)

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "NOMINAL" in response.text
    assert "All Clear" in response.text


@pytest.mark.asyncio
async def test_state_elevated(
    authenticated_client: AsyncClient,
) -> None:
    """3 blocking actions in last 5 min → ELEVATED."""
    await _seed_heartbeat()
    for i in range(3):
        await _add_event("block", risk_score=60 + i)

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "ELEVATED" in response.text
    assert "3 blocks" in response.text


@pytest.mark.asyncio
async def test_state_active(
    authenticated_client: AsyncClient,
) -> None:
    """15 blocking actions in last 5 min → ACTIVE."""
    await _seed_heartbeat()
    for _ in range(15):
        await _add_event("ban", risk_score=80)

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "ACTIVE" in response.text
    assert "15 blocks" in response.text


@pytest.mark.asyncio
async def test_state_proxy_down(
    authenticated_client: AsyncClient,
) -> None:
    """No heartbeat keys → PROXY_DOWN."""
    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "PROXY_DOWN" in response.text
    assert "heartbeat not detected" in response.text.lower()


@pytest.mark.asyncio
async def test_top_ip_appears(
    authenticated_client: AsyncClient,
) -> None:
    """Multiple IPs in stream — top attacker IP shown in bar."""
    await _seed_heartbeat()
    for _ in range(20):
        await _add_event("block", risk_score=90, src_ip="5.5.5.5")
    await _add_event("allow", risk_score=0, src_ip="1.2.3.4")

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "5.5.5.5" in response.text


@pytest.mark.asyncio
async def test_max_risk_appears(
    authenticated_client: AsyncClient,
) -> None:
    """Highest risk score appears in bar."""
    await _seed_heartbeat()
    await _add_event("block", risk_score=42, src_ip="5.5.5.5")
    await _add_event("block", risk_score=99, src_ip="5.5.5.5")

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "99" in response.text


@pytest.mark.asyncio
async def test_tarpit_actions_count_as_blocks(
    authenticated_client: AsyncClient,
) -> None:
    """tarpit actions should be counted alongside block/ban."""
    await _seed_heartbeat()
    await _add_event("tarpit", risk_score=70)

    response = await authenticated_client.get("/api/v1/partials/situation")
    assert response.status_code == 200
    assert "ELEVATED" in response.text
    assert "1 block" in response.text
