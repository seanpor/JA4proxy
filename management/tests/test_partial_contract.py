"""Route-contract tests for console partials (Phase 824b).

Asserts the two things about the console partials that no other test suite does:
1. Every extracted GET target from templates enforces authentication (returns 401 unauthenticated).
2. Partials render their corresponding panel landmarks even in an empty state.
3. attack-mode-indicator returns 200 text/html and an empty body when inactive.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import AsyncClient

from .hx_targets import hx_targets

GET_TARGETS = sorted({url for method, url, _ in hx_targets() if method == "GET"})

LANDMARKS = {
    "/api/v1/partials/health-cards": "Active Bans",
    "/api/v1/partials/dial": 'aria-label="Dial slider"',
    "/api/v1/partials/audit": 'id="audit-tbody"',
    "/api/v1/partials/intelligence": 'id="intelligence-row"',
    "/api/v1/partials/intelligence-review": 'id="review-content-inner"',
    "/api/v1/partials/attack-top": "No high-activity IPs",
    "/api/v1/partials/attack-fingerprint-table": "No fingerprint data",
    # attack-mode-indicator intentionally absent — see test_attack_mode_indicator_is_empty_when_inactive
}


def _is_html(response: httpx.Response) -> bool:
    return "text/html" in response.headers.get("content-type", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("url", GET_TARGETS)
async def test_partial_requires_auth(test_client: AsyncClient, url: str) -> None:
    """An unauthenticated GET must be 401, not 500 and not 200.

    A 500 means the handler crashed *before* auth ran. A 200 means customer data
    — bans, audit trail, intelligence findings — is readable without a session.
    """
    response = await test_client.get(url)
    assert response.status_code == 401, (
        f"{url} returned {response.status_code} unauthenticated (expected 401)"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("path,landmark", sorted(LANDMARKS.items()))
async def test_partial_renders_its_panel(
    authenticated_client: AsyncClient, path: str, landmark: str
) -> None:
    """Each partial must render its own panel landmark in the empty state."""
    response = await authenticated_client.get(path)
    assert response.status_code == 200
    assert _is_html(response)
    assert landmark in response.text, f"{path} did not render its own panel"


@pytest.mark.asyncio
async def test_attack_mode_indicator_is_empty_when_inactive(
    authenticated_client: AsyncClient,
) -> None:
    """attack-mode-indicator returns an empty body when attack mode is inactive."""
    response = await authenticated_client.get("/api/v1/partials/attack-mode-indicator")
    assert response.status_code == 200
    assert _is_html(response)
    assert response.text == ""
