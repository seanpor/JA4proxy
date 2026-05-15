"""Phase 85 — unit tests for ``analytics.ti_feeds.crowdstrike``.

CrowdStrike Falcon Intel uses OAuth2 client credentials, not TAXII. Tests:
- POST /oauth2/token with scope=indicators:read
- GET /intel/combined/indicators/v1 with Meta.Pagination.Offset cursor
- malicious_confidence threshold filtering

These tests are RED until ``src/analytics/ti_feeds/crowdstrike.py`` exists.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: F401


def _run(coro):
    return asyncio.run(coro)


def _import_cs():
    from src.analytics.ti_feeds.crowdstrike import CrowdStrikeClient

    return CrowdStrikeClient


def _make_cs_config(**overrides):
    from src.analytics.ti_feeds.base import FeedConfig

    defaults = dict(
        id="crowdstrike-falcon",
        type="crowdstrike",
        client_id="cs-client-id",
        client_secret="cs-client-secret-VALUE",
        indicator_types=["ip_address"],
        min_malicious_confidence="high",
        poll_interval_minutes=30,
        ban_ttl_hours=48,
        enabled=True,
    )
    defaults.update(overrides)
    return FeedConfig(**defaults)


# ── OAuth2 token acquisition ──────────────────────────────────────────────────


def test_oauth2_token_endpoint_called_correctly(stub_management_client):
    """The token endpoint URL and scope match the Falcon spec."""
    CrowdStrikeClient = _import_cs()

    captured: dict[str, Any] = {}

    async def _fake_token(client_id: str, client_secret: str, scope: str) -> str:
        captured["client_id"] = client_id
        captured["client_secret"] = client_secret
        captured["scope"] = scope
        return "cs-bearer-tok"

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        token_fetcher=_fake_token,
    )

    _run(client.fetch_bearer_token())

    assert captured["client_id"] == "cs-client-id"
    assert captured["client_secret"] == "cs-client-secret-VALUE"
    assert captured["scope"] == "indicators:read"


def test_oauth2_token_cached(stub_management_client):
    """Token is fetched once across multiple calls until it expires."""
    CrowdStrikeClient = _import_cs()

    fetch_count = {"n": 0}

    async def _fake_token(client_id, client_secret, scope):
        fetch_count["n"] += 1
        return f"tok-{fetch_count['n']}"

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        token_fetcher=_fake_token,
    )
    _run(client.fetch_bearer_token())
    _run(client.fetch_bearer_token())
    _run(client.fetch_bearer_token())
    assert fetch_count["n"] == 1


# ── Cursor pagination ─────────────────────────────────────────────────────────


def test_cursor_pagination(stub_management_client):
    """Pages are fetched until Meta.Pagination.Offset is None / absent."""
    CrowdStrikeClient = _import_cs()

    pages = [
        {
            "resources": [
                {
                    "id": "ind-1",
                    "indicator": "203.0.113.10",
                    "type": "ip_address",
                    "malicious_confidence": "high",
                }
            ],
            "meta": {"pagination": {"offset": "5", "total": 7}},
        },
        {
            "resources": [
                {
                    "id": "ind-2",
                    "indicator": "203.0.113.11",
                    "type": "ip_address",
                    "malicious_confidence": "high",
                }
            ],
            "meta": {"pagination": {"offset": None, "total": 7}},
        },
    ]

    offsets_used: list[str | None] = []

    async def _fetch(filters: str, offset: str | None = None, **kwargs):
        offsets_used.append(offset)
        return pages[len(offsets_used) - 1]

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )

    _run(client.poll())

    assert offsets_used[0] is None
    assert offsets_used[1] == "5"
    paths = [r["path"] for r in stub_management_client.requests]
    assert any("203.0.113.10" in p for p in paths)
    assert any("203.0.113.11" in p for p in paths)


# ── Confidence filter ─────────────────────────────────────────────────────────


def test_confidence_filter_drops_below_threshold(stub_management_client):
    """malicious_confidence=low must be skipped when threshold=high."""
    CrowdStrikeClient = _import_cs()

    async def _fetch(filters: str, offset=None, **kwargs):
        return {
            "resources": [
                {
                    "id": "ind-low",
                    "indicator": "203.0.113.50",
                    "type": "ip_address",
                    "malicious_confidence": "low",
                },
                {
                    "id": "ind-med",
                    "indicator": "203.0.113.51",
                    "type": "ip_address",
                    "malicious_confidence": "medium",
                },
                {
                    "id": "ind-high",
                    "indicator": "203.0.113.52",
                    "type": "ip_address",
                    "malicious_confidence": "high",
                },
            ],
            "meta": {"pagination": {"offset": None}},
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(min_malicious_confidence="high"),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    _run(client.poll())

    paths = [r["path"] for r in stub_management_client.requests]
    assert not any("203.0.113.50" in p for p in paths)
    assert not any("203.0.113.51" in p for p in paths)
    assert any("203.0.113.52" in p for p in paths)


# ── phase-104: coverage gap tests ────────────────────────────────────────────


# ── Token fetcher not set (line 121) ─────────────────────────────────────────


def test_fetch_bearer_token_no_fetcher_raises(stub_management_client):
    """fetch_bearer_token raises RuntimeError when token_fetcher is None."""
    CrowdStrikeClient = _import_cs()

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        token_fetcher=None,
        page_fetcher=None,
    )
    with pytest.raises(RuntimeError, match="requires token_fetcher"):
        _run(client.fetch_bearer_token())


# ── _ensure_token: missing client_id/secret (lines 206-207) ─────────────────


def test_ensure_token_missing_credentials(stub_management_client):
    """_ensure_token raises when client_id or client_secret is unset."""
    CrowdStrikeClient = _import_cs()

    client = CrowdStrikeClient(
        config=_make_cs_config(client_id="", client_secret=""),
        mgmt=stub_management_client,
        state=None,
    )
    # poll() calls _ensure_token internally (no page_fetcher)
    result = _run(client.poll())
    assert any("auth_failed" in e for e in result.errors)


# ── _ensure_token: HTTP error (lines 223-225) ───────────────────────────────


def test_ensure_token_http_error(stub_management_client, monkeypatch):
    """A non-200 from the Falcon auth endpoint is caught and reported."""
    import aiohttp

    CrowdStrikeClient = _import_cs()

    # Mock aiohttp.ClientSession to simulate HTTP 401
    mock_resp = AsyncMock()
    mock_resp.status = 401
    mock_resp.text = AsyncMock(return_value="Unauthorized")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(aiohttp, "ClientSession", MagicMock(return_value=mock_session))

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
    )
    result = _run(client.poll())
    assert any("auth_failed" in e for e in result.errors)
    assert any("HTTP 401" in e for e in result.errors)


# ── _ensure_token: missing access_token (lines 227-229) ─────────────────────


def test_ensure_token_missing_access_token(stub_management_client, monkeypatch):
    """Auth response without access_token raises RuntimeError."""
    import aiohttp

    CrowdStrikeClient = _import_cs()

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"expires_in": 1800})  # no access_token
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(aiohttp, "ClientSession", MagicMock(return_value=mock_session))

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
    )
    result = _run(client.poll())
    assert any("auth_failed" in e for e in result.errors)
    assert any("missing access_token" in e for e in result.errors)


# ── _ensure_token: fresh token not re-fetched (line 204) ────────────────────


def test_ensure_token_skips_refresh_when_fresh(stub_management_client, monkeypatch):
    """A fresh token is not re-fetched on the second poll."""
    import time as time_mod

    import aiohttp

    CrowdStrikeClient = _import_cs()

    fetch_count = {"n": 0}

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={"access_token": "test-tok-xxx", "expires_in": 1800}
    )
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_get_resp = AsyncMock()
    mock_get_resp.status = 200
    mock_get_resp.json = AsyncMock(
        return_value={"resources": [], "meta": {"pagination": {}}}
    )
    mock_get_resp.__aenter__ = AsyncMock(return_value=mock_get_resp)
    mock_get_resp.__aexit__ = AsyncMock(return_value=False)

    def _count_post(*args, **kwargs):
        fetch_count["n"] += 1
        return mock_resp

    mock_session = AsyncMock()
    mock_session.post = MagicMock(side_effect=_count_post)
    mock_session.get = MagicMock(return_value=mock_get_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(aiohttp, "ClientSession", MagicMock(return_value=mock_session))

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
    )
    # First poll — fetches token
    _run(client.poll())
    assert fetch_count["n"] == 1
    # Second poll — token is still fresh, should skip
    _run(client.poll())
    assert fetch_count["n"] == 1


# ── page_fetcher error path (lines 158-166) ─────────────────────────────────


def test_page_fetcher_exception_records_error(stub_management_client):
    """An exception from page_fetcher is caught and recorded."""
    CrowdStrikeClient = _import_cs()

    async def _boom(filters, offset=None, **kwargs):
        raise ConnectionError("test-fetcher-down")

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_boom,
    )
    result = _run(client.poll())
    assert any("poll_failed" in e for e in result.errors)


# ── page_fetcher non-dict response (line 302-303) ───────────────────────────


def test_page_fetcher_non_dict_raises(stub_management_client):
    """A non-dict page from page_fetcher raises RuntimeError."""
    CrowdStrikeClient = _import_cs()

    async def _bad_page(filters, offset=None, **kwargs):
        return "not-a-dict"

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_bad_page,
    )
    result = _run(client.poll())
    assert any("poll_failed" in e for e in result.errors)


# ── Pagination with string offset token (lines 306-311) ─────────────────────


def test_pagination_stops_on_missing_offset(stub_management_client):
    """Pagination stops when meta.pagination.offset is None."""
    CrowdStrikeClient = _import_cs()

    call_count = {"n": 0}

    async def _fetch(filters, offset=None, **kwargs):
        call_count["n"] += 1
        return {
            "resources": [
                {
                    "id": f"ind-{call_count['n']}",
                    "indicator": f"203.0.113.{call_count['n']}",
                    "malicious_confidence": "high",
                },
            ],
            "meta": {"pagination": {}},  # no offset key
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    _run(client.poll())
    assert call_count["n"] == 1  # only one page fetched


def test_pagination_follows_string_offset(stub_management_client):
    """Pagination follows string offset tokens across pages."""
    CrowdStrikeClient = _import_cs()

    pages = [
        {
            "resources": [
                {"id": "a1", "indicator": "203.0.113.1", "malicious_confidence": "high"}
            ],
            "meta": {"pagination": {"offset": "cursor-abc"}},
        },
        {
            "resources": [
                {"id": "a2", "indicator": "203.0.113.2", "malicious_confidence": "high"}
            ],
            "meta": {"pagination": {"offset": "cursor-def"}},
        },
        {
            "resources": [
                {"id": "a3", "indicator": "203.0.113.3", "malicious_confidence": "high"}
            ],
            "meta": {"pagination": {}},
        },
    ]

    offsets: list[str | None] = []

    async def _fetch(filters, offset=None, **kwargs):
        offsets.append(offset)
        return pages[len(offsets) - 1]

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    _run(client.poll())
    assert offsets == [None, "cursor-abc", "cursor-def"]
    assert len(stub_management_client.requests) == 3


# ── Ban create error (lines 345-347) ────────────────────────────────────────


def test_ban_create_error_continues_processing(stub_management_client):
    """A failed ban POST records an error but processes remaining indicators."""
    CrowdStrikeClient = _import_cs()

    stub_management_client.fail_path("POST", "/api/v1/bans/203.0.113.1", 500)

    async def _fetch(filters, offset=None, **kwargs):
        return {
            "resources": [
                {
                    "id": "f1",
                    "indicator": "203.0.113.1",
                    "malicious_confidence": "high",
                },
                {
                    "id": "f2",
                    "indicator": "203.0.113.2",
                    "malicious_confidence": "high",
                },
            ],
            "meta": {"pagination": {}},
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    result = _run(client.poll())
    assert any("ban create failed" in e for e in result.errors)
    assert any("203.0.113.2" in c[1] for c in result.created)


# ── state.mark() for bans (lines 348-349) ───────────────────────────────────


def test_state_mark_called_for_ban(stub_management_client):
    """When state is not None, state.mark() is called for each indicator."""
    CrowdStrikeClient = _import_cs()

    mock_state = MagicMock()
    mock_state.mark = AsyncMock()

    async def _fetch(filters, offset=None, **kwargs):
        return {
            "resources": [
                {
                    "id": "f1",
                    "indicator": "203.0.113.1",
                    "malicious_confidence": "high",
                },
            ],
            "meta": {"pagination": {}},
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=mock_state,
        page_fetcher=_fetch,
    )
    result = _run(client.poll())
    assert len(result.created) == 1
    mock_state.mark.assert_awaited_once()
    call_args = mock_state.mark.call_args
    assert call_args[0][0] == "crowdstrike-falcon"
    assert call_args[1]["handle"] == "203.0.113.1"
    assert call_args[1]["kind"] == "ban"


# ── Non-string indicator (line 323-324) ─────────────────────────────────────


def test_non_string_indicator_skipped(stub_management_client):
    """A non-string indicator value is counted as unsupported_pattern."""
    CrowdStrikeClient = _import_cs()

    async def _fetch(filters, offset=None, **kwargs):
        return {
            "resources": [
                {"id": "f1", "indicator": 12345, "malicious_confidence": "high"},
                {"id": "f2", "indicator": None, "malicious_confidence": "high"},
                {
                    "id": "f3",
                    "indicator": "203.0.113.1",
                    "malicious_confidence": "high",
                },
            ],
            "meta": {"pagination": {}},
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern == 2
    assert len(result.created) == 1


# ── __repr__ redacts secrets (lines 131-141) ────────────────────────────────


def test_repr_redacts_secrets(stub_management_client):
    """__repr__ does not leak client_id or client_secret."""
    CrowdStrikeClient = _import_cs()

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
    )
    r = repr(client)
    assert "cs-client-secret-VALUE" not in r
    assert "cs-client-id" not in r
    assert "<redacted>" in r


# ── _resolve_falcon_urls (lines 53-60) ──────────────────────────────────────


def test_resolve_falcon_urls_default():
    """Default URL resolves to the US-1 endpoints."""
    from src.analytics.ti_feeds.crowdstrike import _resolve_falcon_urls

    config = _make_cs_config(url="")
    auth_url, indicators_url = _resolve_falcon_urls(config)
    assert auth_url == "https://api.crowdstrike.com/oauth2/token"
    assert indicators_url == "https://api.crowdstrike.com/intel/combined/indicators/v1"


def test_resolve_falcon_urls_eu():
    """EU-1 base URL resolves correctly."""
    from src.analytics.ti_feeds.crowdstrike import _resolve_falcon_urls

    config = _make_cs_config(url="https://api.eu-1.crowdstrike.com/")
    auth_url, indicators_url = _resolve_falcon_urls(config)
    assert auth_url == "https://api.eu-1.crowdstrike.com/oauth2/token"


# ── _poll_all_pages HTTP error (lines 273-275) ──────────────────────────────


def test_poll_all_pages_http_error(stub_management_client, monkeypatch):
    """A non-200 from the indicators endpoint is caught and reported."""
    import aiohttp

    CrowdStrikeClient = _import_cs()

    # Mock auth to succeed
    mock_auth_resp = AsyncMock()
    mock_auth_resp.status = 200
    mock_auth_resp.json = AsyncMock(
        return_value={"access_token": "test-tok-xxx", "expires_in": 1800}
    )
    mock_auth_resp.__aenter__ = AsyncMock(return_value=mock_auth_resp)
    mock_auth_resp.__aexit__ = AsyncMock(return_value=False)

    # Mock indicators to fail
    mock_ind_resp = AsyncMock()
    mock_ind_resp.status = 429
    mock_ind_resp.text = AsyncMock(return_value="Rate limited")
    mock_ind_resp.__aenter__ = AsyncMock(return_value=mock_ind_resp)
    mock_ind_resp.__aexit__ = AsyncMock(return_value=False)

    call_idx = {"n": 0}

    def _make_session(*args, **kwargs):
        mock_session = AsyncMock()

        def _post(*a, **kw):
            return mock_auth_resp

        def _get(*a, **kw):
            return mock_ind_resp

        mock_session.post = MagicMock(side_effect=_post)
        mock_session.get = MagicMock(side_effect=_get)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        return mock_session

    monkeypatch.setattr(aiohttp, "ClientSession", _make_session)

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
    )
    result = _run(client.poll())
    assert any("poll_failed" in e for e in result.errors)


# ── Null meta/pagination handling (lines 281-282, 306-307) ───────────────────


def test_null_meta_stops_pagination(stub_management_client):
    """When meta or pagination is None/missing, pagination stops."""
    CrowdStrikeClient = _import_cs()

    async def _fetch(filters, offset=None, **kwargs):
        return {
            "resources": [
                {"id": "x1", "indicator": "203.0.113.1", "malicious_confidence": "high"}
            ],
            "meta": None,
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    _run(client.poll())
    assert len(stub_management_client.requests) == 1


# ── poll_duration_s set on result ────────────────────────────────────────────


def test_poll_duration_set(stub_management_client):
    """poll_duration_s is populated regardless of path."""
    CrowdStrikeClient = _import_cs()

    async def _fetch(filters, offset=None, **kwargs):
        return {"resources": [], "meta": {"pagination": {}}}

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    result = _run(client.poll())
    assert result.poll_duration_s >= 0


# ── indicator "value" fallback key (line 322) ────────────────────────────────


def test_value_fallback_key(stub_management_client):
    """When 'indicator' key is missing, 'value' key is used."""
    CrowdStrikeClient = _import_cs()

    async def _fetch(filters, offset=None, **kwargs):
        return {
            "resources": [
                {"id": "v1", "value": "203.0.113.99", "malicious_confidence": "high"},
            ],
            "meta": {"pagination": {}},
        }

    client = CrowdStrikeClient(
        config=_make_cs_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetcher=_fetch,
    )
    result = _run(client.poll())
    assert any("203.0.113.99" in c[1] for c in result.created)
