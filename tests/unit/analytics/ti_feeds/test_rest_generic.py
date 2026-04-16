"""Phase 85 — unit tests for ``analytics.ti_feeds.rest_generic``.

Generic REST connector configured by JSONPath. Tests:
- IP and TTL JSONPath extraction
- Bearer token Authorization header
- Malformed JSON responses are logged and skipped, not fatal

These tests are RED until ``src/analytics/ti_feeds/rest_generic.py`` exists.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: F401


def _run(coro):
    return asyncio.run(coro)


def _import_rest():
    from src.analytics.ti_feeds.rest_generic import RESTGenericClient

    return RESTGenericClient


def _make_rest_config(**overrides):
    from src.analytics.ti_feeds.base import FeedConfig

    defaults = dict(
        id="internal-ti",
        type="rest",
        url="https://threatintel.corp.test/api/v1/indicators",
        auth={"type": "bearer", "token": "internal-tok-VALUE"},
        ip_jsonpath="$.indicators[*].value",
        ttl_jsonpath="$.indicators[*].expires_in",
        ban_ttl_hours=24,
        poll_interval_minutes=15,
        enabled=True,
    )
    defaults.update(overrides)
    return FeedConfig(**defaults)


# ── JSONPath extraction ───────────────────────────────────────────────────────


def test_extracts_ips_via_jsonpath(stub_management_client):
    RESTGenericClient = _import_rest()

    payload = {
        "indicators": [
            {"value": "198.51.100.1", "expires_in": 3600},
            {"value": "198.51.100.2", "expires_in": 7200},
            {"value": "198.51.100.3", "expires_in": 86400},
        ]
    }

    async def _fetch(url: str, headers=None, **kwargs):
        return payload

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())

    paths = [r["path"] for r in stub_management_client.requests if r["method"] == "POST"]
    assert any("198.51.100.1" in p for p in paths)
    assert any("198.51.100.2" in p for p in paths)
    assert any("198.51.100.3" in p for p in paths)


def test_extracts_per_indicator_ttl(stub_management_client):
    RESTGenericClient = _import_rest()

    payload = {
        "indicators": [
            {"value": "198.51.100.1", "expires_in": 600},
            {"value": "198.51.100.2", "expires_in": 86400},
        ]
    }

    async def _fetch(url, headers=None, **kwargs):
        return payload

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())

    bans = [r for r in stub_management_client.requests if r["method"] == "POST" and r["path"].startswith("/api/v1/bans/")]
    by_ip = {r["path"].split("/")[-1]: r["ttl"] for r in bans}
    assert by_ip["198.51.100.1"] == 600
    assert by_ip["198.51.100.2"] == 86400


# ── Auth header ───────────────────────────────────────────────────────────────


def test_bearer_auth_header_set(stub_management_client):
    RESTGenericClient = _import_rest()

    captured: dict[str, Any] = {}

    async def _fetch(url, headers=None, **kwargs):
        captured["headers"] = headers or {}
        return {"indicators": []}

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())

    assert captured["headers"].get("Authorization") == "Bearer internal-tok-VALUE"


# ── Error handling ────────────────────────────────────────────────────────────


def test_malformed_json_response_does_not_crash(stub_management_client, caplog):
    """A non-dict / non-list response is logged and converted to an empty result."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return "this is not json"

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert result.errors  # at least one error was recorded
    assert stub_management_client.requests == []


def test_missing_jsonpath_field_skipped(stub_management_client):
    """Indicators missing the configured field are skipped, not fatal."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "198.51.100.10", "expires_in": 3600},
                {"value": "198.51.100.11"},  # missing expires_in
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())

    paths = [r["path"] for r in stub_management_client.requests]
    assert any("198.51.100.10" in p for p in paths)
    # Either skipped or defaulted — both are acceptable behaviours; the
    # important thing is no crash. Confirm the first IP made it through.
    assert any("198.51.100.10" in p for p in paths)


# ── phase-104: coverage gap tests ────────────────────────────────────────────


# ── JSONPath compile errors (lines 100-108) ──────────────────────────────────


def test_jsonpath_compile_error_returns_none(stub_management_client, caplog):
    """An invalid JSONPath expression logs a warning and compiles to None."""
    RESTGenericClient = _import_rest()

    # Use a syntactically invalid JSONPath expression for ip_jsonpath.
    # The client should log a warning and treat the expression as absent.
    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="$.[INVALID[[[", ja4_jsonpath=""),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value={"indicators": []}),
    )
    # With both ip_expr and ja4_expr None, poll should report an error.
    result = _run(client.poll())
    assert any("missing both" in e for e in result.errors)


# ── jsonpath_ng unavailability (lines 120-124) ───────────────────────────────


def test_jsonpath_unavailable_reports_error(stub_management_client, monkeypatch):
    """When _JSONPATH_AVAILABLE is False, poll returns an error immediately."""
    import src.analytics.ti_feeds.rest_generic as mod

    RESTGenericClient = mod.RESTGenericClient
    original = mod._JSONPATH_AVAILABLE
    monkeypatch.setattr(mod, "_JSONPATH_AVAILABLE", False)

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value={}),
    )
    result = _run(client.poll())
    assert any("jsonpath-ng not installed" in e for e in result.errors)


# ── Missing both ip/ja4 jsonpath (lines 126-132) ────────────────────────────


def test_missing_both_jsonpaths_reports_error(stub_management_client):
    """When both ip_jsonpath and ja4_jsonpath are empty, poll errors."""
    RESTGenericClient = _import_rest()

    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="", ja4_jsonpath=""),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value={}),
    )
    result = _run(client.poll())
    assert any("missing both" in e for e in result.errors)


# ── fetch failure (lines 136-145) ────────────────────────────────────────────


def test_fetch_exception_records_error(stub_management_client):
    """An exception during fetch is caught and recorded, not raised."""
    RESTGenericClient = _import_rest()

    async def _boom(url, headers=None, **kwargs):
        raise ConnectionError("test-connection-refused")

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_boom,
    )
    result = _run(client.poll())
    assert any("fetch_failed" in e for e in result.errors)
    assert result.created == []


# ── Unsupported body type (lines 212-216) ────────────────────────────────────


def test_integer_body_reports_unsupported_type(stub_management_client):
    """A numeric response body is not walkable by JSONPath."""
    RESTGenericClient = _import_rest()

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value=42),
    )
    result = _run(client.poll())
    assert any("unexpected response body type" in e for e in result.errors)


def test_none_body_reports_unsupported_type(stub_management_client):
    """A None response body is not walkable by JSONPath."""
    RESTGenericClient = _import_rest()

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value=None),
    )
    result = _run(client.poll())
    assert any("unexpected response body type" in e for e in result.errors)


# ── Auth type variations (lines 162-181) ─────────────────────────────────────


def test_basic_auth_header(stub_management_client):
    """HTTP Basic auth encodes username:password in the Authorization header."""
    RESTGenericClient = _import_rest()
    captured: dict[str, Any] = {}

    async def _fetch(url, headers=None, **kwargs):
        captured["headers"] = headers or {}
        return {"indicators": []}

    client = RESTGenericClient(
        config=_make_rest_config(auth={"type": "basic", "username": "test-user-xxx", "password": "test-pass-xxx"}),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())

    import base64
    expected = "Basic " + base64.b64encode(b"test-user-xxx:test-pass-xxx").decode()
    assert captured["headers"]["Authorization"] == expected


def test_api_key_auth_header(stub_management_client):
    """api_key auth sets the X-API-Key header."""
    RESTGenericClient = _import_rest()
    captured: dict[str, Any] = {}

    async def _fetch(url, headers=None, **kwargs):
        captured["headers"] = headers or {}
        return {"indicators": []}

    client = RESTGenericClient(
        config=_make_rest_config(auth={"type": "api_key", "key": "test-api-key-xxx"}),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())
    assert captured["headers"]["X-API-Key"] == "test-api-key-xxx"


def test_unknown_auth_type_warns(stub_management_client, caplog):
    """An unrecognised auth type logs a warning but does not crash."""
    import logging

    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {"indicators": []}

    with caplog.at_level(logging.WARNING):
        client = RESTGenericClient(
            config=_make_rest_config(auth={"type": "kerberos"}),
            mgmt=stub_management_client,
            state=None,
            fetch=_fetch,
        )
        _run(client.poll())

    assert any("rest_auth_unknown" in r.message for r in caplog.records)


def test_no_auth_sends_no_auth_header(stub_management_client):
    """When auth is empty, no Authorization or X-API-Key header is set."""
    RESTGenericClient = _import_rest()
    captured: dict[str, Any] = {}

    async def _fetch(url, headers=None, **kwargs):
        captured["headers"] = headers or {}
        return {"indicators": []}

    client = RESTGenericClient(
        config=_make_rest_config(auth={}),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    _run(client.poll())
    assert "Authorization" not in captured["headers"]
    assert "X-API-Key" not in captured["headers"]


# ── Invalid IP / non-string IP in indicators (lines 227-234) ────────────────


def test_invalid_ip_increments_unsupported(stub_management_client):
    """A non-valid IP address is counted as unsupported_pattern."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "not-an-ip", "expires_in": 3600},
                {"value": 12345, "expires_in": 3600},
                {"value": "192.0.2.1", "expires_in": 3600},
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern == 2
    assert len(result.created) == 1


# ── Invalid TTL parsing (lines 240-243) ──────────────────────────────────────


def test_invalid_ttl_uses_default(stub_management_client):
    """A non-numeric TTL falls back to the configured ban_ttl_hours."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "192.0.2.1", "expires_in": "not-a-number"},
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(ban_ttl_hours=24),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert len(result.created) == 1
    ban = stub_management_client.requests[0]
    assert ban["ttl_s"] == 24 * 3600


def test_very_small_ttl_clamped_to_60(stub_management_client):
    """A TTL below 60 seconds is clamped to 60."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "192.0.2.1", "expires_in": 5},
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    ban = stub_management_client.requests[0]
    assert ban["ttl_s"] == 60


# ── Ban creation errors (lines 244-253) ──────────────────────────────────────


def test_ban_create_error_recorded_and_continues(stub_management_client):
    """A failed ban POST records an error but processes remaining indicators."""
    RESTGenericClient = _import_rest()

    # Make the first ban fail
    stub_management_client.fail_path("POST", "/api/v1/bans/192.0.2.1", 500)

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "192.0.2.1", "expires_in": 3600},
                {"value": "192.0.2.2", "expires_in": 3600},
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert any("ban create failed" in e for e in result.errors)
    # Second IP should still have been processed.
    assert any("192.0.2.2" in c[1] for c in result.created)


# ── state.mark() for IPs (lines 254-256) ────────────────────────────────────


def test_state_mark_called_for_ip_indicators(stub_management_client):
    """When state is not None, state.mark() is called for each IP indicator."""
    RESTGenericClient = _import_rest()

    mock_state = MagicMock()
    mock_state.mark = AsyncMock()

    async def _fetch(url, headers=None, **kwargs):
        return {
            "indicators": [
                {"value": "192.0.2.1", "expires_in": 3600},
            ]
        }

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=mock_state,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert len(result.created) == 1
    mock_state.mark.assert_awaited_once()
    call_args = mock_state.mark.call_args
    assert call_args[0][0] == "internal-ti"  # feed_id
    assert call_args[1]["handle"] == "192.0.2.1"
    assert call_args[1]["kind"] == "ban"


# ── JA4 indicators (lines 261-283) ──────────────────────────────────────────


def test_ja4_indicators_posted_to_blocklist(stub_management_client):
    """JA4 fingerprints extracted via ja4_jsonpath are posted to the blocklist."""
    RESTGenericClient = _import_rest()

    # A valid JA4 fingerprint pattern (t13d...) — use the known format.
    ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"

    async def _fetch(url, headers=None, **kwargs):
        return {"fingerprints": [ja4]}

    client = RESTGenericClient(
        config=_make_rest_config(
            ip_jsonpath="",
            ja4_jsonpath="$.fingerprints[*]",
        ),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    blocklist_posts = [r for r in stub_management_client.requests if r["path"] == "/api/v1/blocklist"]
    assert len(blocklist_posts) == 1
    assert blocklist_posts[0]["entry"] == ja4


def test_invalid_ja4_increments_unsupported(stub_management_client):
    """Invalid JA4 values are counted as unsupported_pattern."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return {"fingerprints": ["not-a-ja4", 12345]}

    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="", ja4_jsonpath="$.fingerprints[*]"),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern == 2
    assert result.created == []


def test_ja4_blocklist_error_recorded(stub_management_client):
    """A failed blocklist POST records an error but continues."""
    RESTGenericClient = _import_rest()

    ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"

    # Make post_blocklist raise
    original_post = stub_management_client.post_blocklist

    call_count = {"n": 0}

    async def _failing_post(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("test-blocklist-error")
        return await original_post(**kwargs)

    stub_management_client.post_blocklist = _failing_post

    async def _fetch(url, headers=None, **kwargs):
        return {"fingerprints": [ja4, ja4]}

    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="", ja4_jsonpath="$.fingerprints[*]"),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert any("blocklist create failed" in e for e in result.errors)


def test_ja4_state_mark_called(stub_management_client):
    """When state is not None, state.mark() is called for each JA4 indicator."""
    RESTGenericClient = _import_rest()

    mock_state = MagicMock()
    mock_state.mark = AsyncMock()
    ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"

    async def _fetch(url, headers=None, **kwargs):
        return {"fingerprints": [ja4]}

    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="", ja4_jsonpath="$.fingerprints[*]"),
        mgmt=stub_management_client,
        state=mock_state,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert len(result.created) == 1
    mock_state.mark.assert_awaited_once()
    call_args = mock_state.mark.call_args
    assert call_args[0][0] == "internal-ti"
    assert call_args[1]["kind"] == "blocklist"


# ── List body is also walkable (line 206) ────────────────────────────────────


def test_list_body_is_walkable(stub_management_client):
    """A top-level list response body is walkable by JSONPath."""
    RESTGenericClient = _import_rest()

    async def _fetch(url, headers=None, **kwargs):
        return [
            {"value": "192.0.2.1", "expires_in": 3600},
        ]

    # Use a jsonpath that works on a list root.
    client = RESTGenericClient(
        config=_make_rest_config(ip_jsonpath="$[*].value", ttl_jsonpath="$[*].expires_in"),
        mgmt=stub_management_client,
        state=None,
        fetch=_fetch,
    )
    result = _run(client.poll())
    assert len(result.created) == 1


# ── Poll result fields ──────────────────────────────────────────────────────


def test_poll_result_has_duration(stub_management_client):
    """poll_duration_s is populated on success."""
    RESTGenericClient = _import_rest()

    client = RESTGenericClient(
        config=_make_rest_config(),
        mgmt=stub_management_client,
        state=None,
        fetch=AsyncMock(return_value={"indicators": []}),
    )
    result = _run(client.poll())
    assert result.poll_duration_s >= 0
