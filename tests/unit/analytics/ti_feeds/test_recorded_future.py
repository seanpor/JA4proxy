"""Phase 85 — unit tests for ``analytics.ti_feeds.recorded_future``.

The Recorded Future client is a thin wrapper over ``TAXIIClient`` so most
behaviour is inherited. Tests here cover:
- token exchange happens once and the bearer token is reused for subsequent calls
- collection IDs are configurable from FeedConfig
- pagination cursor is honoured
- inheriting TAXII parsing logic still works

These tests are RED until ``src/analytics/ti_feeds/recorded_future.py`` exists.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _run(coro):
    return asyncio.run(coro)


def _import_rf():
    from analytics.ti_feeds.recorded_future import RecordedFutureClient

    return RecordedFutureClient


def _make_rf_config(**overrides):
    from analytics.ti_feeds.base import FeedConfig

    defaults = dict(
        id="recorded-future",
        type="recorded_future",
        api_token="rf-secret-token",
        feeds=["ip_threat_intel", "c2_server_tracking"],
        min_rf_risk_score=75,
        ban_ttl_hours=72,
        enabled=True,
    )
    defaults.update(overrides)
    return FeedConfig(**defaults)


# ── Token exchange ────────────────────────────────────────────────────────────


def test_token_exchange_once_then_reused(stub_management_client):
    """The token endpoint is called exactly once across multiple polls."""
    RecordedFutureClient = _import_rf()

    exchanges: list[str] = []

    async def _fake_exchange(api_token: str) -> str:
        exchanges.append(api_token)
        return "rf-bearer-12345"

    client = RecordedFutureClient(
        config=_make_rf_config(),
        mgmt=stub_management_client,
        state=None,
        token_exchange=_fake_exchange,
    )

    _run(client.fetch_bearer_token())
    _run(client.fetch_bearer_token())
    _run(client.fetch_bearer_token())

    assert len(exchanges) == 1
    assert exchanges[0] == "rf-secret-token"


def test_collection_ids_configurable(stub_management_client):
    """The configured collection IDs determine which TAXII collections are polled."""
    RecordedFutureClient = _import_rf()

    cfg = _make_rf_config(feeds=["custom_feed_a", "custom_feed_b"])
    client = RecordedFutureClient(
        config=cfg, mgmt=stub_management_client, state=None
    )
    assert client.collection_ids == ["custom_feed_a", "custom_feed_b"]


# ── Pagination ────────────────────────────────────────────────────────────────


def test_pagination_cursor_advances(stub_management_client):
    """A cursor returned from the first page is sent on the second."""
    RecordedFutureClient = _import_rf()

    pages = [
        {
            "type": "bundle",
            "id": "bundle--p1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--p1-1",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": "[ipv4-addr:value = '203.0.113.1']",
                    "confidence": 90,
                    "valid_from": "2026-04-01T00:00:00Z",
                }
            ],
            "next": "cursor-page-2",
        },
        {
            "type": "bundle",
            "id": "bundle--p2",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--p2-1",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": "[ipv4-addr:value = '203.0.113.2']",
                    "confidence": 90,
                    "valid_from": "2026-04-01T00:00:00Z",
                }
            ],
            "next": None,
        },
    ]

    cursor_calls: list[str | None] = []

    async def _paged_fetch(collection_id: str, cursor: str | None = None, **kwargs):
        cursor_calls.append(cursor)
        return pages[len(cursor_calls) - 1]

    client = RecordedFutureClient(
        config=_make_rf_config(),
        mgmt=stub_management_client,
        state=None,
        page_fetch=_paged_fetch,
    )
    result = _run(client.poll())

    assert cursor_calls == [None, "cursor-page-2"]
    # Both pages' indicators were processed
    paths = [r["path"] for r in stub_management_client.requests if r["method"] == "POST"]
    assert any("203.0.113.1" in p for p in paths)
    assert any("203.0.113.2" in p for p in paths)


def test_inherits_min_confidence_from_taxii_logic(stub_management_client):
    """RF still honours the min_confidence threshold from FeedConfig."""
    RecordedFutureClient = _import_rf()

    bundle = {
        "type": "bundle",
        "id": "bundle--lo",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--lo",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '203.0.113.99']",
                "confidence": 10,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
        "next": None,
    }

    async def _fetch(collection_id, cursor=None, **kwargs):
        return bundle

    client = RecordedFutureClient(
        config=_make_rf_config(min_rf_risk_score=50),
        mgmt=stub_management_client,
        state=None,
        page_fetch=_fetch,
    )
    result = _run(client.poll())
    assert result.skipped_below_confidence >= 1
    assert not any("203.0.113.99" in r.get("path", "") for r in stub_management_client.requests)
