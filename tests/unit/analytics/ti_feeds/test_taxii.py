"""Phase 85 — unit tests for ``analytics.ti_feeds.taxii.TAXIIClient``.

Verifies parsing of the canned STIX 2.1 bundle:
- both IP and JA4 indicators are extracted
- below-confidence indicators are skipped (counted but not converted)
- expired indicators are filtered out
- empty collections do not crash
- ``added_after`` is propagated for incremental polls

These tests are RED until ``src/analytics/ti_feeds/taxii.py`` exists.
"""

from __future__ import annotations

import asyncio

import pytest  # noqa: F401


def _run(coro):
    return asyncio.run(coro)


def _import_taxii():
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return TAXIIClient


def _make_config(**overrides):
    """Build a small FeedConfig stub matching the expected dataclass."""
    from src.analytics.ti_feeds.base import FeedConfig

    defaults = dict(
        id="taxii-isac",
        type="taxii2",
        url="https://taxii.example.test/taxii2/",
        collection_id="enterprise-attack",
        username="user",
        password="pass",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=70,
        ban_ttl_hours=168,
    )
    defaults.update(overrides)
    return FeedConfig(**defaults)


# ── Bundle parsing ────────────────────────────────────────────────────────────


def test_taxii_extracts_ja4_indicators(stix_bundle, mock_taxii_server, stub_management_client):
    """Above-confidence JA4 indicators are sent to the blocklist endpoint."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )

    result = _run(client.poll())

    blocklist_calls = [
        r for r in stub_management_client.requests if r["path"] == "/api/v1/blocklist"
    ]
    ja4s = [r["entry"] for r in blocklist_calls]
    assert "t10d170900_9dc949161b6c_b64c0ad42cb7" in ja4s
    assert "t13d301100_5b57614c22b0_3d5424432f57" in ja4s
    assert all(r["managed_by"] == "feed" for r in blocklist_calls)


def test_taxii_extracts_ip_indicators(stix_bundle, mock_taxii_server, stub_management_client):
    """Above-confidence IP indicators are sent to the bans endpoint."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    _run(client.poll())

    ban_paths = [
        r["path"] for r in stub_management_client.requests if r["method"] == "POST" and r["path"].startswith("/api/v1/bans/")
    ]
    assert any("198.51.100.42" in p for p in ban_paths)
    assert any("2001:db8::dead:beef" in p for p in ban_paths)


def test_taxii_skips_below_confidence(stix_bundle, mock_taxii_server, stub_management_client):
    """Confidence < min_confidence increments the skipped counter, not the API."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(min_confidence=70),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())

    assert result.skipped_below_confidence >= 1
    # 203.0.113.1 was confidence=30 — must NOT have triggered an API call
    ban_paths = [r["path"] for r in stub_management_client.requests]
    assert not any("203.0.113.1" in p for p in ban_paths)


def test_taxii_filters_expired_indicators(stix_bundle, mock_taxii_server, stub_management_client):
    """An indicator with valid_until in the past must be filtered out."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    _run(client.poll())

    ban_paths = [r["path"] for r in stub_management_client.requests]
    # 192.0.2.99 was valid_until=2025-12-31 — expired
    assert not any("192.0.2.99" in p for p in ban_paths)


def test_taxii_empty_collection_does_not_crash(mock_taxii_server, stub_management_client):
    """An empty bundle is handled gracefully and produces an empty result."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server({"type": "bundle", "id": "bundle--empty", "objects": []})
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.stix_ids_seen == set()
    assert result.created == []
    assert stub_management_client.requests == []


# ── Incremental polling ───────────────────────────────────────────────────────


def test_taxii_passes_added_after_on_subsequent_poll(stix_bundle, mock_taxii_server, stub_management_client):
    """The second poll honours an ``added_after`` from poll_state."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
        last_added_after="2026-04-01T00:00:00Z",
    )
    _run(client.poll())

    assert server.calls, "Mock TAXII server should have received at least one call"
    last = server.calls[-1]
    assert last["added_after"] == "2026-04-01T00:00:00Z"


def test_taxii_records_seen_stix_ids(stix_bundle, mock_taxii_server, stub_management_client):
    """Every above-confidence non-expired indicator id is in stix_ids_seen."""
    TAXIIClient = _import_taxii()
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())

    # 4 indicators are above confidence and unexpired:
    # ja4 cobalt strike, ja4 sliver, IPv4 198.51.100.42, IPv6 2001:db8::dead:beef
    assert len(result.stix_ids_seen) == 4
    assert "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee1" in result.stix_ids_seen
    assert "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee2" in result.stix_ids_seen
    assert "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee3" in result.stix_ids_seen
    assert "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee6" in result.stix_ids_seen
