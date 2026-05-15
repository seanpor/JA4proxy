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


def test_taxii_extracts_ja4_indicators(
    stix_bundle, mock_taxii_server, stub_management_client
):
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


def test_taxii_extracts_ip_indicators(
    stix_bundle, mock_taxii_server, stub_management_client
):
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
        r["path"]
        for r in stub_management_client.requests
        if r["method"] == "POST" and r["path"].startswith("/api/v1/bans/")
    ]
    assert any("198.51.100.42" in p for p in ban_paths)
    assert any("2001:db8::dead:beef" in p for p in ban_paths)


def test_taxii_skips_below_confidence(
    stix_bundle, mock_taxii_server, stub_management_client
):
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


def test_taxii_filters_expired_indicators(
    stix_bundle, mock_taxii_server, stub_management_client
):
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
    # 192.0.2.99 has valid_until in the past (dynamic_expired) — filtered out
    assert not any("192.0.2.99" in p for p in ban_paths)


def test_taxii_empty_collection_does_not_crash(
    mock_taxii_server, stub_management_client
):
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


def test_taxii_passes_added_after_on_subsequent_poll(
    stix_bundle, mock_taxii_server, stub_management_client
):
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


def test_taxii_records_seen_stix_ids(
    stix_bundle, mock_taxii_server, stub_management_client
):
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


# ── TAXII HTTP error handling (coverage gap closure) ─────────────────────────


def test_taxii_injected_transport_non_dict_raises(
    mock_taxii_server, stub_management_client
):
    """When the injected transport returns a non-dict, RuntimeError is raised."""
    TAXIIClient = _import_taxii()

    class BadTransport:
        async def get_objects(self, collection_id, added_after=None):
            return "not a dict"

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=BadTransport(),
    )
    result = _run(client.poll())
    assert len(result.errors) > 0
    assert "non-dict" in result.errors[0]


def test_taxii_injected_transport_non_list_objects_raises(
    mock_taxii_server, stub_management_client
):
    """When bundle.objects is not a list, RuntimeError is raised."""
    TAXIIClient = _import_taxii()

    class BadObjectsTransport:
        async def get_objects(self, collection_id, added_after=None):
            return {"objects": "not a list"}

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=BadObjectsTransport(),
    )
    result = _run(client.poll())
    assert len(result.errors) > 0
    assert "not a list" in result.errors[0]


def test_taxii_fetch_failure_records_error(mock_taxii_server, stub_management_client):
    """A transport exception is caught and recorded as a poll error."""
    TAXIIClient = _import_taxii()

    class FailTransport:
        async def get_objects(self, collection_id, added_after=None):
            raise ConnectionError("network unreachable")

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=FailTransport(),
    )
    result = _run(client.poll())
    assert len(result.errors) > 0
    assert "fetch_failed" in result.errors[0]


# ── _is_expired edge cases ──────────────────────────────────────────────────


def test_is_expired_with_z_suffix():
    """ISO-8601 with trailing Z is parsed correctly."""
    from src.analytics.ti_feeds.taxii import _is_expired

    # Far past date
    assert _is_expired("2020-01-01T00:00:00Z") is True
    # Far future date
    assert _is_expired("2099-12-31T23:59:59Z") is False


def test_is_expired_parse_failure_returns_false():
    """Bad date strings return False (fail open)."""
    from src.analytics.ti_feeds.taxii import _is_expired

    assert _is_expired("not-a-date") is False
    assert _is_expired("") is False


def test_is_expired_naive_datetime():
    """A naive datetime (no timezone) is treated as UTC."""
    from src.analytics.ti_feeds.taxii import _is_expired

    assert _is_expired("2020-01-01T00:00:00") is True


# ── _apply_indicator edge cases (coverage lines 291-352) ────────────────────


def test_indicator_missing_id_records_error(mock_taxii_server, stub_management_client):
    """An indicator without 'id' appends an error."""
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert any("missing id" in e for e in result.errors)


def test_indicator_invalid_ip_records_error(mock_taxii_server, stub_management_client):
    """An indicator with an invalid IP pattern records an error."""
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--bad-ip",
                "pattern": "[ipv4-addr:value = 'not.an.ip.address']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern >= 1


def test_indicator_ban_api_failure(mock_taxii_server, stub_management_client):
    """When post_ban raises, the error is recorded but poll continues."""
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--ban-fail",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    stub_management_client.fail_path("POST", "/api/v1/bans/198.51.100.1", 500)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert any("ban create failed" in e for e in result.errors)


def test_indicator_blocklist_api_failure(mock_taxii_server, stub_management_client):
    """When post_blocklist raises, the error is recorded."""
    TAXIIClient = _import_taxii()

    # Need a valid JA4 that is not in the FP corpus
    import src.analytics.ti_feeds.ja4_safety as safety

    safety._JA4_FP_CORPUS = frozenset()

    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--bl-fail",
                "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)

    # Make post_blocklist raise
    original_post = stub_management_client.post_blocklist

    async def _fail_blocklist(**kwargs):
        raise RuntimeError("blocklist API down")

    stub_management_client.post_blocklist = _fail_blocklist

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert any("blocklist create failed" in e for e in result.errors)

    stub_management_client.post_blocklist = original_post
    safety._JA4_FP_CORPUS = None


def test_indicator_ja4_fp_blocked(mock_taxii_server, stub_management_client):
    """A JA4 in the FP corpus is rejected with fp_blocked outcome."""
    TAXIIClient = _import_taxii()

    import src.analytics.ti_feeds.ja4_safety as safety

    safety._JA4_FP_CORPUS = frozenset({"t10d170900_9dc949161b6c_b64c0ad42cb7"})

    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--fp-test",
                "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert any("false positive" in e.lower() for e in result.errors)

    safety._JA4_FP_CORPUS = None


def test_indicator_unsupported_pattern(mock_taxii_server, stub_management_client):
    """An unsupported pattern type increments unsupported_pattern."""
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--unsupported",
                "pattern": "[domain-name:value = 'evil.example.com']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern >= 1


def test_indicator_invalid_ja4_pattern(mock_taxii_server, stub_management_client):
    """A ja4 pattern that fails validation records an error."""
    TAXIIClient = _import_taxii()

    import src.analytics.ti_feeds.ja4_safety as safety

    safety._JA4_FP_CORPUS = frozenset()

    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--bad-ja4",
                "pattern": "[x-ja4-fingerprint:value = 'invalid']",
                "confidence": 90,
            }
        ],
    }
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.unsupported_pattern >= 1

    safety._JA4_FP_CORPUS = None


def test_indicator_with_state_tracking(
    stix_bundle, mock_taxii_server, stub_management_client, fake_redis
):
    """When state is provided, mark() is called for successful indicators."""
    TAXIIClient = _import_taxii()
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(fake_redis)
    server = mock_taxii_server(stix_bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=state,
        taxii=server,
    )
    result = _run(client.poll())
    # Should have tracked stix IDs in state
    active = _run(state.get_active_stix_ids("taxii-isac"))
    assert len(active) > 0


# ── Batch processing with inter-batch sleep ─────────────────────────────────


def test_process_objects_batches_large_set(mock_taxii_server, stub_management_client):
    """More than 50 indicators triggers inter-batch sleep."""
    TAXIIClient = _import_taxii()
    from unittest.mock import patch as _patch

    # Create 60 IP indicators
    objects = []
    for i in range(60):
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--batch-{i:04d}",
                "pattern": f"[ipv4-addr:value = '198.51.100.{i % 256}']",
                "confidence": 90,
            }
        )
    bundle = {"type": "bundle", "id": "bundle--batch", "objects": objects}
    server = mock_taxii_server(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )

    sleeps = []
    original_sleep = asyncio.sleep

    async def _track_sleep(s):
        sleeps.append(s)

    with _patch("src.analytics.ti_feeds.taxii.asyncio.sleep", _track_sleep):
        _run(client.poll())

    # 60 indicators / 50 batch = 2 batches, 1 inter-batch sleep
    assert len(sleeps) >= 1


# ── aiohttp HTTP path (coverage lines 186-228) ─────────────────────────────


def test_taxii_aiohttp_non_200_raises(stub_management_client):
    """When aiohttp gets non-200, RuntimeError is raised and caught by poll."""
    TAXIIClient = _import_taxii()
    from unittest.mock import AsyncMock, MagicMock
    from unittest.mock import patch as _patch

    import aiohttp

    class FakeResp:
        status = 503

        async def text(self):
            return "Service Unavailable"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def get(self, url, headers=None, params=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=None,  # force aiohttp path
    )

    with _patch("src.analytics.ti_feeds.taxii.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.poll())
    assert len(result.errors) > 0
    assert "HTTP 503" in result.errors[0]


def test_taxii_aiohttp_json_parse_error(stub_management_client):
    """When aiohttp response is not valid JSON, error is recorded."""
    TAXIIClient = _import_taxii()
    from unittest.mock import patch as _patch

    import aiohttp

    class FakeResp:
        status = 200

        async def text(self):
            return "this is not json"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def get(self, url, headers=None, params=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=None,
    )

    with _patch("src.analytics.ti_feeds.taxii.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.poll())
    assert len(result.errors) > 0
    assert "JSON" in result.errors[0]


def test_taxii_aiohttp_non_list_objects(stub_management_client):
    """When aiohttp response.objects is not a list, error is recorded."""
    TAXIIClient = _import_taxii()
    import json
    from unittest.mock import patch as _patch

    import aiohttp

    class FakeResp:
        status = 200

        async def text(self):
            return json.dumps({"objects": "not a list"})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def get(self, url, headers=None, params=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=None,
    )

    with _patch("src.analytics.ti_feeds.taxii.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.poll())
    assert len(result.errors) > 0
    assert "not a list" in result.errors[0]


def test_taxii_aiohttp_success_path(stub_management_client):
    """aiohttp success path returns valid objects."""
    TAXIIClient = _import_taxii()
    import json
    from unittest.mock import patch as _patch

    import aiohttp

    bundle = {"objects": []}

    class FakeResp:
        status = 200

        async def text(self):
            return json.dumps(bundle)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def get(self, url, headers=None, params=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = TAXIIClient(
        config=_make_config(username="", password=""),
        mgmt=stub_management_client,
        state=None,
        taxii=None,
    )

    with _patch("src.analytics.ti_feeds.taxii.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.poll())
    assert result.errors == []
    assert result.stix_ids_seen == set()
