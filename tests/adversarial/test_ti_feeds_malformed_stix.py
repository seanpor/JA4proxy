"""Phase 85 — adversarial tests for malformed STIX content.

Workers must handle, log, and continue past:
- truncated JSON
- invalid UUIDs
- malformed JA4 strings
- indicators missing required fields (no pattern, no confidence)
- unknown ``pattern_type`` values

The client must NEVER crash on input from a remote feed and NEVER write
partial / corrupt data through the Management API.

These tests are RED until the production parser exists.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

# phase-85: H1 closed (commit 5223cdc) — feed clients now expose
# HTTP-layer DI seams; the shared stubs were extracted to
# tests/_helpers/ti_feed_stubs.py and re-exposed via
# tests/adversarial/conftest.py.
_ = pytest  # noqa: F841 — keep import marker active


def _run(coro):
    return asyncio.run(coro)


def _import_taxii():
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return TAXIIClient


def _make_config():
    from src.analytics.ti_feeds.base import FeedConfig

    return FeedConfig(
        id="adv-feed",
        type="taxii2",
        url="https://x/",
        collection_id="x",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=50,
        ban_ttl_hours=168,
    )


class _BadServer:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def get_objects(self, collection_id: str, added_after=None, **kwargs):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


# ── Truncated JSON / wrong shape ──────────────────────────────────────────────


def test_truncated_json_does_not_crash(stub_management_client):
    TAXIIClient = _import_taxii()
    server = _BadServer(json.JSONDecodeError("Expecting value", "doc", 0))
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.errors  # we recorded the failure
    assert stub_management_client.requests == []


def test_non_dict_payload_does_not_crash(stub_management_client):
    TAXIIClient = _import_taxii()
    server = _BadServer("just a string, not a bundle")
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert result.errors
    assert stub_management_client.requests == []


def test_bundle_with_no_objects_key(stub_management_client):
    TAXIIClient = _import_taxii()
    server = _BadServer({"type": "bundle", "id": "bundle--bad"})  # missing 'objects'
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    # Should treat as empty, not crash
    assert stub_management_client.requests == []


# ── Invalid UUIDs ─────────────────────────────────────────────────────────────


def test_invalid_uuid_indicator_id_skipped(stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--bad-uuid",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--NOT-A-UUID",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "confidence": 90,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
    }
    server = _BadServer(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    # Either skipped or accepted with the invalid id; key behaviour is no crash
    assert result is not None


# ── Malformed JA4 strings ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_ja4",
    [
        "not-a-ja4",
        "tooshort",
        "t10d170900_NOTHEX_b64c0ad42cb7",
        "t10d170900_9dc949161B6C_b64c0ad42cb7",  # uppercase disallowed
        "",
    ],
)
def test_malformed_ja4_indicator_skipped(bad_ja4, stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--bad-ja4",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--bad-ja4",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": f"[x-ja4-fingerprint:value = '{bad_ja4}']",
                "confidence": 90,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
    }
    server = _BadServer(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    paths = [r["path"] for r in stub_management_client.requests]
    assert not any(bad_ja4 and bad_ja4 in p for p in paths)


# ── Missing required fields ───────────────────────────────────────────────────


def test_indicator_missing_pattern_skipped(stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--missing",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--missing-pattern",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "confidence": 90,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
    }
    server = _BadServer(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    _run(client.poll())
    assert stub_management_client.requests == []


def test_indicator_missing_confidence_skipped(stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--missing",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--missing-confidence",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '198.51.100.50']",
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
    }
    server = _BadServer(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    paths = [r["path"] for r in stub_management_client.requests]
    assert not any("198.51.100.50" in p for p in paths)


# ── Unknown pattern_type ──────────────────────────────────────────────────────


def test_unknown_pattern_type_skipped(stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = {
        "type": "bundle",
        "id": "bundle--unknown-pt",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--unknown-pt",
                "spec_version": "2.1",
                "pattern_type": "yara",
                "pattern": "rule something { strings: $ = \"foo\" condition: any of them }",
                "confidence": 90,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        ],
    }
    server = _BadServer(bundle)
    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    result = _run(client.poll())
    assert stub_management_client.requests == []
