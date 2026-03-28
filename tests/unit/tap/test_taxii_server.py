"""
Unit tests for src/tap/export/taxii_server.py — Phase 20, Group 9.
"""
import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tap.export.taxii_server import TaxiiServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    taxii = {
        "enabled": True,
        "port": 8092,
        "api_key": "",
        "collection_id": "ja4proxy-bans",
        "collection_title": "JA4proxy Ban List",
    }
    taxii.update(overrides)
    return {"intelligence_export": {"taxii": taxii}}


def _make_redis(ban_keys: dict | None = None) -> MagicMock:
    redis = MagicMock()
    if ban_keys is None:
        ban_keys = {}

    def keys_side_effect(pattern):
        return [k.encode() for k in ban_keys.keys()]

    def get_side_effect(key):
        key_str = key.decode() if isinstance(key, bytes) else str(key)
        val = ban_keys.get(key_str)
        if val is None:
            return None
        if isinstance(val, dict):
            return json.dumps(val).encode()
        return str(val).encode()

    redis.keys.side_effect = keys_side_effect
    redis.get.side_effect = get_side_effect
    return redis


def _make_request(
    headers: dict | None = None,
    query: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.headers = headers or {}
    req.match_info = {}
    req.rel_url = MagicMock()
    req.rel_url.query = query or {}
    return req


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDiscovery:
    @pytest.mark.asyncio
    async def test_taxii_discovery_returns_valid_json(self):
        """GET /taxii2/ must return a discovery document with 'title' field."""
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server.handle_taxii_request("/taxii2/", req)

        assert resp.status == 200
        body = json.loads(resp.text)
        assert "title" in body

    @pytest.mark.asyncio
    async def test_discovery_includes_api_roots(self):
        """Discovery document must include api_roots."""
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server.handle_taxii_request("/taxii2/", req)

        body = json.loads(resp.text)
        assert "api_roots" in body
        assert len(body["api_roots"]) > 0


class TestCollections:
    @pytest.mark.asyncio
    async def test_collections_endpoint_returns_configured_collection(self):
        """GET /taxii2/api/collections/ must return the configured collection."""
        server = TaxiiServer(_make_config(collection_id="test-col"), _make_redis())
        req = _make_request()
        resp = await server.handle_taxii_request("/taxii2/api/collections/", req)

        assert resp.status == 200
        body = json.loads(resp.text)
        ids = [c["id"] for c in body.get("collections", [])]
        assert "test-col" in ids

    @pytest.mark.asyncio
    async def test_collections_include_can_read_true(self):
        """Collections must have can_read=True."""
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server.handle_taxii_request("/taxii2/api/collections/", req)

        body = json.loads(resp.text)
        for col in body.get("collections", []):
            assert col["can_read"] is True


class TestObjects:
    @pytest.mark.asyncio
    async def test_objects_endpoint_returns_stix_bundle(self):
        """GET objects must return a STIX bundle with type='bundle'."""
        bans = {
            "ban:1.2.3.4": json.dumps({
                "ip": "1.2.3.4",
                "score": 80,
                "reason": "test",
                "timestamp": time.time(),
            }),
        }
        server = TaxiiServer(_make_config(), _make_redis(bans))
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )

        assert resp.status == 200
        body = json.loads(resp.text)
        assert body["type"] == "bundle"
        assert "objects" in body

    @pytest.mark.asyncio
    async def test_added_after_filter_works(self):
        """Entries added before the added_after timestamp must be excluded."""
        old_ts = time.time() - 3600  # 1 hour ago
        new_ts = time.time()

        bans = {
            "ban:1.2.3.4": json.dumps({
                "ip": "1.2.3.4",
                "score": 80,
                "reason": "old",
                "timestamp": old_ts,
            }),
            "ban:5.6.7.8": json.dumps({
                "ip": "5.6.7.8",
                "score": 80,
                "reason": "new",
                "timestamp": new_ts,
            }),
        }

        # Filter to only include entries added after 30 minutes ago
        cutoff = datetime.fromtimestamp(
            time.time() - 1800, tz=timezone.utc
        ).isoformat()

        server = TaxiiServer(_make_config(), _make_redis(bans))
        req = _make_request(query={"added_after": cutoff})
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )

        body = json.loads(resp.text)
        indicator_names = [obj.get("name", "") for obj in body.get("objects", [])]
        assert not any("1.2.3.4" in n for n in indicator_names), "Old entry should be filtered"
        assert any("5.6.7.8" in n for n in indicator_names), "New entry should be included"

    @pytest.mark.asyncio
    async def test_api_key_required_for_objects(self):
        """When api_key is configured, GET objects without key must return 401."""
        server = TaxiiServer(_make_config(api_key="secret"), _make_redis())
        req = _make_request()  # no X-API-Key
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 401

    @pytest.mark.asyncio
    async def test_api_key_accepted(self):
        """When correct X-API-Key is provided, return 200."""
        server = TaxiiServer(_make_config(api_key="secret"), _make_redis())
        req = _make_request(headers={"X-API-Key": "secret"})
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200


class TestStixIndicator:
    def test_stix_indicator_has_correct_pattern_type(self):
        """_build_stix_indicator must set pattern_type='stix'."""
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("1.2.3.4", 80, "reason", None)
        assert indicator["pattern_type"] == "stix"

    def test_stix_indicator_type_is_indicator(self):
        """STIX object type must be 'indicator'."""
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("1.2.3.4", 80, "reason", None)
        assert indicator["type"] == "indicator"

    def test_stix_indicator_contains_ip_pattern(self):
        """STIX pattern must reference the IP."""
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("1.2.3.4", 80, "reason", None)
        assert "1.2.3.4" in indicator["pattern"]

    def test_stix_indicator_id_format(self):
        """STIX indicator id must start with 'indicator--'."""
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("1.2.3.4", 80, "reason", None)
        assert indicator["id"].startswith("indicator--")

    def test_stix_indicator_extensions_include_score(self):
        """STIX extensions must include x-ja4proxy with score."""
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("1.2.3.4", 85, "reason", "t13d_abc")
        ext = indicator["extensions"]["x-ja4proxy"]
        assert ext["score"] == 85
        assert ext["ja4"] == "t13d_abc"
