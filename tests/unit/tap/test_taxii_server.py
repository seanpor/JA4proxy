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
            "ban:1.2.3.4": json.dumps(
                {
                    "ip": "1.2.3.4",
                    "score": 80,
                    "reason": "test",
                    "timestamp": time.time(),
                }
            ),
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
            "ban:1.2.3.4": json.dumps(
                {
                    "ip": "1.2.3.4",
                    "score": 80,
                    "reason": "old",
                    "timestamp": old_ts,
                }
            ),
            "ban:5.6.7.8": json.dumps(
                {
                    "ip": "5.6.7.8",
                    "score": 80,
                    "reason": "new",
                    "timestamp": new_ts,
                }
            ),
        }

        # Filter to only include entries added after 30 minutes ago
        cutoff = datetime.fromtimestamp(time.time() - 1800, tz=timezone.utc).isoformat()

        server = TaxiiServer(_make_config(), _make_redis(bans))
        req = _make_request(query={"added_after": cutoff})
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )

        body = json.loads(resp.text)
        indicator_names = [obj.get("name", "") for obj in body.get("objects", [])]
        assert not any(
            "1.2.3.4" in n for n in indicator_names
        ), "Old entry should be filtered"
        assert any(
            "5.6.7.8" in n for n in indicator_names
        ), "New entry should be included"

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


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------


class TestTaxiiServerLifecycle:
    """Lines 55-62, 66-71, 85-87: _create_app, start, close lifecycle."""

    @pytest.mark.asyncio
    async def test_create_app_registers_three_routes(self):
        # _create_app (lines 54-62) registers discovery, collections, objects endpoints.
        # If any route is missing, threat intelligence consumers will fail silently.
        server = TaxiiServer(_make_config(), _make_redis())
        app = server._create_app()
        routes = {str(r.resource.canonical) for r in app.router.routes()}
        assert "/taxii2/" in routes
        assert "/taxii2/api/collections/" in routes
        assert any("objects" in r for r in routes)

    @pytest.mark.asyncio
    async def test_start_and_close_run_without_error(self):
        # start (lines 64-81) and close (lines 83-87) manage the HTTP server lifecycle.
        # A crash here means the TAXII feed silently stops serving to consumers.
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_runner = AsyncMock()
        mock_site = AsyncMock()

        with patch(
            "src.tap.export.taxii_server.web.AppRunner", return_value=mock_runner
        ), patch("src.tap.export.taxii_server.web.TCPSite", return_value=mock_site):
            server = TaxiiServer(_make_config(), _make_redis())
            await server.start()
            assert server._runner is mock_runner
            await server.close()
            # After close, _runner must be cleared so re-start is safe
            assert server._runner is None

    @pytest.mark.asyncio
    async def test_close_is_idempotent_when_runner_is_none(self):
        # close() (lines 83-87) must be safe to call before start().
        # A second close() on teardown must not raise.
        server = TaxiiServer(_make_config(), _make_redis())
        await server.close()  # runner is None — must not raise


class TestPrivateHandlers:
    """Lines 93-94, 97, 100-102: _handle_discovery, _handle_collections, _handle_objects."""

    @pytest.mark.asyncio
    async def test_handle_discovery_delegates_correctly(self):
        # _handle_discovery (line 93-94) is the aiohttp route callback.
        # If the delegation is broken, the /taxii2/ route returns nothing useful.
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server._handle_discovery(req)
        assert resp.status == 200
        body = json.loads(resp.text)
        assert "title" in body

    @pytest.mark.asyncio
    async def test_handle_collections_delegates_correctly(self):
        # _handle_collections (line 96-97) routes aiohttp callbacks.
        # A broken delegation means collection listing fails for STIX clients.
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server._handle_collections(req)
        assert resp.status == 200
        body = json.loads(resp.text)
        assert "collections" in body

    @pytest.mark.asyncio
    async def test_handle_objects_extracts_collection_id_from_match_info(self):
        # _handle_objects (lines 99-102) reads collection_id from match_info.
        # If the path assembly is wrong, the objects path never matches.
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        req.match_info = {"collection_id": "my-col"}
        resp = await server._handle_objects(req)
        assert resp.status == 200


class TestHandleTaxiiRequestEdgeCases:
    """Lines 154: 404 for unknown paths."""

    @pytest.mark.asyncio
    async def test_unknown_path_returns_404(self):
        # handle_taxii_request (line 154) returns 404 for unrecognised paths.
        # Without this, malformed requests might match unintended handlers.
        server = TaxiiServer(_make_config(), _make_redis())
        req = _make_request()
        resp = await server.handle_taxii_request("/taxii2/unknown/", req)
        assert resp.status == 404


class TestObjectsResponseEdgeCases:
    """Lines 165-166, 171-172, 178, 197-199, 202-203, 214-215, 240: _objects_response paths."""

    @pytest.mark.asyncio
    async def test_added_after_invalid_timestamp_is_ignored(self):
        # Lines 165-166: an unparseable added_after must be silently ignored (no crash).
        # A malformed query parameter must never cause an outage for STIX consumers.
        bans = {
            "ban:1.2.3.4": json.dumps(
                {"ip": "1.2.3.4", "score": 80, "reason": "r", "timestamp": time.time()}
            )
        }
        server = TaxiiServer(_make_config(), _make_redis(bans))
        req = _make_request(query={"added_after": "not-a-date"})
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        # Invalid date must not crash — all entries should be returned
        assert resp.status == 200
        body = json.loads(resp.text)
        assert len(body["objects"]) >= 1

    @pytest.mark.asyncio
    async def test_redis_keys_exception_returns_empty_bundle(self):
        # Lines 171-172: Redis unavailability must not crash the TAXII endpoint.
        # Fail-open: return an empty bundle rather than a 500.
        redis = MagicMock()
        redis.keys.side_effect = ConnectionError("redis down")
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200
        body = json.loads(resp.text)
        assert body["objects"] == []

    @pytest.mark.asyncio
    async def test_ban_entry_with_none_value_is_skipped(self):
        # Line 178: keys() may return a key whose TTL expired before get().
        # The None value must be skipped — never raises, never adds empty indicator.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:1.2.3.4"]
        redis.get.return_value = None
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200
        body = json.loads(resp.text)
        assert body["objects"] == []

    @pytest.mark.asyncio
    async def test_ban_entry_with_plain_string_json_value(self):
        # Lines 197-199: JSON value that is a plain string (not a dict) falls through
        # to ip = str(meta) branch.  The indicator must still be created.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:1.2.3.4"]
        # JSON-encoded plain string
        redis.get.return_value = json.dumps("1.2.3.4").encode()
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200
        body = json.loads(resp.text)
        assert len(body["objects"]) == 1

    @pytest.mark.asyncio
    async def test_ban_entry_with_non_json_raw_value(self):
        # Lines 198-199: raw value is not valid JSON at all (plain IP text).
        # ip = raw.strip() path must produce a valid indicator.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:2.2.2.2"]
        redis.get.return_value = b"2.2.2.2"
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200
        body = json.loads(resp.text)
        assert any("2.2.2.2" in obj.get("name", "") for obj in body["objects"])

    @pytest.mark.asyncio
    async def test_ban_entry_with_missing_ip_field_falls_back_to_key(self):
        # Lines 202-203: when JSON is valid dict but 'ip' is empty, derive IP from key.
        # This ensures every ban key produces an indicator regardless of value format.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:3.3.3.3"]
        redis.get.return_value = json.dumps({"score": 80, "reason": "r"}).encode()
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200
        body = json.loads(resp.text)
        assert any("3.3.3.3" in obj.get("name", "") for obj in body["objects"])

    @pytest.mark.asyncio
    async def test_entry_parse_exception_is_caught_not_propagated(self):
        # Lines 214-215: malformed per-entry data must be skipped, not crash the endpoint.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:bad"]
        # get() raises unexpectedly — simulates corrupt Redis response
        redis.get.side_effect = RuntimeError("corrupted data")
        server = TaxiiServer(_make_config(), redis)
        req = _make_request()
        resp = await server.handle_taxii_request(
            "/taxii2/api/collections/ja4proxy-bans/objects/", req
        )
        assert resp.status == 200

    def test_build_stix_indicator_uses_ipv6_pattern_for_ipv6_address(self):
        # Line 240: IPv6 addresses must use [ipv6-addr:value = '...'] STIX pattern.
        # Using the wrong pattern type would cause STIX consumers to reject the indicator.
        server = TaxiiServer(_make_config(), _make_redis())
        indicator = server._build_stix_indicator("2001:db8::1", 80, "reason", None)
        assert "ipv6-addr" in indicator["pattern"]
        assert "2001:db8::1" in indicator["pattern"]
