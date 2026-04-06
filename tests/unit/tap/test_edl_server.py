"""
Unit tests for src/tap/export/edl_server.py — Phase 20, Group 9.
"""
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tap.export.edl_server import EDLServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    edl = {
        "enabled": True,
        "port": 8091,
        "api_key": "",
        "allowed_ips": [],
        "max_age_hours": 24,
        "min_score": 0,
        "include_comments": False,
        "lists": {
            "banned_ips": True,
            "banned_cidrs": True,
            "combined": True,
        },
    }
    edl.update(overrides)
    return {"intelligence_export": {"edl": edl}}


def _make_redis(ban_keys: dict | None = None) -> MagicMock:
    """Return a mock Redis client with pre-set ban:* keys.

    ban_keys: dict mapping key (str) to value (str or dict-as-json).
    """
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
    remote: str = "127.0.0.1",
    path: str = "/edl/banned_ips",
    query: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.headers = headers or {}
    req.remote = remote
    req.path = path
    req.match_info = {}
    # Simulate rel_url.query
    req.rel_url = MagicMock()
    req.rel_url.query = query or {}
    return req


async def _make_server_with_bans(
    bans: dict,
    config_overrides: dict | None = None,
) -> EDLServer:
    """Create an EDLServer with pre-loaded ban data (no real aiohttp server)."""
    cfg_ovr = config_overrides or {}
    config = _make_config(**cfg_ovr)
    redis = _make_redis(bans)
    server = EDLServer(config, redis)
    await server._rebuild_lists()
    return server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBannedIPsList:
    @pytest.mark.asyncio
    async def test_banned_ips_list_contains_active_bans_only(self):
        """Only active ban entries should appear in the list."""
        bans = {
            "ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()}),
            "ban:5.6.7.8": json.dumps({"ip": "5.6.7.8", "score": 70, "timestamp": time.time()}),
        }
        server = await _make_server_with_bans(bans)
        req = _make_request()
        response = await server.handle_edl_request("banned_ips", req)

        assert response.status == 200
        body = response.text
        assert "1.2.3.4" in body
        assert "5.6.7.8" in body

    @pytest.mark.asyncio
    async def test_entries_older_than_max_age_excluded(self):
        """Entries whose timestamp is older than max_age_hours must be excluded."""
        old_ts = time.time() - 25 * 3600  # 25 hours ago
        bans = {
            "ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": old_ts}),
            "ban:9.9.9.9": json.dumps({"ip": "9.9.9.9", "score": 80, "timestamp": time.time()}),
        }
        server = await _make_server_with_bans(bans, {"max_age_hours": 24})
        req = _make_request()
        response = await server.handle_edl_request("banned_ips", req)

        body = response.text
        assert "1.2.3.4" not in body, "Old entry should be excluded"
        assert "9.9.9.9" in body

    @pytest.mark.asyncio
    async def test_entries_below_min_score_excluded(self):
        """Entries with score < min_score must be excluded."""
        bans = {
            "ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 30, "timestamp": time.time()}),
            "ban:9.9.9.9": json.dumps({"ip": "9.9.9.9", "score": 80, "timestamp": time.time()}),
        }
        server = await _make_server_with_bans(bans, {"min_score": 50})
        req = _make_request()
        response = await server.handle_edl_request("banned_ips", req)

        body = response.text
        assert "1.2.3.4" not in body, "Low-score entry should be excluded"
        assert "9.9.9.9" in body

    @pytest.mark.asyncio
    async def test_etag_returned_with_response(self):
        """ETag header must be present in a 200 response."""
        bans = {"ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()})}
        server = await _make_server_with_bans(bans)
        req = _make_request()
        response = await server.handle_edl_request("banned_ips", req)

        assert response.status == 200
        assert "ETag" in response.headers

    @pytest.mark.asyncio
    async def test_304_returned_when_etag_matches(self):
        """When If-None-Match matches the current ETag, return 304."""
        bans = {"ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()})}
        server = await _make_server_with_bans(bans)

        # First request to get ETag
        req1 = _make_request()
        resp1 = await server.handle_edl_request("banned_ips", req1)
        etag = resp1.headers.get("ETag", "")
        assert etag

        # Second request with matching If-None-Match
        req2 = _make_request(headers={"If-None-Match": etag})
        resp2 = await server.handle_edl_request("banned_ips", req2)
        assert resp2.status == 304

    @pytest.mark.asyncio
    async def test_403_when_api_key_missing(self):
        """When api_key is configured and X-API-Key is absent, return 403."""
        bans = {}
        server = await _make_server_with_bans(bans, {"api_key": "secret123"})
        req = _make_request()  # no X-API-Key header
        response = await server.handle_edl_request("banned_ips", req)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_api_key_accepted_when_correct(self):
        """When correct X-API-Key is provided, return 200."""
        bans = {}
        server = await _make_server_with_bans(bans, {"api_key": "secret123"})
        req = _make_request(headers={"X-API-Key": "secret123"})
        response = await server.handle_edl_request("banned_ips", req)
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_403_when_source_ip_not_in_allowed_ips(self):
        """When allowed_ips is configured and remote IP is not in it, return 403."""
        bans = {}
        server = await _make_server_with_bans(bans, {"allowed_ips": ["10.0.0.1"]})
        req = _make_request(remote="1.2.3.4")
        response = await server.handle_edl_request("banned_ips", req)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_200_when_source_ip_in_allowed_ips(self):
        """When allowed_ips is configured and remote is in it, return 200."""
        bans = {}
        server = await _make_server_with_bans(bans, {"allowed_ips": ["10.0.0.1"]})
        req = _make_request(remote="10.0.0.1")
        response = await server.handle_edl_request("banned_ips", req)
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_comments_included_when_include_comments_true(self):
        """When include_comments=True, response body starts with a '#' comment line."""
        bans = {"ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()})}
        server = await _make_server_with_bans(bans, {"include_comments": True})
        req = _make_request()
        response = await server.handle_edl_request("banned_ips", req)

        assert response.status == 200
        assert response.text.startswith("#"), "Response should start with a comment"

    @pytest.mark.asyncio
    async def test_combined_list_is_union_of_banned_ips_and_cidrs(self):
        """Combined list should contain both IPs and CIDRs."""
        bans = {
            "ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()}),
            "ban:10.0.0.0/8": json.dumps({"ip": "10.0.0.0/8", "score": 80, "timestamp": time.time()}),
        }
        server = await _make_server_with_bans(bans)
        req = _make_request()
        response = await server.handle_edl_request("combined", req)

        body = response.text
        assert "1.2.3.4" in body
        assert "10.0.0.0/8" in body


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------

class TestEDLServerLifecycle:
    """Lines 67-69, 73-79: _create_app and start()."""

    @pytest.mark.asyncio
    async def test_create_app_registers_edl_route(self):
        # _create_app (lines 66-69) registers /edl/{list_name}.
        # If the route is missing, firewall clients pulling from /edl/ get 404.
        config = _make_config()
        redis = _make_redis({})
        server = EDLServer(config, redis)
        app = server._create_app()
        routes = [str(r.resource.canonical) for r in app.router.routes()]
        assert any("edl" in r for r in routes)

    @pytest.mark.asyncio
    async def test_start_and_close_run_without_error(self):
        # start() (lines 71-89) and close() (lines 91-95) manage the aiohttp server.
        # A failure here silently kills the EDL feed consumed by NGFWs.
        from unittest.mock import AsyncMock, patch

        mock_runner = AsyncMock()
        mock_site = AsyncMock()
        config = _make_config()
        redis = _make_redis({})

        with patch("src.tap.export.edl_server.web.AppRunner", return_value=mock_runner), \
             patch("src.tap.export.edl_server.web.TCPSite", return_value=mock_site):
            server = EDLServer(config, redis)
            await server.start()
            assert server._runner is mock_runner
            await server.close()
            assert server._runner is None

    @pytest.mark.asyncio
    async def test_close_is_idempotent_when_runner_is_none(self):
        # close() (lines 91-95) must be safe before start() — called on teardown paths.
        config = _make_config()
        redis = _make_redis({})
        server = EDLServer(config, redis)
        await server.close()  # must not raise


class TestRebuildListsEdgeCases:
    """Lines 93-95, 112-114, 121, 139-141, 145-146, 164-165: _rebuild_lists paths."""

    @pytest.mark.asyncio
    async def test_redis_keys_exception_returns_empty_lists(self):
        # Lines 112-114: Redis KEYS failure must be caught — lists stay empty.
        # Fail-open: better to serve a stale empty list than crash and serve nothing.
        config = _make_config()
        redis = MagicMock()
        redis.keys.side_effect = ConnectionError("redis down")
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert server._lists["banned_ips"] == []
        assert server._lists["banned_cidrs"] == []

    @pytest.mark.asyncio
    async def test_key_expired_between_keys_and_get_is_skipped(self):
        # Line 121: get() returns None for a key whose TTL expired after KEYS.
        # The missing key must be silently skipped — no crash, no partial entry.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:1.2.3.4"]
        redis.get.return_value = None  # expired
        config = _make_config()
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert server._lists["banned_ips"] == []

    @pytest.mark.asyncio
    async def test_plain_string_json_value_uses_it_as_ip(self):
        # Lines 139-141: JSON value is a plain string — ip = str(meta).
        # Older ban entries may store just the IP as a JSON string.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:5.5.5.5"]
        redis.get.return_value = json.dumps("5.5.5.5").encode()
        config = _make_config()
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert "5.5.5.5" in server._lists["banned_ips"]

    @pytest.mark.asyncio
    async def test_non_json_raw_value_strips_and_uses_as_ip(self):
        # Lines 140-141: raw value is not JSON at all — raw.strip() is used.
        # Legacy entries that store a plain IP byte string must still appear in the list.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:6.6.6.6"]
        redis.get.return_value = b"6.6.6.6"
        config = _make_config()
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert "6.6.6.6" in server._lists["banned_ips"]

    @pytest.mark.asyncio
    async def test_missing_ip_field_derives_ip_from_key(self):
        # Lines 145-146: when JSON dict has no 'ip' field, derive from key string.
        # Ensures every ban:* key produces an entry regardless of value schema.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:7.7.7.7"]
        redis.get.return_value = json.dumps({"score": 80}).encode()
        config = _make_config()
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert "7.7.7.7" in server._lists["banned_ips"]

    @pytest.mark.asyncio
    async def test_per_entry_exception_is_caught_and_skipped(self):
        # Lines 164-165: corrupt per-entry data must not abort the rebuild.
        # A single bad entry must not prevent the remaining valid entries from appearing.
        redis = MagicMock()
        redis.keys.return_value = [b"ban:bad", b"ban:8.8.8.8"]
        def get_side(key):
            if key == b"ban:bad":
                raise RuntimeError("corrupted")
            return json.dumps({"ip": "8.8.8.8", "score": 80}).encode()
        redis.get.side_effect = get_side
        config = _make_config()
        server = EDLServer(config, redis)
        await server._rebuild_lists()
        assert "8.8.8.8" in server._lists["banned_ips"]


class TestHandleEdlRequestEdgeCases:
    """Lines 180-181, 205: _handle_request and 404 for unknown list_name."""

    @pytest.mark.asyncio
    async def test_handle_request_private_method_routes_to_public(self):
        # Lines 180-181: _handle_request is the aiohttp route callback.
        # It must delegate correctly to handle_edl_request.
        bans = {"ban:1.2.3.4": json.dumps({"ip": "1.2.3.4", "score": 80, "timestamp": time.time()})}
        server = await _make_server_with_bans(bans)
        req = _make_request()
        req.match_info = {"list_name": "banned_ips"}
        resp = await server._handle_request(req)
        assert resp.status == 200
        assert "1.2.3.4" in resp.text

    @pytest.mark.asyncio
    async def test_unknown_list_name_returns_404(self):
        # Line 205: handle_edl_request returns 404 for unknown list names.
        # Without this, clients requesting /edl/bad_name would get a confusing error.
        bans = {}
        server = await _make_server_with_bans(bans)
        req = _make_request()
        resp = await server.handle_edl_request("nonexistent_list", req)
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_source_ip_restriction_falls_back_to_x_real_ip_header(self):
        # Lines 192-195: when request.remote is falsy, check X-Real-IP header.
        # This handles reverse-proxy deployments where remote is the proxy address.
        bans = {}
        server = await _make_server_with_bans(bans, {"allowed_ips": ["10.10.10.10"]})
        req = _make_request(remote="")
        req.remote = ""
        req.headers = {"X-Real-IP": "1.1.1.1"}
        resp = await server.handle_edl_request("banned_ips", req)
        assert resp.status == 403

    @pytest.mark.asyncio
    async def test_empty_body_has_no_trailing_newline(self):
        # Lines 224-225 (body += "\n" only when body is non-empty):
        # An empty list must not produce a file with a stray newline that
        # confuses firewall parsers treating blank lines as errors.
        bans = {}
        server = await _make_server_with_bans(bans)
        req = _make_request()
        resp = await server.handle_edl_request("banned_ips", req)
        assert resp.status == 200
        assert resp.text == ""
