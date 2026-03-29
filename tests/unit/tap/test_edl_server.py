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
