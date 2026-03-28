"""
Unit tests for GDPR delete functionality in src/tap/security.py — Group 12 (Phase 20).

Tests the ``gdpr_delete`` async function that implements the right-to-erasure
for fingerprint data stored under ``fp:*`` Redis keys.
"""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from src.tap.security import gdpr_delete


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redis(conn_ids: list[bytes] = None, delete_return: int = 1) -> MagicMock:
    """Return a mock synchronous redis-py client pre-configured for fp:* ops."""
    redis = MagicMock()
    redis.zrange.return_value = conn_ids if conn_ids is not None else []
    redis.delete.return_value = delete_return
    return redis


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGdprDelete:
    @pytest.mark.asyncio
    async def test_gdpr_delete_removes_fp_ip_key(self):
        """gdpr_delete must delete the fp:ip:{ip} sorted-set key."""
        redis = _make_redis(conn_ids=[])
        await gdpr_delete("1.2.3.4", redis)

        deleted_keys = [str(c) for c in redis.delete.call_args_list]
        assert any("fp:ip:1.2.3.4" in k for k in deleted_keys)

    @pytest.mark.asyncio
    async def test_gdpr_delete_removes_all_fp_conn_keys_for_ip(self):
        """gdpr_delete must delete fp:conn:{conn_id} for every conn_id stored under fp:ip."""
        redis = _make_redis(conn_ids=[b"conn-abc", b"conn-def"])

        await gdpr_delete("1.2.3.4", redis)

        deleted_keys = [str(c) for c in redis.delete.call_args_list]
        assert any("fp:conn:conn-abc" in k for k in deleted_keys)
        assert any("fp:conn:conn-def" in k for k in deleted_keys)

    @pytest.mark.asyncio
    async def test_gdpr_delete_does_not_remove_other_ip_keys(self):
        """Deleting data for 1.2.3.4 must not touch fp:ip:5.6.7.8."""
        redis = _make_redis(conn_ids=[b"conn-111"])

        await gdpr_delete("1.2.3.4", redis)

        deleted_keys = [str(c) for c in redis.delete.call_args_list]
        assert not any("5.6.7.8" in k for k in deleted_keys)

    @pytest.mark.asyncio
    async def test_gdpr_delete_removes_fp_os_ip_key(self):
        """gdpr_delete must also delete fp:os:ip:{ip}."""
        redis = _make_redis(conn_ids=[])

        await gdpr_delete("2001:db8::1", redis)

        deleted_keys = [str(c) for c in redis.delete.call_args_list]
        assert any("fp:os:ip:2001:db8::1" in k for k in deleted_keys)

    @pytest.mark.asyncio
    async def test_gdpr_delete_returns_deleted_key_count(self):
        """Return dict must contain 'deleted_keys' with the total count."""
        redis = _make_redis(conn_ids=[b"conn-x", b"conn-y"], delete_return=1)

        result = await gdpr_delete("10.0.0.1", redis)

        # 2 conn keys + 1 fp:ip key + 1 fp:os:ip key = 4 calls, each returning 1
        assert result["deleted_keys"] == 4
        assert result["ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_gdpr_delete_returns_ip_in_result(self):
        """Return dict must contain 'ip' matching the requested IP."""
        redis = _make_redis(conn_ids=[])
        result = await gdpr_delete("192.168.1.100", redis)
        assert result["ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_gdpr_delete_handles_empty_conn_list(self):
        """When there are no connections for the IP, function must complete cleanly."""
        redis = _make_redis(conn_ids=[])

        result = await gdpr_delete("3.3.3.3", redis)

        # fp:ip + fp:os:ip = 2 delete calls
        assert redis.delete.call_count == 2
        assert result["ip"] == "3.3.3.3"

    @pytest.mark.asyncio
    async def test_gdpr_delete_queries_correct_sorted_set_key(self):
        """zrange must be called on fp:ip:{ip} to discover conn_ids."""
        redis = _make_redis(conn_ids=[])

        await gdpr_delete("172.16.0.5", redis)

        redis.zrange.assert_called_once()
        call_args = redis.zrange.call_args
        assert "fp:ip:172.16.0.5" in str(call_args)

    @pytest.mark.asyncio
    async def test_gdpr_delete_handles_string_conn_ids(self):
        """Conn IDs returned as plain strings (not bytes) must also be handled."""
        redis = MagicMock()
        redis.zrange.return_value = ["conn-str-1", "conn-str-2"]
        redis.delete.return_value = 1

        await gdpr_delete("4.4.4.4", redis)

        deleted_keys = [str(c) for c in redis.delete.call_args_list]
        assert any("fp:conn:conn-str-1" in k for k in deleted_keys)
        assert any("fp:conn:conn-str-2" in k for k in deleted_keys)
