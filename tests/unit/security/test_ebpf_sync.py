"""Unit tests for Phase 35b — scripts/redis-to-ebpf.py (eBPF/XDP sync service).

Tests the actual module-level functions exposed by redis-to-ebpf.py:
- _ip_to_hex: IPv4 → 4-byte hex string; IPv6 → None
- _bpftool_update: graceful fallback on FileNotFoundError, PermissionError
- _bpftool_delete: graceful fallback on errors
- _collect_blocked_ips: async; reads scan_iter("ban:*") and smembers("ip:blacklist")
- _sync_loop: Prometheus counter ja4proxy_ebpf_drops_total registered at import
"""

import asyncio
import importlib
import importlib.util
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent.parent.parent / "scripts"


# ---------------------------------------------------------------------------
# Helpers — dynamic import of the script as a module (once per session)
# ---------------------------------------------------------------------------

# Import once at module level to avoid Prometheus counter duplicate registration
# errors that occur when exec_module() is called multiple times.
def _import_redis_to_ebpf():
    """Return the cached redis_to_ebpf module, importing it once."""
    if "redis_to_ebpf" not in sys.modules:
        script_path = SCRIPTS_DIR / "redis-to-ebpf.py"
        spec = importlib.util.spec_from_file_location("redis_to_ebpf", str(script_path))
        mod = importlib.util.module_from_spec(spec)
        sys.modules["redis_to_ebpf"] = mod
        spec.loader.exec_module(mod)
    return sys.modules["redis_to_ebpf"]


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _ip_to_hex
# ---------------------------------------------------------------------------


class TestIpToHex:
    """Tests for _ip_to_hex()."""

    def test_ipv4_returns_hex_string(self):
        """Valid IPv4 address returns a 4-byte space-separated hex string."""
        mod = _import_redis_to_ebpf()
        result = mod._ip_to_hex("10.0.0.1")
        assert result is not None
        # Should be 4 hex bytes separated by spaces: "0a 00 00 01"
        parts = result.split()
        assert len(parts) == 4, f"Expected 4 hex bytes, got: {result!r}"
        # Each part should be a 2-char hex string
        for p in parts:
            assert len(p) == 2, f"Each byte should be 2 hex chars, got: {p!r}"
            int(p, 16)  # should not raise

    def test_known_ipv4_encoding(self):
        """10.0.0.1 encodes as '0a 00 00 01'."""
        mod = _import_redis_to_ebpf()
        result = mod._ip_to_hex("10.0.0.1")
        assert result == "0a 00 00 01"

    def test_ipv6_returns_none(self):
        """IPv6 addresses return None — not supported by the XDP map."""
        mod = _import_redis_to_ebpf()
        result = mod._ip_to_hex("2001:db8::1")
        assert result is None, f"IPv6 should return None, got: {result!r}"

    def test_invalid_ip_returns_none(self):
        """Non-IP strings return None without raising."""
        mod = _import_redis_to_ebpf()
        assert mod._ip_to_hex("not-an-ip") is None
        assert mod._ip_to_hex("") is None
        assert mod._ip_to_hex("256.0.0.1") is None

    def test_ipv4_with_whitespace_is_handled(self):
        """Leading/trailing whitespace in the IP string is stripped."""
        mod = _import_redis_to_ebpf()
        result = mod._ip_to_hex("  192.168.1.1  ")
        assert result is not None
        parts = result.split()
        assert len(parts) == 4


# ---------------------------------------------------------------------------
# _bpftool_update — graceful fallback
# ---------------------------------------------------------------------------


class TestBpftoolUpdate:
    """Tests for _bpftool_update() graceful error handling."""

    def test_returns_true_on_success(self):
        """Returns True when bpftool exits 0."""
        mod = _import_redis_to_ebpf()

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            result = mod._bpftool_update(42, "0a 00 00 01")

        assert result is True

    def test_bpftool_not_found_returns_false_does_not_raise(self, caplog):
        """FileNotFoundError (bpftool not on PATH) → returns False, logs WARNING."""
        mod = _import_redis_to_ebpf()

        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run", side_effect=FileNotFoundError("bpftool: not found")):
                result = mod._bpftool_update(42, "0a 00 00 01")

        assert result is False
        warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(
            "bpftool" in msg.lower() or "ebpf" in msg.lower()
            for msg in warning_msgs
        ), f"Expected WARNING about bpftool, got: {warning_msgs}"

    def test_permission_error_returns_false_does_not_raise(self, caplog):
        """PermissionError (missing CAP_BPF) → returns False, logs WARNING."""
        mod = _import_redis_to_ebpf()

        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run", side_effect=PermissionError("Operation not permitted")):
                result = mod._bpftool_update(42, "0a 00 00 01")

        assert result is False
        warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(
            "permission" in msg.lower() or "cap_bpf" in msg.lower() or "ebpf" in msg.lower()
            for msg in warning_msgs
        ), f"Expected WARNING about permission denial, got: {warning_msgs}"

    def test_called_process_error_returns_false(self):
        """CalledProcessError (bpftool error) → returns False."""
        mod = _import_redis_to_ebpf()

        err = subprocess.CalledProcessError(1, ["bpftool"], stderr=b"map not found")
        with patch("subprocess.run", side_effect=err):
            result = mod._bpftool_update(42, "0a 00 00 01")

        assert result is False

    def test_timeout_returns_false(self):
        """TimeoutExpired → returns False."""
        mod = _import_redis_to_ebpf()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["bpftool"], 5)):
            result = mod._bpftool_update(42, "0a 00 00 01")

        assert result is False


# ---------------------------------------------------------------------------
# _bpftool_delete — graceful fallback
# ---------------------------------------------------------------------------


class TestBpftoolDelete:
    """Tests for _bpftool_delete() graceful error handling."""

    def test_returns_true_on_success(self):
        """Returns True when bpftool delete exits 0."""
        mod = _import_redis_to_ebpf()

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            result = mod._bpftool_delete(42, "0a 00 00 01")

        assert result is True

    def test_file_not_found_returns_false(self):
        """FileNotFoundError → returns False without raising."""
        mod = _import_redis_to_ebpf()

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = mod._bpftool_delete(42, "0a 00 00 01")

        assert result is False

    def test_permission_error_returns_false(self):
        """PermissionError → returns False without raising."""
        mod = _import_redis_to_ebpf()

        with patch("subprocess.run", side_effect=PermissionError("EPERM")):
            result = mod._bpftool_delete(42, "0a 00 00 01")

        assert result is False


# ---------------------------------------------------------------------------
# _collect_blocked_ips — async Redis reading
# ---------------------------------------------------------------------------


class TestCollectBlockedIps:
    """Tests for _collect_blocked_ips() — reads ban:* and ip:blacklist from Redis."""

    def _make_async_redis(self, ban_keys=None, blacklist_members=None):
        """Return an AsyncMock Redis client with configurable state.

        Implements scan_iter as an async generator and smembers as an AsyncMock.
        """
        ban_keys = [k.encode() for k in (ban_keys or [])]
        blacklist_members = {m.encode() for m in (blacklist_members or [])}

        r = MagicMock()

        async def _mock_scan_iter(pattern):
            for key in ban_keys:
                yield key

        r.scan_iter = _mock_scan_iter
        r.smembers = AsyncMock(return_value=blacklist_members)
        return r

    def test_collects_ban_keys(self):
        """IPs from ban:{ip} keys are included with reason='ban'."""
        mod = _import_redis_to_ebpf()
        redis = self._make_async_redis(ban_keys=["ban:10.0.0.1", "ban:192.168.1.2"])

        result = _run(mod._collect_blocked_ips(redis))

        assert "10.0.0.1" in result
        assert result["10.0.0.1"] == "ban"
        assert "192.168.1.2" in result
        assert result["192.168.1.2"] == "ban"

    def test_collects_ip_blacklist_members(self):
        """IPs from ip:blacklist SET are included with reason='blacklist'."""
        mod = _import_redis_to_ebpf()
        redis = self._make_async_redis(blacklist_members=["172.16.0.10"])

        result = _run(mod._collect_blocked_ips(redis))

        assert "172.16.0.10" in result
        assert result["172.16.0.10"] == "blacklist"

    def test_ban_takes_precedence_over_blacklist(self):
        """An IP in both ban:* and ip:blacklist is stored with reason='ban'."""
        mod = _import_redis_to_ebpf()
        redis = self._make_async_redis(
            ban_keys=["ban:10.0.0.1"],
            blacklist_members=["10.0.0.1"],
        )

        result = _run(mod._collect_blocked_ips(redis))

        # ban is inserted first, blacklist skips duplicates
        assert result.get("10.0.0.1") == "ban"

    def test_empty_redis_returns_empty_dict(self):
        """No keys in Redis → empty result, no error."""
        mod = _import_redis_to_ebpf()
        redis = self._make_async_redis()

        result = _run(mod._collect_blocked_ips(redis))

        assert result == {}

    def test_redis_error_returns_empty_dict_does_not_raise(self, caplog):
        """Redis exception → returns empty dict (fail-open), logs error."""
        mod = _import_redis_to_ebpf()

        r = MagicMock()

        async def _broken_scan_iter(pattern):
            raise ConnectionError("Redis unavailable")
            yield  # make it an async generator

        r.scan_iter = _broken_scan_iter
        r.smembers = AsyncMock(side_effect=ConnectionError("Redis unavailable"))

        with caplog.at_level(logging.ERROR):
            result = _run(mod._collect_blocked_ips(r))

        assert result == {}
        error_msgs = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
        assert any(
            "redis" in msg.lower() or "error" in msg.lower()
            for msg in error_msgs
        ), f"Expected ERROR log about Redis failure, got: {error_msgs}"

    def test_does_not_call_write_operations(self):
        """_collect_blocked_ips is read-only — must not write to Redis."""
        mod = _import_redis_to_ebpf()
        redis = self._make_async_redis(ban_keys=["ban:10.0.0.1"])
        redis.set = AsyncMock()
        redis.delete = AsyncMock()
        redis.sadd = AsyncMock()
        redis.srem = AsyncMock()

        _run(mod._collect_blocked_ips(redis))

        redis.set.assert_not_called()
        redis.delete.assert_not_called()
        redis.sadd.assert_not_called()
        redis.srem.assert_not_called()

    def test_scans_ban_star_pattern(self):
        """scan_iter is called with 'ban:*' pattern."""
        mod = _import_redis_to_ebpf()

        scan_iter_calls = []

        async def _recording_scan_iter(pattern):
            scan_iter_calls.append(pattern)
            return
            yield  # make it an async generator

        r = MagicMock()
        r.scan_iter = _recording_scan_iter
        r.smembers = AsyncMock(return_value=set())

        _run(mod._collect_blocked_ips(r))

        assert "ban:*" in scan_iter_calls, (
            f"scan_iter should be called with 'ban:*', got: {scan_iter_calls}"
        )

    def test_reads_ip_blacklist_set(self):
        """smembers is called with 'ip:blacklist'."""
        mod = _import_redis_to_ebpf()

        async def _empty_scan_iter(pattern):
            return
            yield

        r = MagicMock()
        r.scan_iter = _empty_scan_iter
        r.smembers = AsyncMock(return_value=set())

        _run(mod._collect_blocked_ips(r))

        r.smembers.assert_called_once_with("ip:blacklist")


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------


class TestPrometheusMetrics:
    """Tests that ja4proxy_ebpf_drops_total is registered at import time."""

    def test_ebpf_drops_counter_registered(self):
        """ja4proxy_ebpf_drops_total counter with reason label is registered."""
        mod = _import_redis_to_ebpf()

        from prometheus_client import REGISTRY

        registered_names = set(REGISTRY._names_to_collectors.keys())
        assert any("ebpf_drops" in name for name in registered_names), (
            f"ja4proxy_ebpf_drops_total not registered in Prometheus registry. "
            f"Registered ja4proxy metrics: {[n for n in registered_names if 'ja4proxy' in n]}"
        )

    def test_ebpf_sync_errors_counter_registered(self):
        """ja4proxy_ebpf_sync_errors_total counter is registered at import time."""
        mod = _import_redis_to_ebpf()

        from prometheus_client import REGISTRY

        registered_names = set(REGISTRY._names_to_collectors.keys())
        assert any("ebpf_sync_errors" in name for name in registered_names), (
            f"ja4proxy_ebpf_sync_errors_total not registered. "
            f"Registered: {[n for n in registered_names if 'ja4proxy' in n]}"
        )
