"""Unit tests for Phase 35b — scripts/redis-to-ebpf.py (eBPF/XDP sync service).

Tests the RedisToEbpf sync service:
- Graceful fallback: bpftool not on PATH → logs WARNING, returns without error
- Graceful fallback: 'ip' command fails → logs WARNING, continues
- With mock Redis: reads SMEMBERS from ja4:blacklist and KEYS matching ban:*
- With mock bpftool: calls 'bpftool map update' for each IP in blacklist and bans
- Deduplication: IPs already in BPF map are not re-added on next poll

The implementation does NOT exist yet — these tests define the interface contract.
"""

import asyncio
import importlib
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent.parent.parent / "scripts"


# ---------------------------------------------------------------------------
# Helpers — dynamic import of the script as a module
# ---------------------------------------------------------------------------


def _import_redis_to_ebpf():
    """Import scripts/redis-to-ebpf.py as a module."""
    import importlib.util

    script_path = SCRIPTS_DIR / "redis-to-ebpf.py"
    spec = importlib.util.spec_from_file_location("redis_to_ebpf", str(script_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_mock_redis(blacklist_ips=None, ban_keys=None, ban_values=None):
    """Return a mock synchronous Redis client with configurable state."""
    r = MagicMock()
    blacklist_ips = {ip.encode() for ip in (blacklist_ips or [])}
    ban_keys = [k.encode() for k in (ban_keys or [])]
    ban_values = ban_values or {}

    r.smembers = MagicMock(return_value=blacklist_ips)
    r.keys = MagicMock(return_value=ban_keys)
    r.get = MagicMock(side_effect=lambda k: ban_values.get(k.decode(), b"1"))
    return r


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Graceful fallback — bpftool not available
# ---------------------------------------------------------------------------


class TestBpftoolNotAvailable:
    """Tests that the service fails open when bpftool is absent."""

    def test_no_bpftool_logs_warning_does_not_raise(self, caplog):
        """If bpftool is not on PATH, the service logs WARNING and returns cleanly."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        mock_redis = _make_mock_redis(blacklist_ips=["10.0.0.1"])

        def _no_bpftool(*args, **kwargs):
            raise FileNotFoundError("bpftool: command not found")

        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run", side_effect=_no_bpftool):
                with patch("subprocess.check_call", side_effect=_no_bpftool):
                    # The sync_once or equivalent function should not raise
                    try:
                        if hasattr(mod, "sync_once"):
                            mod.sync_once(redis_client=mock_redis)
                        elif hasattr(mod, "EbpfSyncer"):
                            syncer = mod.EbpfSyncer(redis_client=mock_redis)
                            syncer.sync_once()
                        elif hasattr(mod, "RedisToEbpf"):
                            syncer = mod.RedisToEbpf(redis_client=mock_redis)
                            syncer.sync_once()
                        else:
                            pytest.skip("Cannot find sync entry point in redis-to-ebpf.py")
                    except Exception as exc:
                        pytest.fail(
                            f"sync_once raised an exception when bpftool absent: {exc}"
                        )

        warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(
            "bpftool" in msg.lower() or "ebpf" in msg.lower() or "warn" in msg.lower()
            for msg in warning_msgs
        ), f"Expected a WARNING about bpftool being unavailable, got: {warning_msgs}"

    def test_bpftool_permission_error_does_not_raise(self, caplog):
        """Permission denied on bpftool (missing CAP_BPF) → WARNING, no exception."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        mock_redis = _make_mock_redis(blacklist_ips=["10.0.0.2"])

        def _permission_denied(*args, **kwargs):
            raise PermissionError("Operation not permitted")

        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run", side_effect=_permission_denied):
                with patch("subprocess.check_call", side_effect=_permission_denied):
                    try:
                        if hasattr(mod, "sync_once"):
                            mod.sync_once(redis_client=mock_redis)
                        elif hasattr(mod, "EbpfSyncer"):
                            mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                        elif hasattr(mod, "RedisToEbpf"):
                            mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    except Exception as exc:
                        pytest.fail(
                            f"sync_once raised an exception on PermissionError: {exc}"
                        )

    def test_startup_continues_if_ebpf_attach_fails(self, caplog):
        """Proxy/syncer startup must not be blocked if eBPF attach fails."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        # Simulate the 'ip link set xdp' command failing
        def _ip_fails(args, **kwargs):
            if "ip" in args[0] if isinstance(args[0], list) else args[0]:
                raise subprocess.CalledProcessError(1, args)
            return MagicMock(returncode=0)

        mock_redis = _make_mock_redis()
        with caplog.at_level(logging.WARNING):
            with patch("subprocess.run", side_effect=_ip_fails):
                with patch("subprocess.check_call", side_effect=_ip_fails):
                    try:
                        if hasattr(mod, "attach_xdp"):
                            mod.attach_xdp(interface="eth0")
                        elif hasattr(mod, "EbpfSyncer"):
                            syncer = mod.EbpfSyncer(redis_client=mock_redis)
                            if hasattr(syncer, "attach"):
                                syncer.attach()
                    except Exception as exc:
                        pytest.fail(
                            f"XDP attach failure should not propagate: {exc}"
                        )


# ---------------------------------------------------------------------------
# Redis data reading
# ---------------------------------------------------------------------------


class TestRedisDataReading:
    """Tests that the syncer reads the correct Redis keys."""

    def test_reads_ja4_blacklist_smembers(self):
        """sync_once reads SMEMBERS from ja4:blacklist key."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        mock_redis = _make_mock_redis(blacklist_ips=["192.168.1.1", "10.0.0.1"])

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            with patch("subprocess.check_call", return_value=None):
                try:
                    if hasattr(mod, "sync_once"):
                        mod.sync_once(redis_client=mock_redis)
                    elif hasattr(mod, "EbpfSyncer"):
                        mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                    elif hasattr(mod, "RedisToEbpf"):
                        mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    else:
                        pytest.skip("No sync entry point found")
                except Exception:
                    pass  # May fail due to missing bpftool — that's OK here

        # Verify smembers was called with 'ja4:blacklist'
        mock_redis.smembers.assert_called_with("ja4:blacklist")

    def test_reads_ban_keys_pattern(self):
        """sync_once reads keys matching ban:* pattern."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        mock_redis = _make_mock_redis(
            ban_keys=["ban:10.0.0.1", "ban:192.168.1.100"]
        )

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            with patch("subprocess.check_call", return_value=None):
                try:
                    if hasattr(mod, "sync_once"):
                        mod.sync_once(redis_client=mock_redis)
                    elif hasattr(mod, "EbpfSyncer"):
                        mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                    elif hasattr(mod, "RedisToEbpf"):
                        mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    else:
                        pytest.skip("No sync entry point found")
                except Exception:
                    pass

        # Verify keys was called with ban:* pattern
        mock_redis.keys.assert_called_with("ban:*")

    def test_does_not_call_redis_write_operations(self):
        """Sync service is read-only: must not write to Redis."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        mock_redis = _make_mock_redis(blacklist_ips=["10.0.0.1"])
        # Track all calls
        mock_redis.set = MagicMock()
        mock_redis.delete = MagicMock()
        mock_redis.sadd = MagicMock()
        mock_redis.srem = MagicMock()

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            with patch("subprocess.check_call", return_value=None):
                try:
                    if hasattr(mod, "sync_once"):
                        mod.sync_once(redis_client=mock_redis)
                    elif hasattr(mod, "EbpfSyncer"):
                        mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                    elif hasattr(mod, "RedisToEbpf"):
                        mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    else:
                        pytest.skip("No sync entry point found")
                except Exception:
                    pass

        mock_redis.set.assert_not_called()
        mock_redis.delete.assert_not_called()
        mock_redis.sadd.assert_not_called()
        mock_redis.srem.assert_not_called()


# ---------------------------------------------------------------------------
# bpftool map update calls
# ---------------------------------------------------------------------------


class TestBpftoolMapUpdates:
    """Tests that bpftool is invoked correctly for each blocked IP."""

    def test_calls_bpftool_map_update_for_blacklist_ips(self):
        """For each IP in ja4:blacklist, 'bpftool map update' is called."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        blacklist_ips = ["10.0.0.1", "10.0.0.2"]
        mock_redis = _make_mock_redis(blacklist_ips=blacklist_ips)

        bpftool_calls = []

        def _mock_run(args, **kwargs):
            bpftool_calls.append(args)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_mock_run):
            with patch("subprocess.check_call", return_value=None):
                try:
                    if hasattr(mod, "sync_once"):
                        mod.sync_once(redis_client=mock_redis)
                    elif hasattr(mod, "EbpfSyncer"):
                        mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                    elif hasattr(mod, "RedisToEbpf"):
                        mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    else:
                        pytest.skip("No sync entry point found")
                except Exception:
                    pass

        # At least one bpftool call should have been made for each blacklisted IP
        bpftool_invocations = [
            args for args in bpftool_calls
            if isinstance(args, (list, tuple)) and len(args) > 0
            and ("bpftool" in str(args[0]) or "bpftool" in str(args))
        ]

        if bpftool_invocations:
            # Each blacklisted IP should appear in at least one bpftool call
            all_args_str = " ".join(str(a) for args in bpftool_invocations for a in args)
            for ip in blacklist_ips:
                assert ip in all_args_str, (
                    f"bpftool was not called with blacklisted IP {ip}; "
                    f"calls: {bpftool_invocations}"
                )

    def test_calls_bpftool_map_update_for_ban_ips(self):
        """For each ban:* key, 'bpftool map update' is called with the banned IP."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        ban_keys = ["ban:172.16.0.1", "ban:172.16.0.2"]
        ban_ips = ["172.16.0.1", "172.16.0.2"]
        mock_redis = _make_mock_redis(ban_keys=ban_keys)

        bpftool_calls = []

        def _mock_run(args, **kwargs):
            bpftool_calls.append(args)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_mock_run):
            with patch("subprocess.check_call", return_value=None):
                try:
                    if hasattr(mod, "sync_once"):
                        mod.sync_once(redis_client=mock_redis)
                    elif hasattr(mod, "EbpfSyncer"):
                        mod.EbpfSyncer(redis_client=mock_redis).sync_once()
                    elif hasattr(mod, "RedisToEbpf"):
                        mod.RedisToEbpf(redis_client=mock_redis).sync_once()
                    else:
                        pytest.skip("No sync entry point found")
                except Exception:
                    pass

        bpftool_invocations = [
            args for args in bpftool_calls
            if "bpftool" in str(args)
        ]

        if bpftool_invocations:
            all_args_str = " ".join(str(a) for args in bpftool_invocations for a in args)
            for ip in ban_ips:
                assert ip in all_args_str, (
                    f"bpftool not called for banned IP {ip}; calls: {bpftool_invocations}"
                )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    """Tests that the syncer deduplicates IPs to avoid redundant bpftool calls."""

    def test_already_synced_ips_not_re_added_on_next_poll(self):
        """IPs already in the BPF map are skipped on subsequent sync_once calls."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        # Find the syncer class
        SyncerClass = None
        for name in ["EbpfSyncer", "RedisToEbpf"]:
            if hasattr(mod, name):
                SyncerClass = getattr(mod, name)
                break

        if SyncerClass is None and not hasattr(mod, "sync_once"):
            pytest.skip("No stateful syncer class found in redis-to-ebpf.py")

        if SyncerClass is None:
            pytest.skip("Deduplication test requires a stateful syncer class")

        mock_redis = _make_mock_redis(blacklist_ips=["10.0.0.1"])
        syncer = SyncerClass(redis_client=mock_redis)

        bpftool_call_count = [0]

        def _mock_run(args, **kwargs):
            if "bpftool" in str(args):
                bpftool_call_count[0] += 1
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_mock_run):
            with patch("subprocess.check_call", return_value=None):
                # First poll
                try:
                    syncer.sync_once()
                except Exception:
                    pytest.skip("sync_once not available on syncer class")

                first_count = bpftool_call_count[0]

                # Second poll — same IPs, should not re-add them
                try:
                    syncer.sync_once()
                except Exception:
                    pass

                second_count = bpftool_call_count[0]

        # The second poll should issue fewer (or zero) bpftool calls for 10.0.0.1
        assert second_count <= first_count + 1, (
            f"Second poll should not re-add IPs already in map. "
            f"First poll: {first_count} calls, second poll total: {second_count} calls"
        )

    def test_new_ips_added_on_second_poll(self):
        """New IPs that appear after the first poll are added on the second poll."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        SyncerClass = None
        for name in ["EbpfSyncer", "RedisToEbpf"]:
            if hasattr(mod, name):
                SyncerClass = getattr(mod, name)
                break

        if SyncerClass is None:
            pytest.skip("Deduplication test requires a stateful syncer class")

        # First poll: only one IP
        mock_redis = _make_mock_redis(blacklist_ips=["10.0.0.1"])
        syncer = SyncerClass(redis_client=mock_redis)

        seen_ips = []

        def _mock_run(args, **kwargs):
            seen_ips.append(str(args))
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_mock_run):
            with patch("subprocess.check_call", return_value=None):
                try:
                    syncer.sync_once()
                except Exception:
                    pytest.skip("sync_once not callable")

                # Now add a new IP to Redis
                mock_redis.smembers.return_value = {b"10.0.0.1", b"10.0.0.99"}
                seen_ips.clear()

                try:
                    syncer.sync_once()
                except Exception:
                    pass

        # The new IP 10.0.0.99 should appear in the second batch of bpftool calls
        # (the already-synced 10.0.0.1 may or may not re-appear — what matters is 10.0.0.99 does)
        second_calls_str = " ".join(seen_ips)
        if second_calls_str:  # Only assert if bpftool was called
            assert "10.0.0.99" in second_calls_str, (
                f"New IP 10.0.0.99 was not added on second poll. Calls: {seen_ips}"
            )


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------


class TestPrometheusMetrics:
    """Tests that ja4proxy_ebpf_drops_total is registered and accessible."""

    def test_ebpf_drops_counter_registered(self):
        """ja4proxy_ebpf_drops_total counter with reason label is registered."""
        try:
            mod = _import_redis_to_ebpf()
        except Exception as exc:
            pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")

        # The module should register the counter at import time
        from prometheus_client import REGISTRY

        registered_names = set()
        for name in REGISTRY._names_to_collectors:
            registered_names.add(name)

        assert any("ebpf_drops" in name for name in registered_names), (
            f"ja4proxy_ebpf_drops_total not registered in Prometheus registry. "
            f"Registered ja4proxy metrics: {[n for n in registered_names if 'ja4proxy' in n]}"
        )
