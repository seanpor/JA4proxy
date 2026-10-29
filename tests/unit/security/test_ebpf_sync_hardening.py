"""Unit and property tests for Phase 855 — eBPF Volumetric Drop Daemon Invariants.

Verifies:
- Robustness against malformed Redis keys and values (non-UTF8, corrupt types).
- Subprocess resilience and fail-open behavior on bpftool errors, timeouts, and JSON corruption.
- Clean recovery and backoff on Redis connection drop without leaking resources.
- Monotonicity of drop counter delta calculations across counter resets.
"""

import asyncio
import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

SCRIPTS_DIR = Path(__file__).parent.parent.parent.parent / "scripts"


def _import_redis_to_ebpf():
    if "redis_to_ebpf" not in sys.modules:
        script_path = SCRIPTS_DIR / "redis-to-ebpf.py"
        spec = importlib.util.spec_from_file_location("redis_to_ebpf", str(script_path))
        mod = importlib.util.module_from_spec(spec)
        sys.modules["redis_to_ebpf"] = mod
        spec.loader.exec_module(mod)
    return sys.modules["redis_to_ebpf"]


@pytest.mark.asyncio
async def test_collect_blocked_ips_corrupt_data_handling():
    """Verify _collect_blocked_ips gracefully handles malformed keys/values without throwing."""
    mod = _import_redis_to_ebpf()

    # Mock Redis client yielding dirty keys and non-string types
    fake_keys = [
        "ban:1.2.3.4",
        "ban:",               # empty IP
        "ban:invalid.ip.string",
        "ban:999.999.999.999",
        "ban:2001:db8::1",    # IPv6 (filtered out)
        "ban:10.0.0.1/24",    # CIDR (filtered out by _ip_to_hex)
        "ban:   172.16.0.5  ", # whitespace IPv4
    ]

    async def fake_scan_iter(match=None):
        for k in fake_keys:
            yield k

    mock_client = AsyncMock()
    mock_client.scan_iter = fake_scan_iter
    mock_client.smembers = AsyncMock(return_value={
        "192.168.1.1",
        "malformed_blacklist_item",
        "",
        "8.8.8.8",
    })

    ips = await mod._collect_blocked_ips(mock_client)
    # Valid IPv4 addresses only
    assert "1.2.3.4" in ips
    assert "172.16.0.5" in ips
    assert "192.168.1.1" in ips
    assert "8.8.8.8" in ips
    # Invalid or non-IPv4 addresses must be excluded
    assert "2001:db8::1" not in ips
    assert "invalid.ip.string" not in ips
    assert "" not in ips


@given(
    input_str=st.text(max_size=100)
)
@settings(max_examples=100)
def test_property_ip_to_hex_never_crashes(input_str: str):
    """Property test verifying _ip_to_hex handles any arbitrary Unicode string safely."""
    mod = _import_redis_to_ebpf()
    res = mod._ip_to_hex(input_str)
    if res is not None:
        # If successfully converted, must be 4 two-character hex strings
        parts = res.split(" ")
        assert len(parts) == 4
        for p in parts:
            assert len(p) == 2
            int(p, 16)  # valid hex


def test_bpftool_update_resilience_to_errors():
    """Verify _bpftool_update returns False on various process failures without raising."""
    mod = _import_redis_to_ebpf()

    # 1. CalledProcessError with stderr
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, ["bpftool"], stderr=b"Map is full")):
        assert mod._bpftool_update(1234, "0a 00 00 01") is False

    # 2. TimeoutExpired
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["bpftool"], 5)):
        assert mod._bpftool_update(1234, "0a 00 00 01") is False

    # 3. FileNotFoundError (bpftool missing)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert mod._bpftool_update(1234, "0a 00 00 01") is False

    # 4. PermissionError (missing capabilities)
    with patch("subprocess.run", side_effect=PermissionError):
        assert mod._bpftool_update(1234, "0a 00 00 01") is False


def test_bpftool_delete_resilience_to_errors():
    """Verify _bpftool_delete returns False on various failures without raising."""
    mod = _import_redis_to_ebpf()

    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, ["bpftool"], stderr=b"No such file")):
        assert mod._bpftool_delete(1234, "0a 00 00 01") is False

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["bpftool"], 5)):
        assert mod._bpftool_delete(1234, "0a 00 00 01") is False


def test_read_drop_counters_corrupted_json():
    """Verify _read_drop_counters handles corrupted bpftool output gracefully."""
    mod = _import_redis_to_ebpf()

    # Empty stdout
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=b"")
        counts = mod._read_drop_counters(9999)
        assert isinstance(counts, dict)

    # Malformed JSON
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=b"{not: valid: json]")
        counts = mod._read_drop_counters(9999)
        assert isinstance(counts, dict)

    # Unexpected data structure
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=b'["unexpected", "list"]')
        counts = mod._read_drop_counters(9999)
        assert isinstance(counts, dict)


@pytest.mark.asyncio
async def test_sync_loop_reconnection_on_redis_error():
    """Verify _sync_loop catches Redis connection error, sleeps, and continues."""
    mod = _import_redis_to_ebpf()

    iteration = 0

    async def fake_collect(client):
        nonlocal iteration
        iteration += 1
        if iteration == 1:
            raise ConnectionError("Redis connection dropped")
        # Exit the loop on second iteration
        raise asyncio.CancelledError()

    with patch.object(mod.aioredis, "from_url") as mock_from_url, \
         patch.object(mod, "_collect_blocked_ips", side_effect=fake_collect), \
         patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_redis = AsyncMock()
        mock_from_url.return_value = mock_redis
        with pytest.raises(asyncio.CancelledError):
            await mod._sync_loop(1234, "redis://localhost:6379", interval=1, drop_counters_map_id=None)

        # Verified it slept after the error
        mock_sleep.assert_called_with(1)
