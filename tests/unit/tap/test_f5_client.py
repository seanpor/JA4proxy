"""
Unit tests for src/tap/export/f5_client.py — Phase 20, Group 9.
"""
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tap.export.f5_client import F5Client

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    cfg = {
        "base_url": "https://f5.example.com",
        "username": "admin",
        "password": "pass",
        "data_group": "ja4proxy_blocklist",
        "max_rps": 10,
        "verify_tls": True,
    }
    cfg.update(overrides)
    return cfg


def _make_response(status: int) -> MagicMock:
    resp = AsyncMock()
    resp.status = status
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _make_session(*responses) -> MagicMock:
    """Return a mock session whose patch() returns each response in sequence."""
    session = MagicMock()
    session.patch.side_effect = list(responses)
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFullSync:
    @pytest.mark.asyncio
    async def test_full_sync_patches_configured_data_group(self):
        """full_sync must issue a PATCH to the configured data group."""
        resp = _make_response(200)
        session = _make_session(resp)
        client = F5Client(_make_config(), session)

        await client.full_sync()

        session.patch.assert_called_once()
        call_args = session.patch.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get("url", "")
        assert "ja4proxy_blocklist" in url


class TestDeltaPush:
    @pytest.mark.asyncio
    async def test_delta_push_adds_single_ip(self):
        """delta_push must call PATCH with the IP in the request payload."""
        resp = _make_response(200)
        session = _make_session(resp)
        client = F5Client(_make_config(), session)

        await client.delta_push("1.2.3.4", "add")

        session.patch.assert_called_once()
        call_kwargs = session.patch.call_args.kwargs
        records = call_kwargs.get("json", {}).get("records", [])
        ips = [r.get("name") for r in records]
        assert "1.2.3.4" in ips

    @pytest.mark.asyncio
    async def test_delta_push_fires_without_delay(self):
        """delta_push must complete quickly (no artificial delay on first call)."""
        resp = _make_response(200)
        session = _make_session(resp)
        client = F5Client(_make_config(), session)

        start = time.monotonic()
        await client.delta_push("1.2.3.4", "add")
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"delta_push took too long: {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_retry_on_429(self):
        """delta_push must retry once on 429 before succeeding."""
        resp_429 = _make_response(429)
        resp_200 = _make_response(200)
        session = _make_session(resp_429, resp_200)

        client = F5Client(_make_config(), session)

        with patch("src.tap.export.f5_client.asyncio.sleep", new=AsyncMock()):
            await client.delta_push("1.2.3.4", "add")

        assert session.patch.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_on_503(self):
        """delta_push must retry once on 503 before succeeding."""
        resp_503 = _make_response(503)
        resp_200 = _make_response(200)
        session = _make_session(resp_503, resp_200)

        client = F5Client(_make_config(), session)

        with patch("src.tap.export.f5_client.asyncio.sleep", new=AsyncMock()):
            await client.delta_push("1.2.3.4", "add")

        assert session.patch.call_count == 2

    @pytest.mark.asyncio
    async def test_max_rps_semaphore_limits_concurrency(self):
        """max_rps semaphore should limit concurrent requests."""
        # Just verify that the semaphore exists and has correct value
        client = F5Client(_make_config(max_rps=5), MagicMock())
        assert client._semaphore._value == 5


class TestRateLimit:
    @pytest.mark.asyncio
    async def test_rate_limit_tracking_list_exists(self):
        """Client should track request timestamps for rate limiting."""
        client = F5Client(_make_config(max_rps=10), MagicMock())
        assert hasattr(client, "_request_times")
        assert isinstance(client._request_times, list)


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------

class TestAcquireRateSlot:
    """Lines 63-66: rate slot waits when max_rps is already at capacity."""

    @pytest.mark.asyncio
    async def test_rate_slot_fills_timestamps_on_each_request(self):
        # Lines 55-67: _acquire_rate_slot appends to _request_times on each call.
        # Without this tracking, max_rps enforcement is silently bypassed.
        client = F5Client(_make_config(max_rps=10), MagicMock())
        assert len(client._request_times) == 0
        await client._acquire_rate_slot()
        assert len(client._request_times) == 1

    @pytest.mark.asyncio
    async def test_rate_slot_evicts_timestamps_older_than_one_second(self):
        # Lines 59-60: timestamps older than 1 second are removed before each check.
        # Without eviction, _request_times grows unbounded and always triggers waits.
        import time as _time
        client = F5Client(_make_config(max_rps=10), MagicMock())
        # Inject a timestamp 2 seconds in the past
        client._request_times.append(_time.monotonic() - 2.0)
        await client._acquire_rate_slot()
        # The stale timestamp should have been evicted; only the new one remains
        assert len(client._request_times) == 1

    @pytest.mark.asyncio
    async def test_rate_slot_sleeps_when_at_capacity(self):
        # Lines 63-66: when _request_times is at capacity, sleep until a slot frees.
        # Without this sleep, max_rps would be exceeded, potentially triggering F5 429s.
        import time as _time
        with patch("src.tap.export.f5_client.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            client = F5Client(_make_config(max_rps=2), MagicMock())
            # Pre-fill request_times to simulate being at max_rps
            now = _time.monotonic()
            client._request_times = [now - 0.1, now - 0.05]  # two recent requests
            await client._acquire_rate_slot()
            mock_sleep.assert_called_once()


class TestPatchDataGroupEdgeCases:
    """Lines 79-80, 92-93, 137, 140-147: exception paths in delta_push and _patch_data_group."""

    @pytest.mark.asyncio
    async def test_full_sync_exception_is_caught_not_propagated(self):
        # Lines 79-80: full_sync catches all exceptions from _patch_data_group.
        # An F5 outage must not crash the proxy's export pipeline.
        session = MagicMock()
        session.patch.side_effect = ConnectionError("F5 unreachable")
        client = F5Client(_make_config(), session)
        await client.full_sync()  # must not raise

    @pytest.mark.asyncio
    async def test_delta_push_exception_is_caught_not_propagated(self):
        # Lines 92-93: delta_push catches all exceptions from _patch_data_group.
        # A bad F5 response must not prevent other export targets from being notified.
        session = MagicMock()
        session.patch.side_effect = ConnectionError("connection reset")
        client = F5Client(_make_config(), session)
        await client.delta_push("1.2.3.4", "add")  # must not raise

    @pytest.mark.asyncio
    async def test_max_retries_exhausted_returns_without_crash(self):
        # Line 137: after _MAX_RETRIES exhausted on 429, method returns without raising.
        # Retry budget exhaustion must not propagate — drop the update, log, move on.
        resp_429 = _make_response(429)
        session = _make_session(resp_429, resp_429, resp_429, resp_429)
        client = F5Client(_make_config(), session)

        with patch("src.tap.export.f5_client.asyncio.sleep", new=AsyncMock()):
            await client.delta_push("1.2.3.4", "add")  # must not raise

        # Should have attempted _MAX_RETRIES + 1 times (3 + 1 = 4)
        assert session.patch.call_count == 4

    @pytest.mark.asyncio
    async def test_patch_exception_retries_up_to_max(self):
        # Lines 140-147: session.patch() exception triggers retry up to _MAX_RETRIES.
        # Transient network errors should be retried before giving up.
        session = MagicMock()
        session.patch.side_effect = OSError("connection refused")
        client = F5Client(_make_config(), session)

        with patch("src.tap.export.f5_client.asyncio.sleep", new=AsyncMock()):
            await client.delta_push("1.2.3.4", "add")  # must not raise

        # 4 attempts: initial + 3 retries
        assert session.patch.call_count == 4

    @pytest.mark.asyncio
    async def test_no_auth_when_username_empty(self):
        # Lines 106, 116-117: when username is empty, auth kwarg is not set.
        # Sending a null auth header would cause F5 to reject the request with 401.
        resp = _make_response(200)
        session = _make_session(resp)
        client = F5Client(_make_config(username=""), session)
        await client.delta_push("1.2.3.4", "add")
        call_kwargs = session.patch.call_args.kwargs
        assert "auth" not in call_kwargs

    @pytest.mark.asyncio
    async def test_full_sync_outer_exception_handler_triggered(self):
        # Lines 79-80: if _patch_data_group itself raises (bypassing its internal guards),
        # full_sync catches it and logs an exception. This guards against future code changes
        # that remove the internal try/except from _patch_data_group.
        from unittest.mock import AsyncMock
        session = MagicMock()
        client = F5Client(_make_config(), session)
        client._patch_data_group = AsyncMock(side_effect=RuntimeError("unexpected"))
        await client.full_sync()  # must not raise

    @pytest.mark.asyncio
    async def test_delta_push_outer_exception_handler_triggered(self):
        # Lines 92-93: if _patch_data_group raises unexpectedly, delta_push catches it
        # and logs an exception. Ensures a single bad IP push never aborts the export pipeline.
        from unittest.mock import AsyncMock
        session = MagicMock()
        client = F5Client(_make_config(), session)
        client._patch_data_group = AsyncMock(side_effect=RuntimeError("unexpected"))
        await client.delta_push("1.2.3.4", "add")  # must not raise
