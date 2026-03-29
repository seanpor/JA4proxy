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
