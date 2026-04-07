"""Integration tests for XSOAR and Splunk SOAR connectors.

Tests that each command/action:
  - Sends the correct HTTP method and path
  - Sends the correct Authorization header
  - Sends the correct request body fields
  - Raises on non-2xx responses

These tests use the SOARMock server (tests/mocks/soar_mock.py) which is a real
aiohttp HTTP server bound on 127.0.0.1 on a random port.

Tested modules:
  integrations/xsoar/JA4proxy/commands.py        — 8 XSOAR commands
  integrations/splunk-soar/ja4proxy/connector.py — 8 Splunk SOAR actions
"""

from __future__ import annotations

import asyncio
import pytest
import pytest_asyncio

from tests.mocks.soar_mock import SOARMock, soar_mock_server


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def soar_mock():
    """Start the SOAR mock server and yield (base_url, token, mock)."""
    async with soar_mock_server(token="test-operator-token") as (base_url, token, mock):
        yield base_url, token, mock


# ---------------------------------------------------------------------------
# Helper: import connectors lazily so missing files cause ImportError at test
# collection (not at module import time), yielding a FAILED rather than ERROR.
# ---------------------------------------------------------------------------


def _import_xsoar():
    """Import the XSOAR connector module. Raises ImportError if not present."""
    from integrations.xsoar.JA4proxy import commands as xsoar_commands  # type: ignore[import]
    return xsoar_commands


def _import_splunk():
    """Import the Splunk SOAR connector module. Raises ImportError if not present."""
    from integrations.splunk_soar.ja4proxy import connector as splunk_connector  # type: ignore[import]
    return splunk_connector


# ===========================================================================
# XSOAR connector tests (8 commands)
# ===========================================================================


class TestXSOARBanIP:
    """ja4proxy-ban-ip command."""

    @pytest.mark.asyncio
    async def test_xsoar_ban_ip_sends_correct_request(self, soar_mock):
        """POST /api/v1/bans with correct body and auth header."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        await commands.ban_ip(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            ttl_seconds=3600,
            reason="test",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/bans"
        assert req["headers"].get("Authorization") == f"Bearer {token}"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("ttl_seconds") == 3600
        assert req["body"].get("reason") == "test"

    @pytest.mark.asyncio
    async def test_xsoar_ban_ip_raises_on_error_status(self, soar_mock):
        """Non-2xx responses are raised as exceptions."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()
        mock.set_error("POST", "/api/v1/bans", status=500)

        with pytest.raises(Exception):
            await commands.ban_ip(
                base_url=base_url,
                token=token,
                ip="1.2.3.4",
                ttl_seconds=3600,
                reason="test",
            )


class TestXSOARReleaseBan:
    """ja4proxy-release-ban command."""

    @pytest.mark.asyncio
    async def test_xsoar_release_ban_sends_delete(self, soar_mock):
        """DELETE /api/v1/bans/{ip}."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        await commands.release_ban(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "DELETE"
        assert req["path"] == "/api/v1/bans/1.2.3.4"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestXSOARGetConnectionHistory:
    """ja4proxy-get-connection-history command."""

    @pytest.mark.asyncio
    async def test_xsoar_get_connection_history(self, soar_mock):
        """GET /api/v1/connections?ip=1.2.3.4&days=7."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        await commands.get_connection_history(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            days=7,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == "/api/v1/connections"
        assert req["query"].get("ip") == "1.2.3.4"
        assert req["query"].get("days") in ("7", 7), (
            f"Expected query param days=7, got {req['query'].get('days')!r}"
        )
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestXSOARGetFingerprintDetail:
    """ja4proxy-get-fingerprint-detail command."""

    @pytest.mark.asyncio
    async def test_xsoar_get_fingerprint_detail(self, soar_mock):
        """GET /api/v1/fingerprints/{ja4}."""
        base_url, token, mock = soar_mock
        ja4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        commands = _import_xsoar()

        await commands.get_fingerprint_detail(
            base_url=base_url,
            token=token,
            ja4=ja4,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == f"/api/v1/fingerprints/{ja4}"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestXSOARAddToWatchlist:
    """ja4proxy-add-to-watchlist command."""

    @pytest.mark.asyncio
    async def test_xsoar_add_to_watchlist(self, soar_mock):
        """POST /api/v1/watchlist with ip and reason."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        await commands.add_to_watchlist(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            reason="suspicious beaconing",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/watchlist"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("reason") == "suspicious beaconing"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestXSOARGetHealth:
    """ja4proxy-get-health command."""

    @pytest.mark.asyncio
    async def test_xsoar_get_health(self, soar_mock):
        """GET /api/v1/health/deep; response includes status field."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        result = await commands.get_health(
            base_url=base_url,
            token=token,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == "/api/v1/health/deep"
        assert req["headers"].get("Authorization") == f"Bearer {token}"
        # The returned value must contain a "status" field
        assert "status" in result, (
            f"Expected 'status' key in health response, got: {result!r}"
        )


class TestXSOARAddToAllowlist:
    """ja4proxy-add-to-allowlist command."""

    @pytest.mark.asyncio
    async def test_xsoar_add_to_allowlist(self, soar_mock):
        """POST /api/v1/allowlist with ip and ttl_seconds."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        await commands.add_to_allowlist(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            ttl_seconds=86400,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/allowlist"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("ttl_seconds") == 86400
        assert req["headers"].get("Authorization") == f"Bearer {token}"

    @pytest.mark.asyncio
    async def test_xsoar_add_to_allowlist_rejects_no_expiry(self, soar_mock):
        """ttl_seconds=0 must be rejected — allowlist requires a mandatory expiry."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        with pytest.raises(ValueError, match=r"ttl_seconds|expiry|indefinite"):
            await commands.add_to_allowlist(
                base_url=base_url,
                token=token,
                ip="1.2.3.4",
                ttl_seconds=0,
            )


class TestXSOARGetDial:
    """ja4proxy-get-dial command."""

    @pytest.mark.asyncio
    async def test_xsoar_get_dial(self, soar_mock):
        """GET /api/v1/dial returns current dial setting."""
        base_url, token, mock = soar_mock
        commands = _import_xsoar()

        result = await commands.get_dial(
            base_url=base_url,
            token=token,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == "/api/v1/dial"
        assert req["headers"].get("Authorization") == f"Bearer {token}"
        assert "dial" in result, (
            f"Expected 'dial' key in response, got: {result!r}"
        )


class TestXSOARAuthError:
    """XSOAR connector error handling."""

    @pytest.mark.asyncio
    async def test_xsoar_returns_401_on_bad_token(self, soar_mock):
        """Wrong token raises an auth-related exception."""
        base_url, _, mock = soar_mock
        commands = _import_xsoar()

        with pytest.raises(Exception) as exc_info:
            await commands.ban_ip(
                base_url=base_url,
                token="wrong-token",
                ip="1.2.3.4",
                ttl_seconds=3600,
                reason="test",
            )

        # The exception must communicate the 401 status
        err_str = str(exc_info.value).lower()
        assert "401" in err_str or "auth" in err_str or "unauthorized" in err_str, (
            f"Expected auth-related error, got: {exc_info.value!r}"
        )


# ===========================================================================
# Splunk SOAR connector tests (8 actions)
# ===========================================================================


class TestSplunkBlockIP:
    """block_ip action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_block_ip(self, soar_mock):
        """POST /api/v1/bans with correct body."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.block_ip(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            ttl_seconds=3600,
            reason="high risk score",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/bans"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("ttl_seconds") == 3600
        assert req["body"].get("reason") == "high risk score"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkUnblockIP:
    """unblock_ip action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_unblock_ip(self, soar_mock):
        """DELETE /api/v1/bans/{ip}."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.unblock_ip(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "DELETE"
        assert req["path"] == "/api/v1/bans/1.2.3.4"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkGetConnectionHistory:
    """get_connection_history action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_get_connection_history(self, soar_mock):
        """GET /api/v1/connections?ip={ip}&days={days}."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.get_connection_history(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            days=30,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == "/api/v1/connections"
        assert req["query"].get("ip") == "1.2.3.4"
        assert req["query"].get("days") in ("30", 30)
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkGetFingerprintHistory:
    """get_fingerprint_history action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_get_fingerprint_history(self, soar_mock):
        """GET /api/v1/fingerprints/{ja4}."""
        base_url, token, mock = soar_mock
        ja4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        connector = _import_splunk()

        await connector.get_fingerprint_history(
            base_url=base_url,
            token=token,
            ja4_fingerprint=ja4,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == f"/api/v1/fingerprints/{ja4}"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkAddToWatchlist:
    """add_to_watchlist action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_add_to_watchlist(self, soar_mock):
        """POST /api/v1/watchlist with ip and reason."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.add_to_watchlist(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            reason="IOC from threat intel",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/watchlist"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("reason") == "IOC from threat intel"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkAddToAllowlist:
    """add_to_allowlist action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_add_to_allowlist(self, soar_mock):
        """POST /api/v1/allowlist with ip and ttl_seconds."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.add_to_allowlist(
            base_url=base_url,
            token=token,
            ip="1.2.3.4",
            ttl_seconds=86400,
            reason="FP confirmed",
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "POST"
        assert req["path"] == "/api/v1/allowlist"
        assert req["body"].get("ip") == "1.2.3.4"
        assert req["body"].get("ttl_seconds") == 86400
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkRemoveFromAllowlist:
    """remove_from_allowlist action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_remove_from_allowlist(self, soar_mock):
        """DELETE /api/v1/allowlist/{id}."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()
        entry_id = "allowlist-entry-abc123"

        await connector.remove_from_allowlist(
            base_url=base_url,
            token=token,
            entry_id=entry_id,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "DELETE"
        assert req["path"] == f"/api/v1/allowlist/{entry_id}"
        assert req["headers"].get("Authorization") == f"Bearer {token}"


class TestSplunkGetHealth:
    """get_health action."""

    @pytest.mark.asyncio
    async def test_splunk_soar_get_health(self, soar_mock):
        """GET /api/v1/health/deep."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        result = await connector.get_health(
            base_url=base_url,
            token=token,
        )

        req = mock.last_request()
        assert req is not None, "No request was recorded"
        assert req["method"] == "GET"
        assert req["path"] == "/api/v1/health/deep"
        assert req["headers"].get("Authorization") == f"Bearer {token}"
        assert "status" in result, (
            f"Expected 'status' key in health response, got: {result!r}"
        )


class TestSplunkErrorHandling:
    """Splunk SOAR connector error paths."""

    @pytest.mark.asyncio
    async def test_splunk_soar_raises_on_500(self, soar_mock):
        """block_ip raises JA4proxySoarError on server error."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()
        mock.set_error("POST", "/api/v1/bans", 500)

        with pytest.raises(connector.JA4proxySoarError):
            await connector.block_ip(
                base_url=base_url,
                token=token,
                ip="1.2.3.4",
                ttl_seconds=3600,
                reason="test",
            )

    @pytest.mark.asyncio
    async def test_splunk_soar_raises_auth_error_on_401(self, soar_mock):
        """Wrong token raises AuthError — not a generic JA4proxySoarError."""
        base_url, _, mock = soar_mock
        connector = _import_splunk()

        with pytest.raises(connector.AuthError):
            await connector.block_ip(
                base_url=base_url,
                token="wrong-token",
                ip="1.2.3.4",
                ttl_seconds=3600,
                reason="test",
            )

    @pytest.mark.asyncio
    async def test_splunk_soar_get_fingerprint_history_passes_days(self, soar_mock):
        """days parameter must be forwarded to the API — not silently dropped."""
        base_url, token, mock = soar_mock
        connector = _import_splunk()

        await connector.get_fingerprint_history(
            base_url=base_url,
            token=token,
            ja4_fingerprint="t13d1516h2_aabbccddeeff_aabbccddeeff",
            days=14,
        )

        req = mock.last_request()
        assert req is not None
        assert req["query"].get("days") == "14", (
            f"Expected days=14 in query params, got: {req['query']}"
        )
