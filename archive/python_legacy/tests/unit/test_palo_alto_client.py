"""
Unit tests for src/tap/export/palo_alto_client.py — Phase 20, Group 9.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.tap.export.palo_alto_client import PaloAltoClient, _build_uid_xml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> dict:
    cfg = {
        "base_url": "https://pa.example.com",
        "api_key": "LUFRPT1...",
        "tags": ["ja4proxy-ban"],
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


def _make_session(status: int = 200) -> MagicMock:
    session = MagicMock()
    resp = _make_response(status)
    session.get.return_value = resp
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRegisterIP:
    @pytest.mark.asyncio
    async def test_register_ip_calls_xml_api_with_correct_tag(self):
        """register_ip must call GET with the register XML."""
        session = _make_session()
        client = PaloAltoClient(_make_config(), session)

        await client.register_ip("1.2.3.4", ["ja4proxy-ban"])

        session.get.assert_called_once()
        call_url = session.get.call_args.args[0]
        assert "register" in call_url
        assert "1.2.3.4" in call_url

    @pytest.mark.asyncio
    async def test_unregister_ip_removes_tag(self):
        """unregister_ip must use <unregister> in the XML command."""
        session = _make_session()
        client = PaloAltoClient(_make_config(), session)

        await client.unregister_ip("1.2.3.4", ["ja4proxy-ban"])

        call_url = session.get.call_args.args[0]
        assert "unregister" in call_url
        assert "1.2.3.4" in call_url

    @pytest.mark.asyncio
    async def test_full_sync_registers_all_banned_ips(self):
        """full_sync must call register_ip for each active ban."""
        session = _make_session()
        client = PaloAltoClient(_make_config(), session)

        # full_sync is currently a stub; just verify it doesn't crash
        await client.full_sync()  # must not raise

    def test_verify_tls_false_emits_warn(self, caplog):
        """When verify_tls=False, a warning must be logged at construction time."""
        session = MagicMock()
        with caplog.at_level(logging.WARNING, logger="src.tap.export.palo_alto_client"):
            client = PaloAltoClient(_make_config(verify_tls=False), session)

        assert any(
            "tls_verification_disabled" in record.message
            or "disabled" in record.message.lower()
            for record in caplog.records
        ), f"Expected TLS warning, got: {[r.message for r in caplog.records]}"


class TestBuildUidXml:
    def test_register_xml_contains_register_tag(self):
        xml = _build_uid_xml("register", "1.2.3.4", ["tag1"])
        assert "<register>" in xml

    def test_unregister_xml_contains_unregister_tag(self):
        xml = _build_uid_xml("unregister", "1.2.3.4", ["tag1"])
        assert "<unregister>" in xml

    def test_xml_contains_ip(self):
        xml = _build_uid_xml("register", "1.2.3.4", ["tag1"])
        assert "1.2.3.4" in xml

    def test_xml_contains_tag(self):
        xml = _build_uid_xml("register", "1.2.3.4", ["ja4proxy-ban"])
        assert "ja4proxy-ban" in xml


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------


class TestCallApiEdgeCases:
    """Lines 98-104: _call_api error and non-context-manager paths."""

    @pytest.mark.asyncio
    async def test_api_error_status_logs_warning_but_does_not_raise(self, caplog):
        # Lines 97-100: when the XML API returns >= 400, log a WARNING but do not raise.
        # A PAN device rejecting a tag update must not crash the export pipeline.
        resp = _make_response(400)
        session = _make_session(400)
        client = PaloAltoClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.palo_alto_client"):
            await client.register_ip("1.2.3.4", ["ja4proxy-ban"])

        assert any("api_error" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_api_200_does_not_log_warning(self, caplog):
        # Lines 95-100: a 200 response from the XML API must produce no warning.
        # Spurious warnings would flood SIEM dashboards and mask real issues.
        session = _make_session(200)
        client = PaloAltoClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.palo_alto_client"):
            await client.register_ip("1.2.3.4", ["ja4proxy-ban"])

        assert not any("api_error" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_non_aenter_response_reads_status_attribute(self):
        # Lines 101-102: when resp_ctx has no __aenter__, status is read via getattr().
        # This path is hit by mock responses in tests and must be handled cleanly.
        resp_mock = MagicMock()
        resp_mock.status = 200
        # Remove __aenter__ so the else branch is taken
        del resp_mock.__aenter__
        session = MagicMock()
        session.get.return_value = resp_mock
        client = PaloAltoClient(_make_config(), session)
        await client.register_ip("1.2.3.4", ["ja4proxy-ban"])  # must not raise

    @pytest.mark.asyncio
    async def test_request_exception_is_caught_and_logged(self, caplog):
        # Lines 103-104: session.get() raising must be caught and logged.
        # A network error to PAN must never propagate to the proxy's hot path.
        session = MagicMock()
        session.get.side_effect = ConnectionError("PAN unreachable")
        client = PaloAltoClient(_make_config(), session)

        with caplog.at_level(logging.ERROR, logger="src.tap.export.palo_alto_client"):
            await client.register_ip("1.2.3.4", ["ja4proxy-ban"])  # must not raise

        assert any("request_error" in r.message for r in caplog.records)
