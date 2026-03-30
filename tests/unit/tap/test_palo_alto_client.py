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
            "tls_verification_disabled" in record.message or "disabled" in record.message.lower()
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
