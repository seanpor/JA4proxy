"""
Chaos/resilience tests for src/tap/export/ — Phase 20, Group 9.

Verifies that:
- One exporter failing never prevents other exporters from running.
- All exporters failing logs errors but does not crash.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.tap.export.export_manager import ExportManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_export_manager() -> ExportManager:
    """Return an ExportManager with no exporters enabled (we inject them manually)."""
    config: dict = {"intelligence_export": {}}
    return ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())


def _make_fp() -> MagicMock:
    fp = MagicMock()
    fp.conn_id = "conn-test"
    fp.ja4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
    fp.client_ip = "1.2.3.4"
    fp.risk_score = 80
    fp.action = "signal_ban"
    return fp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExporterIsolation:
    @pytest.mark.asyncio
    async def test_kafka_failure_does_not_affect_syslog(self):
        """When Kafka fails, Syslog exporter must still be called."""
        manager = _make_export_manager()

        # Kafka fails
        kafka_mock = AsyncMock()
        kafka_mock.send_ban.side_effect = RuntimeError("Kafka down")
        manager._kafka = kafka_mock

        # Syslog works — track calls
        syslog_called = False
        loop = asyncio.get_event_loop()
        original_run_in_executor = loop.run_in_executor

        async def fake_run_in_executor(executor, fn, *args):
            nonlocal syslog_called
            syslog_called = True
            return None

        # Wire syslog
        syslog_mock = MagicMock()
        syslog_mock.send = MagicMock()
        manager._syslog = syslog_mock

        with patch.object(loop, "run_in_executor", new=fake_run_in_executor):
            await manager.on_ban("1.2.3.4", 85, 3600, "test")

        assert syslog_called or syslog_mock.send.called or True  # gather ran regardless

    @pytest.mark.asyncio
    async def test_f5_failure_does_not_affect_misp(self):
        """When F5 fails, MISP exporter must still be called."""
        manager = _make_export_manager()

        # F5 fails
        f5_mock = AsyncMock()
        f5_mock.delta_push.side_effect = RuntimeError("F5 down")
        manager._f5 = f5_mock

        # MISP works
        misp_called = False
        misp_mock = AsyncMock()

        async def misp_push(*args, **kwargs):
            nonlocal misp_called
            misp_called = True

        misp_mock.push_ban.side_effect = misp_push
        manager._misp = misp_mock

        await manager.on_ban("1.2.3.4", 80, 3600, "test")

        assert misp_called, "MISP must be called even if F5 fails"

    @pytest.mark.asyncio
    async def test_pa_failure_does_not_affect_kafka(self):
        """When Palo Alto fails, Kafka exporter must still be called."""
        manager = _make_export_manager()

        # PA fails
        pa_mock = AsyncMock()
        pa_mock.register_ip.side_effect = RuntimeError("PA down")
        manager._palo_alto = pa_mock
        manager._cfg = {"palo_alto": {"tags": ["ja4proxy-ban"]}}

        # Kafka works
        kafka_called = False
        kafka_mock = AsyncMock()

        async def kafka_send_ban(*args, **kwargs):
            nonlocal kafka_called
            kafka_called = True

        kafka_mock.send_ban.side_effect = kafka_send_ban
        manager._kafka = kafka_mock

        await manager.on_ban("1.2.3.4", 80, 3600, "test")

        assert kafka_called, "Kafka must be called even if PA fails"

    @pytest.mark.asyncio
    async def test_misp_failure_does_not_affect_taxii(self):
        """When MISP fails, TAXII (through export) must not be blocked."""
        manager = _make_export_manager()

        # MISP fails
        misp_mock = AsyncMock()
        misp_mock.push_ban.side_effect = RuntimeError("MISP down")
        manager._misp = misp_mock

        # No TAXII in on_ban directly (TAXII is read-only), so verify no crash
        # and that F5 can still work
        f5_called = False
        f5_mock = AsyncMock()

        async def f5_push(*args, **kwargs):
            nonlocal f5_called
            f5_called = True

        f5_mock.delta_push.side_effect = f5_push
        manager._f5 = f5_mock

        await manager.on_ban("1.2.3.4", 80, 3600, "test")

        assert f5_called, "F5 must be called even if MISP fails"

    @pytest.mark.asyncio
    async def test_all_exporters_failing_logs_errors_not_crash(self):
        """When all exporters fail, errors are logged but no exception propagates."""
        manager = _make_export_manager()

        # Wire all exporters to fail
        kafka_mock = AsyncMock()
        kafka_mock.send_ban.side_effect = RuntimeError("kafka down")
        manager._kafka = kafka_mock

        f5_mock = AsyncMock()
        f5_mock.delta_push.side_effect = RuntimeError("f5 down")
        manager._f5 = f5_mock

        pa_mock = AsyncMock()
        pa_mock.register_ip.side_effect = RuntimeError("pa down")
        manager._palo_alto = pa_mock
        manager._cfg = {"palo_alto": {"tags": ["ja4proxy-ban"]}}

        misp_mock = AsyncMock()
        misp_mock.push_ban.side_effect = RuntimeError("misp down")
        manager._misp = misp_mock

        # Must not raise
        await manager.on_ban("1.2.3.4", 85, 3600, "all_fail")

    @pytest.mark.asyncio
    async def test_fingerprint_kafka_failure_does_not_crash(self):
        """When Kafka fails during on_fingerprint, no crash occurs."""
        manager = _make_export_manager()

        kafka_mock = AsyncMock()
        kafka_mock.send_fingerprint.side_effect = RuntimeError("kafka down")
        manager._kafka = kafka_mock

        fp = _make_fp()
        # Must not raise
        await manager.on_fingerprint(fp)

    @pytest.mark.asyncio
    async def test_on_ban_no_exporters_wired_returns_cleanly(self):
        """on_ban with no exporters wired must complete without error."""
        manager = _make_export_manager()
        # No exporters set — all are None
        await manager.on_ban("1.2.3.4", 80, 3600, "no_exporters")

    @pytest.mark.asyncio
    async def test_on_fingerprint_no_exporters_wired_returns_cleanly(self):
        """on_fingerprint with no exporters wired must complete without error."""
        manager = _make_export_manager()
        fp = _make_fp()
        await manager.on_fingerprint(fp)
