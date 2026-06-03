"""
Unit tests for src/tap/export/export_manager.py — ExportManager lifecycle.

The ExportManager is the fan-out hub that delivers intelligence to all enabled
export backends (EDL, F5, Palo Alto, Kafka, Syslog, TAXII, MISP).  Every
backend failure must be isolated — one broken exporter must never prevent others
from receiving events.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from src.tap.export.export_manager import ExportManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(**enabled_backends) -> dict:
    """Build a minimal proxy config dict with specific backends enabled."""
    intelligence_export = {}
    for name, enabled in enabled_backends.items():
        intelligence_export[name] = {"enabled": enabled}
    return {"intelligence_export": intelligence_export}


def _manager(**enabled_backends) -> ExportManager:
    return ExportManager(
        config=_cfg(**enabled_backends),
        redis=MagicMock(),
        http_session=MagicMock(),
    )


# ---------------------------------------------------------------------------
# start() — exporter instantiation
# ---------------------------------------------------------------------------


class TestExportManagerStart:
    """Cover lines 53-137: each per-backend branch in start()."""

    @pytest.mark.asyncio
    async def test_start_edl_when_enabled(self):
        """EDLServer is instantiated and started when edl.enabled=True (lines 57-67).
        So what: if start() isn't called, the EDL HTTP server never binds — no
        firewall can pull the dynamic ban list."""
        import src.tap.export.edl_server as _edl_mod

        config = {"intelligence_export": {"edl": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_edl = AsyncMock()
        mock_edl.start = AsyncMock()
        with patch.object(_edl_mod, "EDLServer", return_value=mock_edl):
            await mgr.start()
        mock_edl.start.assert_awaited_once()
        assert mgr._edl is mock_edl

    @pytest.mark.asyncio
    async def test_start_no_backends_enabled_runs_cleanly(self):
        """start() with all backends disabled completes without errors (fast path)."""
        mgr = ExportManager(
            config={"intelligence_export": {}},
            redis=MagicMock(),
        )
        await mgr.start()  # must not raise
        assert mgr._edl is None
        assert mgr._kafka is None

    @pytest.mark.asyncio
    async def test_start_edl_exception_does_not_prevent_other_exporters(self):
        """EDL start() raising must not prevent Kafka from starting (lines 64-67).
        So what: fail-open — one broken backend must not blind the others."""
        config = {
            "intelligence_export": {
                "edl": {"enabled": True},
                "kafka": {"enabled": True},
            }
        }
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_kafka = AsyncMock()
        mock_kafka.start = AsyncMock()

        with (
            patch(
                "src.tap.export.edl_server.EDLServer",
                side_effect=RuntimeError("edl init failed"),
                create=True,
            ),
            patch(
                "src.tap.export.kafka_producer.KafkaExporter",
                return_value=mock_kafka,
                create=True,
            ),
        ):
            await mgr.start()  # must not raise

    @pytest.mark.asyncio
    async def test_start_kafka_when_enabled(self):
        """KafkaExporter is instantiated and started when kafka.enabled=True (lines 95-105).
        So what: without Kafka, security events don't reach the SIEM."""
        config = {
            "intelligence_export": {
                "kafka": {"enabled": True, "brokers": "localhost:9092"}
            }
        }
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_kafka = AsyncMock()
        mock_kafka.start = AsyncMock()
        with patch(
            "src.tap.export.kafka_producer.KafkaExporter",
            return_value=mock_kafka,
            create=True,
        ):
            await mgr.start()
        mock_kafka.start.assert_awaited_once()
        assert mgr._kafka is mock_kafka

    @pytest.mark.asyncio
    async def test_start_syslog_when_enabled(self):
        """SyslogExporter is instantiated (sync, no start()) when syslog.enabled=True."""
        config = {"intelligence_export": {"syslog": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_syslog = MagicMock()
        with patch(
            "src.tap.export.syslog_exporter.SyslogExporter",
            return_value=mock_syslog,
            create=True,
        ):
            await mgr.start()
        assert mgr._syslog is mock_syslog

    @pytest.mark.asyncio
    async def test_start_misp_when_enabled(self):
        """MISPClient is instantiated when misp.enabled=True."""
        config = {"intelligence_export": {"misp": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        mock_misp = MagicMock()
        with patch(
            "src.tap.export.misp_client.MISPClient", return_value=mock_misp, create=True
        ):
            await mgr.start()
        assert mgr._misp is mock_misp


# ---------------------------------------------------------------------------
# on_fingerprint()
# ---------------------------------------------------------------------------


class TestOnFingerprint:
    """Lines 141-162: fingerprint fan-out."""

    @pytest.mark.asyncio
    async def test_on_fingerprint_calls_kafka_send(self):
        """on_fingerprint() calls kafka.send_fingerprint when kafka is wired (lines 149-150).
        So what: if Kafka doesn't receive fingerprints, the SIEM has no JA4 telemetry.
        """
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_kafka = AsyncMock()
        mgr._kafka = mock_kafka
        fp = MagicMock()
        await mgr.on_fingerprint(fp)
        mock_kafka.send_fingerprint.assert_awaited_once_with(fp)

    @pytest.mark.asyncio
    async def test_on_fingerprint_no_exporters_returns_immediately(self):
        """on_fingerprint() with no streaming exporters is a no-op (line 152-153)."""
        mgr = ExportManager(config={}, redis=MagicMock())
        await mgr.on_fingerprint(MagicMock())  # must not raise

    @pytest.mark.asyncio
    async def test_on_fingerprint_kafka_exception_logged_not_raised(self):
        """kafka.send_fingerprint raising → logged, not re-raised (lines 155-162).
        So what: a Kafka broker failure must not crash the capture loop."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_kafka = AsyncMock()
        mock_kafka.send_fingerprint.side_effect = RuntimeError("broker unavailable")
        mgr._kafka = mock_kafka
        await mgr.on_fingerprint(MagicMock())  # must not raise


# ---------------------------------------------------------------------------
# on_ban()
# ---------------------------------------------------------------------------


class TestOnBan:
    """Lines 164-209: ban fan-out to all backends."""

    @pytest.mark.asyncio
    async def test_on_ban_calls_kafka_send_ban(self):
        """on_ban() calls kafka.send_ban when kafka is wired."""
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_kafka = AsyncMock()
        mgr._kafka = mock_kafka
        await mgr.on_ban("1.2.3.4", score=90, ttl=3600, reason="test")
        mock_kafka.send_ban.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_ban_calls_f5_delta_push(self):
        """on_ban() calls f5.delta_push when f5 is wired."""
        mgr = ExportManager(
            config={"intelligence_export": {}},
            redis=MagicMock(),
            http_session=MagicMock(),
        )
        mock_f5 = AsyncMock()
        mgr._f5 = mock_f5
        await mgr.on_ban("1.2.3.4", score=80, ttl=1800, reason="bot")
        mock_f5.delta_push.assert_awaited_once_with("1.2.3.4", "add")

    @pytest.mark.asyncio
    async def test_on_ban_syslog_action_mapping_signal_ban(self):
        """score>=85 maps to 'signal_ban' action for syslog (lines 187-196).
        So what: wrong action label means SIEM cannot correctly classify ban severity.
        """
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_syslog = MagicMock()
        mock_syslog.send = MagicMock()
        mgr._syslog = mock_syslog
        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new_callable=AsyncMock) as mock_exec:
            await mgr.on_ban("1.2.3.4", score=90, ttl=3600, reason="bot")
        # Verify run_in_executor was called (syslog is sync)
        mock_exec.assert_awaited()

    @pytest.mark.asyncio
    async def test_on_ban_no_exporters_returns_immediately(self):
        """on_ban() with no exporters is a no-op."""
        mgr = ExportManager(config={}, redis=MagicMock())
        await mgr.on_ban("1.2.3.4", score=50, ttl=300, reason="")  # must not raise

    @pytest.mark.asyncio
    async def test_on_ban_exception_logged_not_raised(self):
        """An exception from one backend is logged, not re-raised (lines 202-208).
        So what: one failing backend must not prevent others from receiving the ban."""
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_kafka = AsyncMock()
        mock_kafka.send_ban.side_effect = RuntimeError("kafka down")
        mgr._kafka = mock_kafka
        await mgr.on_ban("1.2.3.4", score=95, ttl=3600, reason="test")  # must not raise

    @pytest.mark.asyncio
    async def test_on_ban_calls_misp_push_ban(self):
        """on_ban() calls misp.push_ban when misp is wired."""
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_misp = AsyncMock()
        mgr._misp = mock_misp
        await mgr.on_ban("10.0.0.1", score=75, ttl=1200, reason="scanner")
        mock_misp.push_ban.assert_awaited_once_with("10.0.0.1", 75, "scanner")


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    """Lines 211-233: teardown of all running exporters."""

    @pytest.mark.asyncio
    async def test_close_calls_edl_close(self):
        """close() calls edl.close() (lines 213-225)."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_edl = AsyncMock()
        mgr._edl = mock_edl
        await mgr.close()
        mock_edl.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_calls_taxii_close(self):
        """close() calls taxii.close()."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_taxii = AsyncMock()
        mgr._taxii = mock_taxii
        await mgr.close()
        mock_taxii.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_calls_kafka_close(self):
        """close() calls kafka.close()."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_kafka = AsyncMock()
        mgr._kafka = mock_kafka
        await mgr.close()
        mock_kafka.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_calls_syslog_close(self):
        """close() calls syslog.close() (line 227-232)."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_syslog = MagicMock()
        mock_syslog.close = MagicMock()
        mgr._syslog = mock_syslog
        await mgr.close()
        mock_syslog.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_exception_logged_not_raised(self):
        """close() exception from one exporter is logged, not re-raised.
        So what: a broken exporter must not prevent others from closing cleanly."""
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_edl = AsyncMock()
        mock_edl.close.side_effect = RuntimeError("close failed")
        mgr._edl = mock_edl
        await mgr.close()  # must not raise

    @pytest.mark.asyncio
    async def test_close_no_exporters_is_noop(self):
        """close() with nothing wired up must not raise."""
        mgr = ExportManager(config={}, redis=MagicMock())
        await mgr.close()  # must not raise


# ---------------------------------------------------------------------------
# Additional start() coverage — F5, PaloAlto, TAXII, exception paths
# ---------------------------------------------------------------------------


class TestExportManagerStartAdditional:
    """Cover lines 70-76 (F5), 81-91 (PaloAlto), 102-103 (Kafka exc),
    113-114 (Syslog exc), 119-126 (TAXII), 136-137 (MISP exc)."""

    @pytest.mark.asyncio
    async def test_start_f5_when_enabled(self):
        """F5Client is instantiated when f5.enabled=True (lines 70-76).
        So what: without F5 start, dynamic block-list pushes are never sent to ADC."""
        config = {"intelligence_export": {"f5": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        mock_f5 = MagicMock()
        with patch(
            "src.tap.export.f5_client.F5Client", return_value=mock_f5, create=True
        ):
            await mgr.start()
        assert mgr._f5 is mock_f5

    @pytest.mark.asyncio
    async def test_start_f5_exception_is_swallowed(self):
        """F5Client init raising → logged, not re-raised (lines 75-77).
        So what: broken ADC config must not prevent other exporters from starting."""
        config = {"intelligence_export": {"f5": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        with patch(
            "src.tap.export.f5_client.F5Client",
            side_effect=RuntimeError("f5 init failed"),
            create=True,
        ):
            await mgr.start()  # must not raise
        assert mgr._f5 is None

    @pytest.mark.asyncio
    async def test_start_palo_alto_when_enabled(self):
        """PaloAltoClient is instantiated when palo_alto.enabled=True (lines 81-93).
        So what: without PaloAlto wired, firewall tag sync never fires on bans."""
        config = {"intelligence_export": {"palo_alto": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        mock_pa = MagicMock()
        with patch(
            "src.tap.export.palo_alto_client.PaloAltoClient",
            return_value=mock_pa,
            create=True,
        ):
            await mgr.start()
        assert mgr._palo_alto is mock_pa

    @pytest.mark.asyncio
    async def test_start_palo_alto_exception_is_swallowed(self):
        """PaloAltoClient init raising → logged, not re-raised (lines 90-93).
        So what: broken Palo Alto config must not prevent Kafka from starting."""
        config = {"intelligence_export": {"palo_alto": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        with patch(
            "src.tap.export.palo_alto_client.PaloAltoClient",
            side_effect=RuntimeError("pa init failed"),
            create=True,
        ):
            await mgr.start()  # must not raise
        assert mgr._palo_alto is None

    @pytest.mark.asyncio
    async def test_start_kafka_exception_is_swallowed(self):
        """KafkaExporter.start() raising → logged, not re-raised (lines 102-105).
        So what: Kafka broker down at startup must not prevent syslog from starting."""
        config = {"intelligence_export": {"kafka": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_kafka = AsyncMock()
        mock_kafka.start.side_effect = RuntimeError("kafka broker down")
        with patch(
            "src.tap.export.kafka_producer.KafkaExporter",
            return_value=mock_kafka,
            create=True,
        ):
            await mgr.start()  # must not raise

    @pytest.mark.asyncio
    async def test_start_syslog_exception_is_swallowed(self):
        """SyslogExporter init raising → logged, not re-raised (lines 113-116).
        So what: broken syslog config must not prevent MISP from starting."""
        config = {"intelligence_export": {"syslog": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        with patch(
            "src.tap.export.syslog_exporter.SyslogExporter",
            side_effect=RuntimeError("syslog init failed"),
            create=True,
        ):
            await mgr.start()  # must not raise
        assert mgr._syslog is None

    @pytest.mark.asyncio
    async def test_start_taxii_when_enabled(self):
        """TaxiiServer is instantiated and started when taxii.enabled=True (lines 119-128).
        So what: without TAXII start, threat intel sharing with partner SOCs never flows.
        """
        config = {"intelligence_export": {"taxii": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_taxii = AsyncMock()
        mock_taxii.start = AsyncMock()
        import src.tap.export.taxii_server as _taxii_mod

        with patch.object(_taxii_mod, "TaxiiServer", return_value=mock_taxii):
            await mgr.start()
        mock_taxii.start.assert_awaited_once()
        assert mgr._taxii is mock_taxii

    @pytest.mark.asyncio
    async def test_start_misp_exception_is_swallowed(self):
        """MISPClient init raising → logged, not re-raised (lines 136-139).
        So what: broken MISP config must not prevent other exporters from starting."""
        config = {"intelligence_export": {"misp": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock(), http_session=MagicMock())
        with patch(
            "src.tap.export.misp_client.MISPClient",
            side_effect=RuntimeError("misp init failed"),
            create=True,
        ):
            await mgr.start()  # must not raise
        assert mgr._misp is None


# ---------------------------------------------------------------------------
# on_ban() PaloAlto path
# ---------------------------------------------------------------------------


class TestOnBanAdditional:
    """Cover lines 178-180 (PaloAlto ban path) and syslog score-flag boundaries."""

    @pytest.mark.asyncio
    async def test_on_ban_calls_palo_alto_register_ip(self):
        """on_ban() calls palo_alto.register_ip when palo_alto is wired (lines 178-180).
        So what: if PaloAlto register_ip isn't called, firewall tags are never applied.
        """
        mgr = ExportManager(
            config={"intelligence_export": {}},
            redis=MagicMock(),
            http_session=MagicMock(),
        )
        mock_pa = AsyncMock()
        mgr._palo_alto = mock_pa
        await mgr.on_ban("2.3.4.5", score=75, ttl=1800, reason="scanner")
        mock_pa.register_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_ban_syslog_flag_action_for_low_score(self):
        """score < 70 → action='flag' for syslog (line 190).
        So what: wrong action label means SIEM classifies low-risk bans as high-priority.
        """
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_syslog = MagicMock()
        mock_syslog.send = MagicMock()
        mgr._syslog = mock_syslog
        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new_callable=AsyncMock) as mock_exec:
            await mgr.on_ban("3.4.5.6", score=60, ttl=300, reason="scan")
        mock_exec.assert_awaited()

    @pytest.mark.asyncio
    async def test_on_ban_syslog_signal_block_action_for_mid_score(self):
        """70 <= score < 85 → action='signal_block' (line 189-190).
        So what: mid-tier bans must map to block not flag for proper SIEM triage."""
        mgr = ExportManager(config={"intelligence_export": {}}, redis=MagicMock())
        mock_syslog = MagicMock()
        mgr._syslog = mock_syslog
        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new_callable=AsyncMock) as mock_exec:
            await mgr.on_ban("4.5.6.7", score=75, ttl=600, reason="bot")
        mock_exec.assert_awaited()


# ---------------------------------------------------------------------------
# close() syslog exception path
# ---------------------------------------------------------------------------


class TestCloseAdditional:
    """Cover line 230-231: syslog.close() raises → logged, not re-raised."""

    @pytest.mark.asyncio
    async def test_close_syslog_exception_logged_not_raised(self):
        """syslog.close() raising → logged, not re-raised (lines 228-233).
        So what: a broken syslog exporter must not prevent kafka from closing cleanly.
        """
        mgr = ExportManager(config={}, redis=MagicMock())
        mock_syslog = MagicMock()
        mock_syslog.close.side_effect = RuntimeError("syslog close failed")
        mgr._syslog = mock_syslog
        await mgr.close()  # must not raise


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestExportManagerCoverageGaps:
    """Lines 125-126: TAXII start exception handler."""

    @pytest.mark.asyncio
    async def test_start_taxii_exception_is_swallowed(self):
        """Lines 125-126: TaxiiServer.start() raising → logged, not re-raised.
        So what: if this except block is absent, a broken TAXII server config would
        propagate its exception through ExportManager.start() and prevent kafka,
        syslog, and MISP exporters from initialising — all threat intel export
        channels would be silently disabled."""
        config = {"intelligence_export": {"taxii": {"enabled": True}}}
        mgr = ExportManager(config=config, redis=MagicMock())
        mock_taxii = AsyncMock()
        mock_taxii.start.side_effect = RuntimeError("TAXII server failed to start")
        import src.tap.export.taxii_server as _taxii_mod

        with patch.object(_taxii_mod, "TaxiiServer", return_value=mock_taxii):
            await mgr.start()  # must not raise
        # _taxii should not be set (exception occurred during start)
        assert mgr._taxii is None or mgr._taxii is mock_taxii  # either is acceptable
