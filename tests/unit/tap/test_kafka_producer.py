"""
Unit tests for src/tap/export/kafka_producer.py — Phase 20, Group 9.
"""
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tap.export.kafka_producer import KafkaExporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    cfg = {
        "brokers": "localhost:9092",
        "fingerprint_topic": "ja4proxy.fingerprints",
        "ban_topic": "ja4proxy.bans",
        "batch_size": 100,
        "linger_ms": 500,
    }
    cfg.update(overrides)
    return cfg


def _make_exporter(**config_overrides) -> tuple[KafkaExporter, MagicMock]:
    """Return (exporter, mock_producer). The mock_producer is injected as _producer."""
    exporter = KafkaExporter(_make_config(**config_overrides))
    mock_producer = AsyncMock()
    mock_producer.start = AsyncMock()
    mock_producer.stop = AsyncMock()
    mock_producer.send_and_wait = AsyncMock()
    mock_producer.flush = AsyncMock()
    exporter._producer = mock_producer
    return exporter, mock_producer


def _make_fp(**kwargs):
    fp = MagicMock()
    fp.conn_id = kwargs.get("conn_id", "conn-1")
    fp.ja4 = kwargs.get("ja4", "t13d1516h2_aabbccddeeff_aabbccddeeff")
    fp.client_ip = kwargs.get("client_ip", "1.2.3.4")
    fp.risk_score = kwargs.get("risk_score", 0)
    fp.action = kwargs.get("action", "observe")
    fp.timestamp = kwargs.get("timestamp", datetime.now(timezone.utc))
    return fp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFingerprintMessage:
    @pytest.mark.asyncio
    async def test_fingerprint_message_schema_v1_valid(self):
        """send_fingerprint must produce a message with schema_version=1 and event=fingerprint."""
        exporter, mock_producer = _make_exporter(batch_size=1)
        fp = _make_fp()

        await exporter.send_fingerprint(fp)

        mock_producer.send_and_wait.assert_called_once()
        call_kwargs = mock_producer.send_and_wait.call_args.kwargs
        value = json.loads(call_kwargs["value"].decode())
        assert value["schema_version"] == 1
        assert value["event"] == "fingerprint"

    @pytest.mark.asyncio
    async def test_message_key_is_client_ip(self):
        """The Kafka message key must equal client_ip encoded as UTF-8 bytes."""
        exporter, mock_producer = _make_exporter(batch_size=1)
        fp = _make_fp(client_ip="10.0.0.1")

        await exporter.send_fingerprint(fp)

        call_kwargs = mock_producer.send_and_wait.call_args.kwargs
        assert call_kwargs["key"] == b"10.0.0.1"


class TestBanMessage:
    @pytest.mark.asyncio
    async def test_ban_event_message_schema_valid(self):
        """send_ban must produce a message with schema_version=1 and event=ban."""
        exporter, mock_producer = _make_exporter(batch_size=1)

        await exporter.send_ban("ban", "1.2.3.4", 85, 3600, "high_score")

        mock_producer.send_and_wait.assert_called_once()
        call_kwargs = mock_producer.send_and_wait.call_args.kwargs
        value = json.loads(call_kwargs["value"].decode())
        assert value["schema_version"] == 1
        assert value["event"] == "ban"

    @pytest.mark.asyncio
    async def test_ban_message_key_is_ip(self):
        """The Kafka ban message key must equal ip encoded as UTF-8 bytes."""
        exporter, mock_producer = _make_exporter(batch_size=1)

        await exporter.send_ban("ban", "1.2.3.4", 85, 3600, "high_score")

        call_kwargs = mock_producer.send_and_wait.call_args.kwargs
        assert call_kwargs["key"] == b"1.2.3.4"


class TestBatching:
    @pytest.mark.asyncio
    async def test_batch_flushed_when_batch_size_reached(self):
        """Batch should flush when batch_size messages have been enqueued."""
        exporter, mock_producer = _make_exporter(batch_size=3, linger_ms=60000)
        fp = _make_fp()

        # Cancel any linger task to prevent interference
        if exporter._linger_task is not None:
            exporter._linger_task.cancel()

        for _ in range(3):
            await exporter.send_fingerprint(fp)

        # After 3 messages with batch_size=3, flush should have been called
        assert mock_producer.send_and_wait.call_count == 3

    @pytest.mark.asyncio
    async def test_batch_flushed_after_linger_ms(self):
        """Batch should be flushed after linger_ms milliseconds."""
        exporter, mock_producer = _make_exporter(batch_size=100, linger_ms=50)
        fp = _make_fp()

        await exporter.send_fingerprint(fp)

        # Wait longer than linger_ms
        await asyncio.sleep(0.15)

        assert mock_producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_broker_unavailable_logs_warn_not_crash(self):
        """When broker is unavailable (send_and_wait raises), no crash should occur."""
        exporter, mock_producer = _make_exporter(batch_size=1)
        mock_producer.send_and_wait.side_effect = ConnectionError("broker unavailable")
        fp = _make_fp()

        # Must not raise
        await exporter.send_fingerprint(fp)
