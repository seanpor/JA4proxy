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


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------


class TestNoopProducer:
    """Line 28, 38, 41, 46, 49: _NoopProducer stub used when aiokafka is absent."""

    @pytest.mark.asyncio
    async def test_noop_producer_start_does_not_raise(self):
        # Line 38: _NoopProducer.start() is the fallback when aiokafka is not installed.
        # If this stub crashes, every deployment without aiokafka fails at startup.
        from src.tap.export.kafka_producer import _NoopProducer

        noop = _NoopProducer()
        await noop.start()  # must not raise

    @pytest.mark.asyncio
    async def test_noop_producer_stop_does_not_raise(self):
        # Line 41: _NoopProducer.stop() must be safe — called during shutdown.
        from src.tap.export.kafka_producer import _NoopProducer

        noop = _NoopProducer()
        await noop.stop()  # must not raise

    @pytest.mark.asyncio
    async def test_noop_producer_send_and_wait_does_not_raise(self):
        # Lines 44-46: _NoopProducer.send_and_wait() must silently swallow messages.
        # Without a Kafka broker, messages should be dropped, not cause an exception.
        from src.tap.export.kafka_producer import _NoopProducer

        noop = _NoopProducer()
        await noop.send_and_wait("topic", key=b"k", value=b"v")  # must not raise

    @pytest.mark.asyncio
    async def test_noop_producer_flush_does_not_raise(self):
        # Line 49: _NoopProducer.flush() must be a no-op when aiokafka is absent.
        from src.tap.export.kafka_producer import _NoopProducer

        noop = _NoopProducer()
        await noop.flush()  # must not raise

    def test_noop_producer_is_used_when_aiokafka_unavailable(self):
        # Line 28, 77: When _AIOKAFKA_AVAILABLE is False, _NoopProducer is assigned.
        # This ensures the exporter degrades gracefully in environments without Kafka.
        from src.tap.export import kafka_producer as kp
        from src.tap.export.kafka_producer import _NoopProducer

        original = kp._AIOKAFKA_AVAILABLE
        try:
            kp._AIOKAFKA_AVAILABLE = False
            exporter = KafkaExporter(_make_config())
            assert isinstance(exporter._producer, _NoopProducer)
        finally:
            kp._AIOKAFKA_AVAILABLE = original


class TestStartAndClose:
    """Lines 75, 85-88, 94-104: start/close lifecycle with error handling."""

    @pytest.mark.asyncio
    async def test_start_swallows_broker_connection_error(self):
        # Lines 85-88: start() must catch exceptions and log a warning.
        # A Kafka broker being temporarily unreachable at boot must not crash the proxy.
        exporter, mock_producer = _make_exporter()
        mock_producer.start.side_effect = ConnectionError("broker unreachable")
        await exporter.start()  # must not raise

    @pytest.mark.asyncio
    async def test_close_cancels_linger_task(self):
        # Lines 94-99: close() cancels the pending linger timer before flushing.
        # If the linger task is not cancelled, a dangling task runs after shutdown.
        exporter, mock_producer = _make_exporter(batch_size=100, linger_ms=60000)
        fp = _make_fp()
        await exporter.send_fingerprint(fp)
        # A linger task should have been created
        assert exporter._linger_task is not None
        await exporter.close()
        # After close, the linger task should be done (cancelled or finished)
        assert exporter._linger_task.done()

    @pytest.mark.asyncio
    async def test_close_flushes_remaining_messages(self):
        # Lines 100, 94-104: close() calls flush() to drain the batch before disconnecting.
        # Without flushing, the last batch of security events is silently dropped.
        exporter, mock_producer = _make_exporter(batch_size=100, linger_ms=60000)
        fp = _make_fp()
        await exporter.send_fingerprint(fp)
        await exporter.close()
        # send_and_wait should have been called exactly once for the queued message
        assert mock_producer.send_and_wait.call_count == 1

    @pytest.mark.asyncio
    async def test_close_swallows_stop_exception(self):
        # Lines 101-104: if producer.stop() raises, close() must not propagate it.
        # A crash on shutdown would prevent graceful teardown of other resources.
        exporter, mock_producer = _make_exporter()
        mock_producer.stop.side_effect = RuntimeError("stop failed")
        await exporter.close()  # must not raise


class TestEnqueueAndLingerFlush:
    """Lines 138: _linger_flush cancellation path."""

    @pytest.mark.asyncio
    async def test_linger_flush_cancelled_without_error(self):
        # Line 138: _linger_flush catches CancelledError silently.
        # The linger timer being cancelled on shutdown must not log an unhandled exception.
        exporter, mock_producer = _make_exporter(batch_size=100, linger_ms=5000)
        fp = _make_fp()
        await exporter.send_fingerprint(fp)
        task = exporter._linger_task
        assert task is not None
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected
        # Task should be done with no residual error
        assert task.done()

    @pytest.mark.asyncio
    async def test_existing_linger_task_reused_when_not_done(self):
        # Lines 189-190: a new linger task is only created if the old one is done.
        # Creating a new task on every message would leak tasks and cause double-flushes.
        exporter, mock_producer = _make_exporter(batch_size=100, linger_ms=60000)
        fp = _make_fp()
        await exporter.send_fingerprint(fp)
        task1 = exporter._linger_task
        await exporter.send_fingerprint(fp)
        task2 = exporter._linger_task
        # Same task — not a new one
        assert task1 is task2

    @pytest.mark.asyncio
    async def test_fingerprint_with_none_timestamp_uses_current_time(self):
        # Lines 131-138: when fp.timestamp is None, datetime.now() is used.
        # Without this branch, None timestamps would crash JSON serialization.
        exporter, mock_producer = _make_exporter(batch_size=1)
        fp = _make_fp(timestamp=None)
        fp.timestamp = None
        await exporter.send_fingerprint(fp)
        call_kwargs = mock_producer.send_and_wait.call_args.kwargs
        value = json.loads(call_kwargs["value"].decode())
        assert isinstance(value["timestamp"], str)
        assert len(value["timestamp"]) > 0
