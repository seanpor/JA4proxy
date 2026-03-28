"""
KafkaExporter — sends fingerprint and ban events to Kafka topics (Phase 20, Group 9).

Uses ``aiokafka`` if available; falls back to a no-op stub.

Message schema v1:
    Fingerprint: {"schema_version": 1, "event": "fingerprint", "conn_id": ..., "ja4": ...,
                  "client_ip": ..., "timestamp": ..., "risk_score": 0, "action": "observe"}
    Ban:         {"schema_version": 1, "event": "ban", "ip": ..., "score": 0, "ttl": 3600,
                  "reason": ...}

Batching: flush when batch_size reached or after linger_ms milliseconds.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaProducer
    _AIOKAFKA_AVAILABLE = True
except ImportError:
    _AIOKAFKA_AVAILABLE = False
    AIOKafkaProducer = None  # type: ignore[assignment,misc]


class _NoopProducer:
    """Stub producer used when aiokafka is not installed."""

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send_and_wait(self, topic: str, key: bytes = b"", value: bytes = b"") -> None:
        logger.debug("kafka_producer | event=noop | topic=%s", topic)

    async def flush(self) -> None:
        pass


class KafkaExporter:
    """Kafka event exporter with batching and linger timer.

    Config section: ``intelligence_export.kafka``.

    Args:
        config: The ``kafka`` sub-dict from ``intelligence_export``.
    """

    def __init__(self, config: dict) -> None:
        self._brokers: str = config.get("brokers", "localhost:9092")
        self._fp_topic: str = config.get("fingerprint_topic", "ja4proxy.fingerprints")
        self._ban_topic: str = config.get("ban_topic", "ja4proxy.bans")
        self._batch_size: int = int(config.get("batch_size", 100))
        self._linger_ms: int = int(config.get("linger_ms", 500))

        # Internal batch buffer: list of (topic, key, value) tuples
        self._batch: list[tuple[str, bytes, bytes]] = []
        self._batch_lock = asyncio.Lock()
        self._linger_task: Optional[asyncio.Task] = None

        # Producer — can be replaced in tests via _producer attribute
        if _AIOKAFKA_AVAILABLE:
            self._producer: Any = AIOKafkaProducer(bootstrap_servers=self._brokers)
        else:
            self._producer = _NoopProducer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect to the Kafka broker."""
        try:
            await self._producer.start()
        except Exception:
            logger.warning("kafka_producer | event=start_failed | brokers=%s", self._brokers)

    async def close(self) -> None:
        """Flush pending messages and disconnect."""
        if self._linger_task is not None:
            self._linger_task.cancel()
            try:
                await self._linger_task
            except asyncio.CancelledError:
                pass
        await self.flush()
        try:
            await self._producer.stop()
        except Exception:
            logger.warning("kafka_producer | event=stop_failed")

    async def flush(self, timeout: float = 5.0) -> None:
        """Flush the current batch immediately."""
        async with self._batch_lock:
            batch = self._batch[:]
            self._batch.clear()

        for topic, key, value in batch:
            try:
                await self._producer.send_and_wait(topic, key=key, value=value)
            except Exception:
                logger.warning(
                    "kafka_producer | event=send_failed | topic=%s", topic
                )

    # ------------------------------------------------------------------
    # Public send methods
    # ------------------------------------------------------------------

    async def send_fingerprint(self, fp: Any) -> None:
        """Enqueue a fingerprint event message."""
        # Build the message dict
        conn_id = getattr(fp, "conn_id", "") if fp is not None else ""
        ja4 = getattr(fp, "ja4", None) if fp is not None else None
        client_ip = getattr(fp, "client_ip", "") if fp is not None else ""
        risk_score = getattr(fp, "risk_score", 0) if fp is not None else 0
        action = getattr(fp, "action", "observe") if fp is not None else "observe"
        timestamp = getattr(fp, "timestamp", None) if fp is not None else None
        if timestamp is not None:
            ts_str = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
        else:
            ts_str = datetime.now(timezone.utc).isoformat()

        msg: dict = {
            "schema_version": 1,
            "event": "fingerprint",
            "conn_id": conn_id,
            "ja4": ja4,
            "client_ip": client_ip,
            "timestamp": ts_str,
            "risk_score": risk_score,
            "action": action,
        }
        value = json.dumps(msg, separators=(",", ":")).encode()
        key = client_ip.encode() if client_ip else b""
        await self._enqueue(self._fp_topic, key, value)

    async def send_ban(
        self,
        event: str,
        ip: str,
        score: int,
        ttl: int,
        reason: str,
    ) -> None:
        """Enqueue a ban event message."""
        msg: dict = {
            "schema_version": 1,
            "event": "ban",
            "ip": ip,
            "score": score,
            "ttl": ttl,
            "reason": reason,
        }
        value = json.dumps(msg, separators=(",", ":")).encode()
        key = ip.encode() if ip else b""
        await self._enqueue(self._ban_topic, key, value)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _enqueue(self, topic: str, key: bytes, value: bytes) -> None:
        """Add a message to the batch; flush if batch is full."""
        async with self._batch_lock:
            self._batch.append((topic, key, value))
            batch_len = len(self._batch)

        if batch_len >= self._batch_size:
            await self.flush()
        else:
            # Start or reset the linger timer
            if self._linger_task is None or self._linger_task.done():
                self._linger_task = asyncio.create_task(self._linger_flush())

    async def _linger_flush(self) -> None:
        """Wait for linger_ms then flush."""
        try:
            await asyncio.sleep(self._linger_ms / 1000.0)
            await self.flush()
        except asyncio.CancelledError:
            pass
