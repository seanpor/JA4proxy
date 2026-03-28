"""Unit tests for TAP mode graceful shutdown sequence (Phase 20, Group 10).

These tests verify the conceptual shutdown contract for TapSensor.  Because
TapSensor is a thin stub at this phase, the tests exercise the expected
*ordering* guarantee via a MockTapSensor that tracks which shutdown steps
occurred and in which order.

Shutdown ordering contract:
  1. Capture is stopped first (no new packets enter the pipeline).
  2. Worker tasks are drained before scoring is finalised.
  3. Kafka/export flushes happen before the Redis connection is closed.
  4. The whole sequence must complete within 15 s under normal load.
  5. If drain does not complete in time, open streams are force-closed.
"""

import asyncio
import time
from typing import List

import pytest


# ---------------------------------------------------------------------------
# MockTapSensor — simulates the shutdown sequence
# ---------------------------------------------------------------------------


class MockTapSensor:
    """Simulates TapSensor shutdown, recording step ordering for assertions."""

    def __init__(
        self,
        drain_timeout: float = 5.0,
        worker_drain_s: float = 0.0,
        force_close_after: float | None = None,
    ) -> None:
        self.steps: List[str] = []
        self._drain_timeout = drain_timeout
        self._worker_drain_s = worker_drain_s
        self._force_close_after = force_close_after
        self._shutdown_event = asyncio.Event()
        self._open_streams: int = 3  # simulated open streams

    async def stop_capture(self) -> None:
        self.steps.append("stop_capture")

    async def drain_workers(self) -> None:
        """Simulate waiting for worker tasks to finish."""
        self.steps.append("drain_workers_start")
        if self._worker_drain_s > 0:
            await asyncio.sleep(self._worker_drain_s)
        self.steps.append("drain_workers_done")

    async def flush_kafka(self) -> None:
        self.steps.append("flush_kafka")

    async def close_redis(self) -> None:
        self.steps.append("close_redis")

    async def force_close_streams(self) -> None:
        self._open_streams = 0
        self.steps.append("force_close_streams")

    async def shutdown(self) -> None:
        """Execute shutdown in the required order."""
        start = time.monotonic()

        await self.stop_capture()

        # Drain workers with optional timeout.
        try:
            await asyncio.wait_for(self.drain_workers(), timeout=self._drain_timeout)
        except asyncio.TimeoutError:
            self.steps.append("drain_timeout")
            await self.force_close_streams()

        # If force_close_after is set, also force-close if streams are still open
        # (simulates a secondary timeout check).
        if self._force_close_after is not None:
            elapsed = time.monotonic() - start
            if elapsed < self._force_close_after and self._open_streams > 0:
                await self.force_close_streams()

        await self.flush_kafka()
        await self.close_redis()

        self._shutdown_event.set()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTapShutdownOrder:
    async def test_shutdown_stops_capture_first(self):
        """stop_capture must be the first shutdown step."""
        sensor = MockTapSensor()
        await sensor.shutdown()

        assert sensor.steps[0] == "stop_capture"

    async def test_shutdown_drains_workers_before_scoring(self):
        """Worker drain must complete before kafka flush / redis close."""
        sensor = MockTapSensor()
        await sensor.shutdown()

        drain_done_idx = sensor.steps.index("drain_workers_done")
        flush_idx = sensor.steps.index("flush_kafka")
        assert drain_done_idx < flush_idx

    async def test_shutdown_flushes_kafka_before_closing_redis(self):
        """Kafka flush must happen before Redis is closed."""
        sensor = MockTapSensor()
        await sensor.shutdown()

        kafka_idx = sensor.steps.index("flush_kafka")
        redis_idx = sensor.steps.index("close_redis")
        assert kafka_idx < redis_idx

    async def test_shutdown_completes_within_15s_under_normal_load(self):
        """Full shutdown completes in well under 15 s for a typical workload."""
        sensor = MockTapSensor(worker_drain_s=0.05)
        start = time.monotonic()
        await sensor.shutdown()
        elapsed = time.monotonic() - start

        assert elapsed < 15.0, f"Shutdown took {elapsed:.2f}s, expected < 15s"

    async def test_shutdown_force_closes_streams_after_drain_timeout(self):
        """When worker drain times out, open streams are force-closed."""
        # Worker drain takes 10 s but timeout is 0.05 s → timeout fires.
        sensor = MockTapSensor(drain_timeout=0.05, worker_drain_s=10.0)
        await sensor.shutdown()

        assert "drain_timeout" in sensor.steps
        assert "force_close_streams" in sensor.steps
        assert sensor._open_streams == 0
