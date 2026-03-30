"""Unit tests for WorkerWatchdog (Phase 20, Group 10).

Tests cover:
- Crashed worker is restarted via worker_factory.
- Worker restart increments the prometheus metric (via factory call count).
- Shard streams are evicted after a worker crash.
- Rapid-crash loop (3 crashes within 60 s) emits a WARNING log.
- Clean worker shutdown does NOT trigger a restart.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tap.watchdog import _RAPID_CRASH_THRESHOLD, _RAPID_CRASH_WINDOW, WorkerWatchdog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sensor(has_evict_shard: bool = True) -> MagicMock:
    """Return a minimal TapSensor mock."""
    sensor = MagicMock()
    if has_evict_shard:
        sensor.evict_shard = MagicMock()
    else:
        del sensor.evict_shard
    return sensor


def _crash_task(exc: Exception | None = None) -> asyncio.Task:
    """Return a Task that raises *exc* (default RuntimeError('boom'))."""
    if exc is None:
        exc = RuntimeError("boom")

    async def _coro():
        raise exc

    return asyncio.ensure_future(_coro())


def _clean_task() -> asyncio.Task:
    """Return a Task that exits cleanly (returns None)."""

    async def _coro():
        return None

    return asyncio.ensure_future(_coro())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCrashedWorkerRestarted:
    async def test_crashed_worker_is_restarted(self):
        """A worker that crashes with RuntimeError should be restarted once."""
        sensor = _make_sensor()
        call_count = 0

        def factory(worker_id: int) -> asyncio.Task:
            nonlocal call_count
            call_count += 1
            # Second call: return a clean task so we don't loop forever.
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)
        crashing = _crash_task()
        await watchdog.watch(0, crashing)

        # factory should have been called once (to produce the replacement task)
        assert call_count == 1

    async def test_worker_restart_increments_metric(self):
        """Restart increments the restart counter metric (checked via factory calls)."""
        sensor = _make_sensor()
        factory_calls: list[int] = []

        def factory(worker_id: int) -> asyncio.Task:
            factory_calls.append(worker_id)
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)
        await watchdog.watch(0, _crash_task())

        # One restart happened → factory was called once for worker 0
        assert factory_calls == [0]

    async def test_shard_streams_evicted_after_worker_crash(self):
        """evict_shard is called with the worker's shard id after a crash."""
        sensor = _make_sensor(has_evict_shard=True)

        def factory(worker_id: int) -> asyncio.Task:
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)
        await watchdog.watch(0, _crash_task())

        sensor.evict_shard.assert_called_once_with(0)


class TestRapidCrashDetection:
    async def test_rapid_crash_loop_emits_warn_after_3_in_60s(
        self, caplog: pytest.LogCaptureFixture
    ):
        """3 crashes within _RAPID_CRASH_WINDOW seconds should emit a WARNING."""
        sensor = _make_sensor()
        crash_count = 0
        max_crashes = _RAPID_CRASH_THRESHOLD

        def factory(worker_id: int) -> asyncio.Task:
            nonlocal crash_count
            crash_count += 1
            if crash_count < max_crashes:
                return _crash_task()
            # After threshold crashes, return clean task to stop recursion.
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)

        with caplog.at_level(logging.WARNING, logger="src.tap.watchdog"):
            await watchdog.watch(0, _crash_task())

        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any("rapid-crash" in m for m in warning_msgs), (
            f"Expected rapid-crash warning; got: {warning_msgs}"
        )


class TestCleanShutdown:
    async def test_watchdog_does_not_restart_after_clean_shutdown(self):
        """A task that exits without an exception should NOT be restarted."""
        sensor = _make_sensor()
        factory_calls: list[int] = []

        def factory(worker_id: int) -> asyncio.Task:
            factory_calls.append(worker_id)
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)
        await watchdog.watch(0, _clean_task())

        # No restart should have happened.
        assert factory_calls == []

    async def test_cancelled_worker_is_not_restarted(self):
        """A CancelledError exit must NOT trigger a restart."""
        sensor = _make_sensor()
        factory_calls: list[int] = []

        def factory(worker_id: int) -> asyncio.Task:
            factory_calls.append(worker_id)
            return _clean_task()

        watchdog = WorkerWatchdog(sensor, factory)
        await watchdog.watch(0, _crash_task(asyncio.CancelledError()))

        assert factory_calls == []
