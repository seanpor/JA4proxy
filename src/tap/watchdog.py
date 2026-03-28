"""
Worker watchdog for TAP mode (Phase 20, Group 10).

Monitors capture worker asyncio.Tasks and restarts them when they crash.
"""
import asyncio
import logging
import time
from typing import TYPE_CHECKING, Callable, List, Optional

if TYPE_CHECKING:
    from src.tap.tap_sensor import TapSensor

logger = logging.getLogger(__name__)

# Rapid crash = 3 crashes in 60 seconds → emit warning
_RAPID_CRASH_WINDOW = 60.0
_RAPID_CRASH_THRESHOLD = 3

# Lazy import of metrics to allow Group 11 to supply them later.
try:
    from src.tap.metrics import TAP_WORKER_RESTARTS  # type: ignore[import]
except ImportError:  # pragma: no cover
    TAP_WORKER_RESTARTS = None


def _increment_restart_metric(worker_id: int) -> None:
    """Increment the restart counter for worker_id if metrics are available."""
    if TAP_WORKER_RESTARTS is not None:
        try:
            TAP_WORKER_RESTARTS.labels(worker_id=str(worker_id)).inc()
        except Exception:  # pragma: no cover
            pass


class WorkerWatchdog:
    """Monitors capture worker asyncio.Tasks; restarts crashed workers.

    Args:
        sensor: The TapSensor instance (provides evict_shard method).
        worker_factory: Callable[int] -> asyncio.Task that creates a new worker task.
    """

    def __init__(
        self,
        sensor: "TapSensor",
        worker_factory: Callable[[int], asyncio.Task],
    ) -> None:
        self._sensor = sensor
        self._worker_factory = worker_factory
        # crash_timestamps[worker_id] = list of float (epoch times of crashes)
        self._crash_timestamps: dict[int, List[float]] = {}

    async def watch(self, worker_id: int, task: asyncio.Task) -> None:
        """Watch a worker task; restart if it crashes unexpectedly.

        If the task exits with an exception (not CancelledError) it is treated
        as a crash.  A replacement task is created via worker_factory and
        watched recursively.

        If the task exits cleanly (return value) or is cancelled, it is NOT
        restarted.
        """
        try:
            await task
        except asyncio.CancelledError:
            # Clean cancellation — do not restart.
            logger.debug(
                "tap worker %d cancelled cleanly; not restarting", worker_id
            )
            return
        except Exception as exc:
            logger.error(
                "tap worker %d crashed with %s: %s; restarting",
                worker_id,
                type(exc).__name__,
                exc,
            )
            await self._evict_shard(worker_id)
            rapid = self._record_crash(worker_id)
            if rapid:
                logger.warning(
                    "tap worker %d rapid-crash loop detected (%d crashes in %.0fs)",
                    worker_id,
                    _RAPID_CRASH_THRESHOLD,
                    _RAPID_CRASH_WINDOW,
                )
            _increment_restart_metric(worker_id)
            new_task = self._worker_factory(worker_id)
            await self.watch(worker_id, new_task)
        else:
            # Task exited without exception — clean shutdown, do not restart.
            logger.debug(
                "tap worker %d exited cleanly; not restarting", worker_id
            )

    async def _evict_shard(self, shard_id: int) -> None:
        """Evict all streams belonging to this shard (called after crash).

        Calls sensor.evict_shard(shard_id) if the method exists, otherwise logs
        a warning.
        """
        evict = getattr(self._sensor, "evict_shard", None)
        if callable(evict):
            try:
                result = evict(shard_id)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:  # pragma: no cover
                logger.warning(
                    "evict_shard(%d) raised %s: %s", shard_id, type(exc).__name__, exc
                )
        else:
            logger.warning(
                "sensor has no evict_shard method; skipping eviction for shard %d",
                shard_id,
            )

    def _record_crash(self, worker_id: int) -> bool:
        """Record a crash timestamp for worker_id.

        Returns True if the rapid-crash threshold has been exceeded (i.e. at
        least _RAPID_CRASH_THRESHOLD crashes within the last _RAPID_CRASH_WINDOW
        seconds).
        """
        now = time.monotonic()
        timestamps = self._crash_timestamps.setdefault(worker_id, [])
        timestamps.append(now)
        # Prune old entries outside the window.
        cutoff = now - _RAPID_CRASH_WINDOW
        self._crash_timestamps[worker_id] = [t for t in timestamps if t >= cutoff]
        return len(self._crash_timestamps[worker_id]) >= _RAPID_CRASH_THRESHOLD
