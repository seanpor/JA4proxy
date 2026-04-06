"""Dead-Man's Switch: self-terminates the proxy if the integrity monitor goes silent.

Phase 56b-1.

The switch monitors the :attr:`IntegrityMonitor.last_check_time` timestamp.
If a clean check has previously run (i.e. ``last_check_time`` is non-zero and
non-``None``) and the monitor has not confirmed a new clean check within
``timeout_seconds``, the switch sends ``signal.SIGTERM`` to the current process.

Design decisions
----------------
- **Grace period** (default 30 s): the switch does not arm until
  ``grace_period_seconds`` have elapsed since construction.  This prevents
  spurious kills during startup when the integrity monitor hasn't had its
  first chance to run.
- **Never-ran guard**: if ``last_check_time`` is 0 or ``None``, the monitor
  has never successfully completed a check.  The switch does NOT trigger in
  this state — only a known-good check that subsequently goes silent should
  trigger self-termination.
- **Fail-open**: any exception inside the watchdog coroutine is caught,
  logged, and the loop continues.  The switch must never crash the proxy due
  to an internal error.
- **Prometheus counter**: ``ja4proxy_dead_man_switch_triggered_total``
  is incremented each time the switch fires.
- **Disabled by config**: when ``enabled=False`` the coroutine returns
  immediately without arming.
"""

import asyncio
import logging
import os
import signal
import time
from typing import Optional

from prometheus_client import Counter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_DMS_TRIGGERED = Counter(
    "ja4proxy_dead_man_switch_triggered_total",
    "Number of times the dead-man's switch has fired and sent SIGTERM",
)


# ---------------------------------------------------------------------------
# Per-instance counter shim (mirrors the pattern in integrity_monitor.py)
# ---------------------------------------------------------------------------


class _InstanceTriggerCounter:
    """Per-instance counter that also increments the global Prometheus counter."""

    def __init__(self) -> None:
        self._count: float = 0.0

    def get(self) -> float:
        return self._count

    def inc(self, amount: float = 1.0) -> None:
        self._count += amount
        _DMS_TRIGGERED.inc(amount)


class _TriggerCounterShim:
    """Shim exposing ``._value`` compatible with prometheus ``Counter._value``."""

    def __init__(self) -> None:
        self._value = _InstanceTriggerCounter()

    def inc(self, amount: float = 1.0) -> None:
        self._value.inc(amount)


# ---------------------------------------------------------------------------
# DeadManSwitch
# ---------------------------------------------------------------------------


class DeadManSwitch:
    """Asyncio watchdog that kills the process if the integrity monitor goes silent.

    Args:
        integrity_monitor: An :class:`~src.security.integrity_monitor.IntegrityMonitor`
            instance (or any object with a ``last_check_time`` float attribute).
        timeout_seconds: How long the integrity monitor may be silent before the
            switch fires.  Defaults to 300 s (5 minutes).
        grace_period_seconds: Startup grace period before the switch arms itself.
            Defaults to 30 s.
        poll_interval_seconds: How often the watchdog checks the timestamp.
            Defaults to 15 s.  Set lower in tests.
        enabled: Master switch.  When ``False``, :meth:`run` returns immediately.
        _start_time_override: Override for ``time.monotonic()`` at construction time,
            used in tests to simulate a process that started long ago.
    """

    def __init__(
        self,
        integrity_monitor: object,
        timeout_seconds: float = 300.0,
        grace_period_seconds: float = 30.0,
        poll_interval_seconds: float = 15.0,
        enabled: bool = True,
        _start_time_override: Optional[float] = None,
    ) -> None:
        self._monitor = integrity_monitor
        self._timeout = timeout_seconds
        self._grace = grace_period_seconds
        self._poll = poll_interval_seconds
        self._enabled = enabled
        self._start_time: float = (
            _start_time_override if _start_time_override is not None else time.monotonic()
        )
        self._trigger_counter = _TriggerCounterShim()
        self._fired: bool = False  # fire only once — repeated SIGTERM is pointless

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the watchdog loop until cancelled.

        Returns immediately if ``enabled=False``.  Any unhandled exception
        inside the loop is caught, logged, and the loop continues (fail-open).
        """
        if not self._enabled:
            logger.debug("dead_man_switch | event=disabled | action=noop")
            return

        logger.info(
            "dead_man_switch | event=started | timeout=%s | grace=%s",
            self._timeout,
            self._grace,
        )

        while True:
            try:
                await asyncio.sleep(self._poll)
            except asyncio.CancelledError:
                logger.info("dead_man_switch | event=stopped")
                return

            try:
                self._check()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Fail open: log and continue the loop
                logger.error(
                    "dead_man_switch | event=watchdog_error | error=%s | "
                    "effect=continuing without action",
                    exc,
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check(self) -> None:
        """Inspect the monitor's timestamp and fire if conditions are met."""
        # Fire at most once — repeated SIGTERM after the first is pointless.
        if self._fired:
            return

        now = time.monotonic()

        # Grace period: do not arm until enough time has elapsed since startup.
        elapsed_since_start = now - self._start_time
        if elapsed_since_start < self._grace:
            logger.debug(
                "dead_man_switch | event=grace_period | elapsed=%.1f | grace=%.1f",
                elapsed_since_start,
                self._grace,
            )
            return

        # Read the monitor's last_check_time.
        last_check: Optional[float] = getattr(self._monitor, "last_check_time", None)

        # Never-ran guard: 0 or None means the monitor hasn't had its first run.
        if not last_check:
            logger.debug(
                "dead_man_switch | event=monitor_never_ran | action=noop"
            )
            return

        # Check staleness.
        age = now - last_check
        if age > self._timeout:
            self._trigger(age)

    def _trigger(self, age: float) -> None:
        """Send SIGTERM to the current process (once only)."""
        self._fired = True
        self._trigger_counter.inc()
        logger.critical(
            "dead_man_switch | event=triggered | last_check_age=%.1f | "
            "timeout=%.1f | action=SIGTERM",
            age,
            self._timeout,
        )
        os.kill(os.getpid(), signal.SIGTERM)
