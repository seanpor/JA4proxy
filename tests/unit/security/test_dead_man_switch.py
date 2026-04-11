"""Unit tests for DeadManSwitch (Phase 56b-1).

Tests cover:
- Grace period: switch does not arm before grace period elapses.
- Armed after first clean check: once last_check_time is set, switch is armed.
- Trigger after timeout: if armed and last_check_time > timeout ago, SIGTERM sent.
- No trigger within timeout: recent check_time → no signal.
- Disabled by config: enabled=False → no trigger ever.
- Fail-open on error: exception in watchdog loop → logged, not re-raised.
- No trigger if monitor never ran: last_check_time=0 or None → no trigger.
"""

import asyncio
import signal
import time
from unittest.mock import MagicMock, patch

import pytest

from src.security.dead_man_switch import DeadManSwitch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_monitor(last_check_time: float = 0.0) -> MagicMock:
    """Return a mock IntegrityMonitor with last_check_time set."""
    monitor = MagicMock()
    monitor.last_check_time = last_check_time
    return monitor


def _make_dms(
    monitor: MagicMock | None = None,
    timeout_seconds: float = 300.0,
    grace_period_seconds: float = 30.0,
    enabled: bool = True,
) -> DeadManSwitch:
    """Build a DeadManSwitch with fast poll interval for tests."""
    if monitor is None:
        monitor = _make_monitor()
    return DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=timeout_seconds,
        grace_period_seconds=grace_period_seconds,
        poll_interval_seconds=0.01,  # fast for tests
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_switch_does_not_arm_before_grace_period():
    """Within 30s of construction, no kill even if monitor goes silent."""
    monitor = _make_monitor(last_check_time=time.monotonic() - 400.0)  # old timestamp
    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,
        grace_period_seconds=30.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic(),  # just started
    )

    with patch("os.kill") as mock_kill:
        # Run for a short time — still within grace period
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_does_not_trigger_if_monitor_never_ran():
    """last_check_time=0 or None → switch never triggers even after grace period."""
    monitor_zero = _make_monitor(last_check_time=0.0)
    dms = DeadManSwitch(
        integrity_monitor=monitor_zero,
        timeout_seconds=1.0,
        grace_period_seconds=0.0,  # no grace period
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,  # already past grace
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_does_not_trigger_if_monitor_never_ran_none():
    """last_check_time=None → switch never triggers."""
    monitor = _make_monitor()
    monitor.last_check_time = None  # type: ignore[assignment]
    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=1.0,
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_arms_after_first_clean_check():
    """Once last_check_time is set to a recent value, switch is armed but does not fire."""
    monitor = _make_monitor(last_check_time=time.monotonic())  # fresh check
    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,  # 5-minute window — won't expire
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Armed but check is recent — should not trigger
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_triggers_after_timeout():
    """If armed and last_check_time > timeout ago, SIGTERM is sent."""
    # Set last_check_time far in the past (armed, but stale)
    monitor = _make_monitor(last_check_time=time.monotonic() - 400.0)

    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,  # 400s > 300s → should trigger
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # The switch fires once only (fire-once guard); the mock prevents the
        # real SIGTERM from stopping the process so the loop keeps running, but
        # the _fired flag means os.kill is called exactly once.
        mock_kill.assert_called_once()
        args = mock_kill.call_args[0]
        assert args[1] == signal.SIGTERM


@pytest.mark.asyncio
async def test_switch_does_not_trigger_within_timeout():
    """Recent last_check_time → switch is armed but does not fire."""
    monitor = _make_monitor(last_check_time=time.monotonic() - 10.0)  # 10s ago

    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,  # 10s << 300s → no trigger
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_disabled_by_config():
    """enabled=False → no trigger even with stale monitor and no grace period."""
    monitor = _make_monitor(last_check_time=time.monotonic() - 9999.0)

    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=1.0,
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=False,  # disabled
        _start_time_override=time.monotonic() - 100.0,
    )

    with patch("os.kill") as mock_kill:
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_switch_fails_open_on_error():
    """Exception in watchdog loop → logged, not re-raised, does not kill process."""
    monitor = MagicMock()
    # Make last_check_time raise AttributeError on first access, then return a sane value
    type(monitor).last_check_time = property(lambda self: (_ for _ in ()).throw(AttributeError("boom")))

    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    with patch("os.kill") as mock_kill:
        # Should run without raising — fail open
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Must not have called kill (error path → fail open)
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_prometheus_counter_incremented_on_trigger():
    """Prometheus counter incremented when SIGTERM is sent."""
    monitor = _make_monitor(last_check_time=time.monotonic() - 400.0)

    dms = DeadManSwitch(
        integrity_monitor=monitor,
        timeout_seconds=300.0,
        grace_period_seconds=0.0,
        poll_interval_seconds=0.01,
        enabled=True,
        _start_time_override=time.monotonic() - 10.0,
    )

    initial = dms._trigger_counter._value.get()

    with patch("os.kill"):
        task = asyncio.create_task(dms.run())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert dms._trigger_counter._value.get() > initial
