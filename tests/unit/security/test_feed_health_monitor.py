"""
Phase 59b — Unit tests for FeedHealthMonitor extensions.

Covers:
- CircuitBreaker._history tracking (success, failure, state_change)
- History max-size enforcement (deque maxlen=100)
- Periodic health probing via register_probe / start_probing / stop_probing
- Alert callbacks on circuit open and feed registration
- Regression check: get_health_summary still works after Phase 59b changes
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.security.feed_health import CircuitBreaker, CircuitState, FeedHealthMonitor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cb(name: str = "test_feed", threshold: int = 3) -> CircuitBreaker:
    return CircuitBreaker(name, failure_threshold=threshold)


# ---------------------------------------------------------------------------
# History tracking on CircuitBreaker
# ---------------------------------------------------------------------------

class TestCircuitBreakerHistory:

    def test_history_records_success(self):
        cb = _cb()
        cb.record_success(response_time=0.05)
        h = cb.history
        assert len(h) == 1
        assert h[0]["event"] == "success"
        assert h[0]["response_time"] == pytest.approx(0.05)
        assert "ts" in h[0]
        assert "state" in h[0]

    def test_history_records_failure(self):
        cb = _cb()
        cb.record_failure()
        h = cb.history
        assert len(h) == 1
        assert h[0]["event"] == "failure"
        assert h[0]["response_time"] == 0.0

    def test_history_records_state_change(self):
        # After enough failures the circuit opens → _transition fires → state_change entry
        cb = _cb(threshold=1)
        cb.record_failure()  # failure entry + state_change entry (OPEN transition)
        h = cb.history
        events = [e["event"] for e in h]
        assert "state_change" in events
        state_change = next(e for e in h if e["event"] == "state_change")
        assert state_change["state"] == CircuitState.OPEN.value

    def test_history_max_size(self):
        cb = _cb(threshold=9999)
        for _ in range(150):
            cb.record_success(0.0)
        assert len(cb.history) == 100

    def test_history_returns_copy(self):
        """Mutating the returned list must not affect the internal deque."""
        cb = _cb()
        cb.record_success(0.1)
        h = cb.history
        h.clear()
        assert len(cb.history) == 1


# ---------------------------------------------------------------------------
# Periodic probing
# ---------------------------------------------------------------------------

class TestFeedProbing:

    @pytest.mark.asyncio
    async def test_probe_calls_record_success(self):
        monitor = FeedHealthMonitor()
        # Ensure the circuit breaker exists first
        cb = monitor.get_circuit_breaker("svc", failure_threshold=5)

        call_count = 0

        async def good_probe() -> float:
            nonlocal call_count
            call_count += 1
            return 0.1

        monitor.register_probe("svc", good_probe, interval_seconds=0.01)
        await monitor.start_probing()

        # Give the task a moment to run at least once
        await asyncio.sleep(0.05)
        await monitor.stop_probing()

        assert call_count >= 1
        h = cb.history
        success_events = [e for e in h if e["event"] == "success"]
        assert len(success_events) >= 1

    @pytest.mark.asyncio
    async def test_probe_calls_record_failure(self):
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("bad_svc", failure_threshold=99)

        fail_count = 0

        async def failing_probe() -> float:
            nonlocal fail_count
            fail_count += 1
            raise ConnectionError("simulated failure")

        monitor.register_probe("bad_svc", failing_probe, interval_seconds=0.01)
        await monitor.start_probing()
        await asyncio.sleep(0.05)
        await monitor.stop_probing()

        assert fail_count >= 1
        h = cb.history
        failure_events = [e for e in h if e["event"] == "failure"]
        assert len(failure_events) >= 1

    @pytest.mark.asyncio
    async def test_probe_cancelled_cleanly(self):
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("svc2")

        async def slow_probe() -> float:
            await asyncio.sleep(100)
            return 0.0

        monitor.register_probe("svc2", slow_probe, interval_seconds=100.0)
        await monitor.start_probing()
        # stop_probing cancels the task — must not raise
        await monitor.stop_probing()
        # Probe tasks should be cleared
        assert len(monitor._probe_tasks) == 0

    @pytest.mark.asyncio
    async def test_start_probing_idempotent(self):
        """Calling start_probing twice must not create duplicate tasks."""
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("svc3")

        async def probe() -> float:
            return 0.0

        monitor.register_probe("svc3", probe, interval_seconds=100.0)
        await monitor.start_probing()
        first_task = monitor._probe_tasks.get("svc3")
        await monitor.start_probing()
        second_task = monitor._probe_tasks.get("svc3")

        assert first_task is second_task
        await monitor.stop_probing()


# ---------------------------------------------------------------------------
# Alert callback
# ---------------------------------------------------------------------------

class TestAlertCallback:

    def test_alert_callback_on_circuit_open(self):
        monitor = FeedHealthMonitor()
        alerts = []

        def on_alert(feed_name: str, event: str, context: dict) -> None:
            alerts.append((feed_name, event, context))

        monitor.set_alert_callback(on_alert)
        cb = monitor.get_circuit_breaker("alertfeed", failure_threshold=1)

        cb.record_failure()  # should open and trigger callback

        circuit_opened = [(fn, ev, ctx) for fn, ev, ctx in alerts if ev == "circuit_opened"]
        assert len(circuit_opened) >= 1
        fn, ev, ctx = circuit_opened[0]
        assert fn == "alertfeed"
        assert ev == "circuit_opened"
        assert ctx["feed_name"] == "alertfeed"
        assert "consecutive_failures" in ctx
        assert "state" in ctx

    def test_alert_callback_on_feed_registered(self):
        monitor = FeedHealthMonitor()
        alerts = []

        def on_alert(feed_name: str, event: str, context: dict) -> None:
            alerts.append((feed_name, event, context))

        monitor.set_alert_callback(on_alert)
        monitor.get_circuit_breaker("newfeed")

        reg_events = [(fn, ev, ctx) for fn, ev, ctx in alerts if ev == "feed_registered"]
        assert len(reg_events) == 1
        fn, ev, ctx = reg_events[0]
        assert fn == "newfeed"
        assert ctx["feed_name"] == "newfeed"

    def test_no_alert_without_callback(self):
        """Setting no callback must not raise when circuit opens."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("silent", failure_threshold=1)
        # Should not raise even without a callback
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_alert_not_fired_for_existing_breaker(self):
        """Second call to get_circuit_breaker for the same feed must not fire registered again."""
        monitor = FeedHealthMonitor()
        alerts = []

        def on_alert(feed_name: str, event: str, context: dict) -> None:
            alerts.append(event)

        monitor.set_alert_callback(on_alert)
        monitor.get_circuit_breaker("dupl")
        monitor.get_circuit_breaker("dupl")  # second call — already exists

        assert alerts.count("feed_registered") == 1


# ---------------------------------------------------------------------------
# Regression: get_health_summary still works after Phase 59b changes
# ---------------------------------------------------------------------------

class TestGetHealthSummaryRegression:

    def test_get_health_summary_includes_history(self):
        """get_health_summary should return the same structure as before Phase 59b."""
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("misp")
        monitor.get_circuit_breaker("greynoise")

        summary = monitor.get_health_summary()

        assert set(summary.keys()) == {"misp", "greynoise"}
        for feed, data in summary.items():
            assert "state" in data
            assert "consecutive_failures" in data
            assert "last_response_time_seconds" in data
            assert "healthy" in data
            assert data["healthy"] is True

    def test_all_healthy_still_works(self):
        monitor = FeedHealthMonitor()
        # Use threshold=1 from the start so one failure opens the circuit
        cb = monitor.get_circuit_breaker("a", failure_threshold=1)
        monitor.get_circuit_breaker("b")
        assert monitor.all_healthy() is True

        cb.record_failure()
        assert monitor.all_healthy() is False


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestCircuitBreakerIsOpenCoverage:
    """Cover lines 139-140, 142 in is_open()."""

    def test_is_open_returns_true_when_open_and_interval_not_elapsed(self):
        """Line 142: is_open() returns True when circuit is OPEN and recovery window
        has not elapsed.
        So what: if this returns False when the circuit is genuinely OPEN, requests
        are forwarded to a broken TI feed — the circuit breaker provides no protection."""
        cb = _cb(threshold=1, name="open_block")
        cb.record_failure()  # opens circuit (threshold=1)
        assert cb.state == CircuitState.OPEN
        # Immediately call is_open — elapsed ≈ 0 < 60s default → must return True
        assert cb.is_open() is True

    def test_is_open_transitions_to_half_open_after_recovery_interval(self):
        """Lines 139-140 + 225-232: after recovery_probe_interval elapses,
        is_open() transitions OPEN→HALF_OPEN and returns False (allows one probe).
        So what: if this transition never fires, a dead TI feed is blocked forever —
        the circuit can never recover and the feed permanently stops contributing
        threat intelligence."""
        import time as _time
        from unittest.mock import patch

        cb = CircuitBreaker("recovery_test", failure_threshold=1, recovery_probe_interval=30.0)
        cb.record_failure()  # opens circuit
        assert cb.state == CircuitState.OPEN

        # Advance monotonic time past the recovery interval
        real_opened_at = cb._opened_at
        with patch("src.security.feed_health.time") as mock_time:
            mock_time.monotonic.return_value = real_opened_at + 40.0  # > 30s
            result = cb.is_open()

        assert result is False
        assert cb.state == CircuitState.HALF_OPEN

    def test_record_success_transitions_closed_from_half_open(self):
        """Lines 157 + 233-240: record_success() when in HALF_OPEN state transitions
        circuit to CLOSED.
        So what: if this transition is missing, a successful probe after the recovery
        window does not close the circuit — requests continue to be blocked even after
        the feed has recovered."""
        import time as _time
        from unittest.mock import patch

        cb = CircuitBreaker("close_test", failure_threshold=1, recovery_probe_interval=10.0)
        cb.record_failure()  # opens circuit
        assert cb.state == CircuitState.OPEN

        real_opened_at = cb._opened_at
        with patch("src.security.feed_health.time") as mock_time:
            mock_time.monotonic.return_value = real_opened_at + 20.0
            cb.is_open()  # transitions OPEN → HALF_OPEN

        assert cb.state == CircuitState.HALF_OPEN

        # Successful probe → must close the circuit
        cb.record_success(0.05)
        assert cb.state == CircuitState.CLOSED


class TestProbeLoopCancellationDuringProbeFn:
    """Cover line 386: CancelledError raised inside await probe_fn()."""

    @pytest.mark.asyncio
    async def test_probe_loop_cancelled_while_awaiting_probe_fn(self):
        """Line 386: CancelledError propagated from within probe_fn is caught and
        causes _probe_loop to return cleanly.
        So what: if this return is missing, CancelledError propagates uncaught through
        stop_probing(), leaving the event loop in an inconsistent state — the proxy
        shutdown sequence would hang or raise on every graceful stop."""
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("cancel_probe")

        probe_started = asyncio.Event()

        async def blocking_probe() -> float:
            probe_started.set()
            await asyncio.sleep(100)  # blocks here; cancelled from outside
            return 0.0

        monitor.register_probe("cancel_probe", blocking_probe, interval_seconds=60.0)
        await monitor.start_probing()

        # Wait until the probe coroutine actually starts executing (event set)
        await probe_started.wait()

        # Cancel while probe_fn is awaiting asyncio.sleep — hits line 386
        await monitor.stop_probing()
        assert len(monitor._probe_tasks) == 0
