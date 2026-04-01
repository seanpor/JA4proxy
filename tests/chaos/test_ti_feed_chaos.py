"""
Phase 48 — Chaos tests: TI feed reliability & circuit breakers.

Verifies that:
- The MISP provider fails open when the feed is unreachable.
- The circuit breaker opens after repeated failures and blocks further calls.
- The circuit breaker transitions to HALF_OPEN after the probe interval and
  re-closes on a successful probe.
- The system continues to return cached signals while the circuit is open.
- FeedHealthMonitor.get_health_summary() reflects live circuit state.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.feed_health import CircuitBreaker, CircuitState, FeedHealthMonitor
from src.security.misp import MISPConfig, MISPProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _misp_config(**kwargs) -> MISPConfig:
    defaults = dict(
        enabled=True,
        api_key="test-key",
        base_url="https://misp.test",
        attribute_score=20,
        score_cap=50,
        queue_size=10,
        worker_count=1,
    )
    defaults.update(kwargs)
    return MISPConfig(**defaults)


def _mock_redis(cached_data=None):
    r = MagicMock()
    encoded = json.dumps(cached_data).encode() if cached_data else None
    r.get = AsyncMock(return_value=encoded)
    r.setex = AsyncMock(return_value=True)
    r.expire = AsyncMock(return_value=True)
    bf = MagicMock()
    bf.add = AsyncMock(return_value=1)
    r.bf = MagicMock(return_value=bf)
    return r


def _mock_local_cache(cached_data=None):
    c = MagicMock()
    c.misp_scores = MagicMock()
    c.misp_scores.get.return_value = cached_data
    return c


def _ctx_manager(mock_resp):
    """Wrap a mock response object in an async context manager."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


# ---------------------------------------------------------------------------
# CircuitBreaker unit tests
# ---------------------------------------------------------------------------

class TestCircuitBreakerStates:
    """State-machine correctness."""

    def test_starts_closed(self):
        cb = CircuitBreaker("misp", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
        assert not cb.is_open()

    def test_opens_after_threshold(self):
        cb = CircuitBreaker("misp", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.is_open()

    def test_open_blocks_requests(self):
        cb = CircuitBreaker("misp", failure_threshold=1, recovery_probe_interval=9999)
        cb.record_failure()
        assert cb.is_open()
        # Calling is_open() multiple times while OPEN still returns True
        assert cb.is_open()

    def test_transitions_to_half_open_after_probe_interval(self):
        cb = CircuitBreaker("misp", failure_threshold=1, recovery_probe_interval=0.0)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        # With recovery_probe_interval=0 the next is_open() should half-open
        result = cb.is_open()
        assert result is False
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker("misp", failure_threshold=1, recovery_probe_interval=0.0)
        cb.record_failure()
        cb.is_open()  # triggers HALF_OPEN
        cb.record_success(response_time=0.1)
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == 0

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker("misp", failure_threshold=1, recovery_probe_interval=0.0)
        cb.record_failure()
        cb.is_open()  # HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_success_resets_consecutive_failures(self):
        cb = CircuitBreaker("misp", failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        assert cb.consecutive_failures == 2
        cb.record_success()
        assert cb.consecutive_failures == 0

    def test_response_time_recorded(self):
        cb = CircuitBreaker("misp", failure_threshold=5)
        cb.record_success(response_time=0.42)
        assert cb.last_response_time == pytest.approx(0.42)


# ---------------------------------------------------------------------------
# FeedHealthMonitor
# ---------------------------------------------------------------------------

class TestFeedHealthMonitor:

    def test_get_or_create_circuit_breaker(self):
        monitor = FeedHealthMonitor()
        cb1 = monitor.get_circuit_breaker("misp")
        cb2 = monitor.get_circuit_breaker("misp")
        assert cb1 is cb2

    def test_health_summary_healthy(self):
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("misp")
        monitor.get_circuit_breaker("greynoise")
        summary = monitor.get_health_summary()
        assert summary["misp"]["healthy"] is True
        assert summary["greynoise"]["healthy"] is True

    def test_health_summary_after_open(self):
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1)
        cb.record_failure()
        summary = monitor.get_health_summary()
        assert summary["misp"]["healthy"] is False
        assert summary["misp"]["state"] == "open"
        assert summary["misp"]["consecutive_failures"] == 1

    def test_all_healthy_true_when_closed(self):
        monitor = FeedHealthMonitor()
        monitor.get_circuit_breaker("misp")
        assert monitor.all_healthy() is True

    def test_all_healthy_false_when_open(self):
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1)
        cb.record_failure()
        assert monitor.all_healthy() is False


# ---------------------------------------------------------------------------
# MISP provider + circuit breaker integration
# ---------------------------------------------------------------------------

class TestMISPCircuitBreakerIntegration:
    """MISP provider uses the circuit breaker to skip API calls when open."""

    @pytest.mark.asyncio
    async def test_circuit_open_skips_api_call(self):
        """When circuit is open, _process_lookup returns without calling the API."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1,
                                         recovery_probe_interval=9999)
        cb.record_failure()  # open the circuit

        mock_session = MagicMock()
        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),
            mock_session,
            health_monitor=monitor,
        )

        await provider._process_lookup("1.2.3.4")
        mock_session.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_circuit_closes_on_successful_api_call(self):
        """A successful API call closes a previously-open circuit."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1,
                                         recovery_probe_interval=0.0)
        cb.record_failure()  # open
        cb.is_open()         # transition to HALF_OPEN

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "response": [{"id": "1", "value": "1.2.3.4", "type": "ip-dst"}]
        })
        mock_session = MagicMock()
        mock_session.post.return_value = _ctx_manager(mock_resp)

        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),
            mock_session,
            health_monitor=monitor,
        )

        await provider._process_lookup("1.2.3.4")
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_timeout_opens_circuit(self):
        """Repeated timeouts drive consecutive_failures up and open the circuit."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=2,
                                         recovery_probe_interval=9999)

        mock_session = MagicMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx.__aexit__ = AsyncMock(return_value=None)
        mock_session.post.return_value = ctx

        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),
            mock_session,
            health_monitor=monitor,
        )

        await provider._process_lookup("1.2.3.4")
        assert cb.consecutive_failures == 1
        assert cb.state == CircuitState.CLOSED

        await provider._process_lookup("1.2.3.4")
        assert cb.consecutive_failures == 2
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_connection_error_records_failure(self):
        """Network errors (ConnectionError) are recorded as circuit failures."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=3)

        mock_session = MagicMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=ConnectionError("refused"))
        ctx.__aexit__ = AsyncMock(return_value=None)
        mock_session.post.return_value = ctx

        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),
            mock_session,
            health_monitor=monitor,
        )

        await provider._process_lookup("5.6.7.8")
        assert cb.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_get_signal_returns_none_gracefully_when_circuit_open(self):
        """get_signal() always returns None for unknown IPs even if circuit is open."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1,
                                         recovery_probe_interval=9999)
        cb.record_failure()

        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),     # cache miss
            MagicMock(),
            health_monitor=monitor,
        )

        # Should return None, not raise
        signal = provider.get_signal("9.9.9.9")
        assert signal is None

    @pytest.mark.asyncio
    async def test_cached_signal_served_while_circuit_open(self):
        """Cached signals are still served from local cache when circuit is open."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=1,
                                         recovery_probe_interval=9999)
        cb.record_failure()

        cached = {"attribute_count": 3}
        provider = MISPProvider(
            _misp_config(score_cap=100),
            _mock_redis(),
            _mock_local_cache(cached_data=cached),   # cache hit
            MagicMock(),
            health_monitor=monitor,
        )

        signal = provider.get_signal("1.2.3.4")
        assert signal is not None
        assert signal.score == 60   # 3 * 20


# ---------------------------------------------------------------------------
# System-level: all providers down simultaneously
# ---------------------------------------------------------------------------

class TestSystemDegradationGraceful:
    """System continues operating when TI feeds are unavailable."""

    @pytest.mark.asyncio
    async def test_misp_down_no_crash(self):
        """MISP unreachable → no signal emitted, no exception, pipeline continues."""
        mock_session = MagicMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=ConnectionRefusedError())
        ctx.__aexit__ = AsyncMock(return_value=None)
        mock_session.post.return_value = ctx

        provider = MISPProvider(
            _misp_config(),
            _mock_redis(),
            _mock_local_cache(),
            mock_session,
        )

        # Must not raise
        await provider._process_lookup("10.0.0.1")
        # get_signal always fails open for unknown IPs
        assert provider.get_signal("10.0.0.1") is None

    @pytest.mark.asyncio
    async def test_recovery_after_outage(self):
        """After a simulated outage, a successful call re-closes the circuit."""
        monitor = FeedHealthMonitor()
        cb = monitor.get_circuit_breaker("misp", failure_threshold=2,
                                         recovery_probe_interval=0.0)
        # Simulate two failures → circuit opens
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Probe window elapsed → HALF_OPEN
        is_open = cb.is_open()
        assert is_open is False
        assert cb.state == CircuitState.HALF_OPEN

        # Successful call → CLOSED
        cb.record_success(response_time=0.05)
        assert cb.state == CircuitState.CLOSED
        assert monitor.all_healthy() is True
