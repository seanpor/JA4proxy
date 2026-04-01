"""
Phase 48 — Feed Health Monitoring & Circuit Breakers.

Provides per-feed circuit breakers (closed/open/half-open) and a health
monitor that aggregates status across all TI feeds.  Both are optional
add-ons; every provider works normally without them (fail-open design).

Circuit-breaker state machine
------------------------------
CLOSED   → normal operation; every request goes through
OPEN     → feed is consistently failing; API calls are skipped until
           `recovery_probe_interval` seconds have elapsed
HALF_OPEN → one probe request is allowed; success → CLOSED,
            failure → OPEN (resets the timer)

Integration pattern (inside TIProvider._process_lookup)
---------------------------------------------------------
    cb = health_monitor.get_circuit_breaker("misp")
    if cb.is_open():
        return          # fail open, skip this lookup
    t0 = time.monotonic()
    try:
        ...
        cb.record_success(time.monotonic() - t0)
    except Exception:
        cb.record_failure()
        raise
"""

import logging
import time
from enum import Enum
from typing import Dict, Optional

from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_FEED_HEALTHY = Gauge(
    "ja4proxy_ti_feed_healthy",
    "Whether a TI feed is currently healthy (1=healthy, 0=unhealthy)",
    ["feed"],
)
_CIRCUIT_OPEN = Gauge(
    "ja4proxy_ti_circuit_breaker_open",
    "Whether a TI feed circuit breaker is open (1=open/half-open, 0=closed)",
    ["feed"],
)
_CONSECUTIVE_FAILURES = Gauge(
    "ja4proxy_ti_feed_consecutive_failures",
    "Consecutive failure count for a TI feed",
    ["feed"],
)
_RESPONSE_TIME = Gauge(
    "ja4proxy_ti_feed_last_response_time_seconds",
    "Last successful API response time in seconds",
    ["feed"],
)
_CIRCUIT_TRANSITIONS = Counter(
    "ja4proxy_ti_circuit_transitions_total",
    "Circuit breaker state transitions",
    ["feed", "to_state"],
)


# ---------------------------------------------------------------------------
# Circuit-breaker
# ---------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Per-feed circuit breaker.

    Thread/task-safe for asyncio (single-threaded event loop); not designed
    for concurrent multi-threaded access without an external lock.
    """

    def __init__(
        self,
        feed_name: str,
        failure_threshold: int = 5,
        recovery_probe_interval: float = 60.0,
    ) -> None:
        self.feed_name = feed_name
        self.failure_threshold = failure_threshold
        self.recovery_probe_interval = recovery_probe_interval

        self._state: CircuitState = CircuitState.CLOSED
        self._consecutive_failures: int = 0
        self._opened_at: Optional[float] = None
        self._last_response_time: float = 0.0

        # Initialise Prometheus labels
        _FEED_HEALTHY.labels(feed=feed_name).set(1)
        _CIRCUIT_OPEN.labels(feed=feed_name).set(0)
        _CONSECUTIVE_FAILURES.labels(feed=feed_name).set(0)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_open(self) -> bool:
        """
        Returns True if the circuit is OPEN *and* the probe window has not
        yet elapsed (i.e. no request should be forwarded).

        Side-effect: transitions OPEN → HALF_OPEN when the probe window
        expires so that the next call returns False and allows one probe.
        """
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - (self._opened_at or 0.0)
            if elapsed >= self.recovery_probe_interval:
                self._transition(CircuitState.HALF_OPEN)
                return False
            return True
        return False

    def record_success(self, response_time: float = 0.0) -> None:
        """Record a successful API call and close the circuit if needed."""
        self._consecutive_failures = 0
        self._last_response_time = response_time
        _RESPONSE_TIME.labels(feed=self.feed_name).set(response_time)
        _CONSECUTIVE_FAILURES.labels(feed=self.feed_name).set(0)
        if self._state != CircuitState.CLOSED:
            self._transition(CircuitState.CLOSED)

    def record_failure(self) -> None:
        """Record a failed API call and open the circuit if threshold exceeded."""
        self._consecutive_failures += 1
        _CONSECUTIVE_FAILURES.labels(feed=self.feed_name).set(self._consecutive_failures)

        should_open = (
            self._state == CircuitState.HALF_OPEN
            or self._consecutive_failures >= self.failure_threshold
        )
        if should_open and self._state != CircuitState.OPEN:
            self._transition(CircuitState.OPEN)

    # ------------------------------------------------------------------
    # Properties (read-only)
    # ------------------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def last_response_time(self) -> float:
        return self._last_response_time

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _transition(self, new_state: CircuitState) -> None:
        old = self._state
        self._state = new_state
        _CIRCUIT_TRANSITIONS.labels(
            feed=self.feed_name, to_state=new_state.value
        ).inc()

        if new_state == CircuitState.OPEN:
            self._opened_at = time.monotonic()
            _CIRCUIT_OPEN.labels(feed=self.feed_name).set(1)
            _FEED_HEALTHY.labels(feed=self.feed_name).set(0)
            logger.warning(
                "ti_feed | event=circuit_opened | feed=%s | "
                "consecutive_failures=%d",
                self.feed_name,
                self._consecutive_failures,
            )
        elif new_state == CircuitState.HALF_OPEN:
            _CIRCUIT_OPEN.labels(feed=self.feed_name).set(1)
            logger.info(
                "ti_feed | event=circuit_half_open | feed=%s | "
                "probe_after=%.1fs",
                self.feed_name,
                self.recovery_probe_interval,
            )
        elif new_state == CircuitState.CLOSED:
            _CIRCUIT_OPEN.labels(feed=self.feed_name).set(0)
            _FEED_HEALTHY.labels(feed=self.feed_name).set(1)
            logger.info(
                "ti_feed | event=circuit_closed | feed=%s | from=%s",
                self.feed_name,
                old.value,
            )


# ---------------------------------------------------------------------------
# Health monitor (aggregator)
# ---------------------------------------------------------------------------

class FeedHealthMonitor:
    """
    Creates and manages circuit breakers for all TI feeds.

    Usage (at startup)::

        monitor = FeedHealthMonitor()
        misp = MISPProvider(..., health_monitor=monitor)

    The monitor is also queryable by the health/readiness endpoint::

        summary = monitor.get_health_summary()
        # {"misp": {"state": "closed", "consecutive_failures": 0, "healthy": True}}
    """

    def __init__(self) -> None:
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_circuit_breaker(
        self,
        feed_name: str,
        failure_threshold: int = 5,
        recovery_probe_interval: float = 60.0,
    ) -> CircuitBreaker:
        """Return the existing circuit breaker for *feed_name*, or create one."""
        if feed_name not in self._breakers:
            self._breakers[feed_name] = CircuitBreaker(
                feed_name=feed_name,
                failure_threshold=failure_threshold,
                recovery_probe_interval=recovery_probe_interval,
            )
        return self._breakers[feed_name]

    def get_health_summary(self) -> Dict[str, dict]:
        """Return a snapshot of every registered feed's health."""
        return {
            name: {
                "state": cb.state.value,
                "consecutive_failures": cb.consecutive_failures,
                "last_response_time_seconds": cb.last_response_time,
                "healthy": cb.state == CircuitState.CLOSED,
            }
            for name, cb in self._breakers.items()
        }

    def all_healthy(self) -> bool:
        """True if every registered feed has a closed circuit."""
        return all(cb.state == CircuitState.CLOSED for cb in self._breakers.values())
