"""Per-feed circuit breaker for the Phase 85 threat-intel runner.

Three states per PHASE_85.md §5.4:

* **CLOSED** — normal operation. Every successful poll resets the failure
  counter. On the ``failure_threshold``th consecutive full-poll failure,
  transition to OPEN.
* **OPEN** — skip polling. After ``open_timeout_s`` seconds, transition to
  HALF-OPEN to try a single probe.
* **HALF-OPEN** — the next poll is a probe. On success, transition to CLOSED.
  On failure, go back to OPEN and double the backoff up to ``backoff_max_s``.

The breaker is **in-process state** keyed by ``feed_id``; the long-term
``circuit_state`` projection is written to Redis by ``state.FeedState`` so the
Management API can surface it. The two sources of truth are kept in sync by
the runner: every transition calls ``FeedState.set_circuit_state`` before it
returns.

Intentionally distinct from Phase 14e/59's
``threat_intelligence.circuit_breaker_failure_threshold`` (PHASE_85.md §5.4
naming note): that breaker opens on a single failing hot-path call, ours opens
only after N consecutive full polls fail.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Breaker state vocabulary, matching the Prometheus gauge encoding."""

    CLOSED = "closed"
    HALF_OPEN = "half_open"
    OPEN = "open"


@dataclass
class CircuitBreakerConfig:
    """Tunables from ``config/proxy.yml`` → ``threat_intel.circuit_breaker``."""

    failure_threshold: int = 3
    open_timeout_s: int = 600
    backoff_max_s: int = 3600


@dataclass
class _CircuitTracker:
    """Per-feed mutable state. Not exported."""

    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    open_since: float = 0.0
    current_backoff_s: int = 0


@dataclass
class PerFeedCircuitBreaker:
    """Independent per-feed breaker managed by :class:`CircuitBreakerManager`."""

    feed_id: str
    config: CircuitBreakerConfig
    tracker: _CircuitTracker = field(default_factory=_CircuitTracker)

    @property
    def state(self) -> CircuitState:
        """Return the current logical state, lazily transitioning OPEN→HALF-OPEN."""
        if self.tracker.state == CircuitState.OPEN:
            if time.monotonic() - self.tracker.open_since >= self.tracker.current_backoff_s:
                self.tracker.state = CircuitState.HALF_OPEN
                logger.info(
                    "ti_feed | event=circuit_half_open | feed=%s | backoff_s=%d",
                    self.feed_id,
                    self.tracker.current_backoff_s,
                )
        return self.tracker.state

    def allow_poll(self) -> bool:
        """Return True if the runner should attempt a poll right now."""
        return self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> CircuitState:
        """Register a successful poll and (maybe) transition to CLOSED."""
        prev = self.tracker.state
        self.tracker.consecutive_failures = 0
        self.tracker.state = CircuitState.CLOSED
        self.tracker.open_since = 0.0
        self.tracker.current_backoff_s = 0
        if prev != CircuitState.CLOSED:
            logger.info(
                "ti_feed | event=circuit_closed | feed=%s | prev_state=%s",
                self.feed_id,
                prev.value,
            )
        return self.tracker.state

    def record_failure(self) -> CircuitState:
        """Register a failed poll and maybe transition CLOSED→OPEN or HALF-OPEN→OPEN."""
        prev = self.tracker.state
        self.tracker.consecutive_failures += 1

        should_open = (
            prev == CircuitState.HALF_OPEN
            or self.tracker.consecutive_failures >= self.config.failure_threshold
        )
        if should_open:
            # Compute next backoff: start at open_timeout_s, double each OPEN cycle.
            if self.tracker.current_backoff_s == 0:
                self.tracker.current_backoff_s = self.config.open_timeout_s
            else:
                self.tracker.current_backoff_s = min(
                    self.tracker.current_backoff_s * 2,
                    self.config.backoff_max_s,
                )
            self.tracker.state = CircuitState.OPEN
            self.tracker.open_since = time.monotonic()
            logger.warning(
                "ti_feed | event=circuit_open | feed=%s | consecutive_failures=%d | "
                "backoff_s=%d",
                self.feed_id,
                self.tracker.consecutive_failures,
                self.tracker.current_backoff_s,
            )
        return self.tracker.state

    def reset(self) -> None:
        """Force the breaker to CLOSED — used by the manual poll endpoint."""
        self.tracker = _CircuitTracker()


class CircuitBreakerManager:
    """Per-feed breaker store, built from the ``threat_intel.circuit_breaker`` config."""

    def __init__(self, config: CircuitBreakerConfig) -> None:
        self._config = config
        self._breakers: dict[str, PerFeedCircuitBreaker] = {}

    def for_feed(self, feed_id: str) -> PerFeedCircuitBreaker:
        """Return (or lazily create) the breaker for ``feed_id``."""
        if feed_id not in self._breakers:
            self._breakers[feed_id] = PerFeedCircuitBreaker(
                feed_id=feed_id, config=self._config
            )
        return self._breakers[feed_id]

    def drop(self, feed_id: str) -> None:
        """Remove the breaker for a feed that has been disabled at runtime."""
        self._breakers.pop(feed_id, None)

    def all_states(self) -> dict[str, CircuitState]:
        """Return a snapshot of the current state for every known feed."""
        return {feed_id: br.state for feed_id, br in self._breakers.items()}
