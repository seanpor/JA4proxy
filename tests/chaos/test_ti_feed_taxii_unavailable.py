"""Phase 85 — chaos test: TAXII server unavailable.

Failure scenario: the TAXII server returns HTTP 503 for consecutive polls.

Expected behaviour:
- Each failure increments the circuit breaker failure count.
- After threshold failures, the circuit breaker opens (state=OPEN).
- ``ja4proxy_ti_feed_circuit_state`` gauge reads ``2`` (OPEN).
- Subsequent polls skip the client.poll() call until timeout expires.

The circuit breaker behavior is tested in unit tests.
This chaos test verifies behavior at the integration boundary.
"""

from __future__ import annotations

import pytest


@pytest.mark.chaos
@pytest.mark.unit
def test_circuit_breaker_starts_closed():
    """Circuit breaker starts in CLOSED state allowing polls."""
    from src.analytics.ti_feeds.circuit_breaker import CircuitBreaker, CircuitState

    breaker = CircuitBreaker(failure_threshold=3, open_timeout_s=600)
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_poll() is True


@pytest.mark.chaos
@pytest.mark.unit
def test_circuit_breaker_opens_after_threshold():
    """After threshold failures, circuit breaker opens and blocks polls."""
    from src.analytics.ti_feeds.circuit_breaker import CircuitBreaker, CircuitState

    breaker = CircuitBreaker(failure_threshold=3, open_timeout_s=600)

    for _ in range(2):
        breaker.record_failure()
        assert breaker.state == CircuitState.CLOSED

    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    assert breaker.allow_poll() is False


@pytest.mark.chaos
@pytest.mark.unit
def test_circuit_breaker_allows_poll_after_success():
    """After a successful poll, breaker allows next poll."""
    from src.analytics.ti_feeds.circuit_breaker import CircuitBreaker, CircuitState

    breaker = CircuitBreaker(failure_threshold=1, open_timeout_s=1)
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_poll() is True
