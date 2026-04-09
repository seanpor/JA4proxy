"""Phase 85 — unit tests for ``analytics.ti_feeds.circuit_breaker``.

Verifies the per-feed CLOSED → OPEN → HALF-OPEN state machine described
in PHASE_85.md §5.4. Uses the ``mock_monotonic`` fixture from conftest to
control elapsed time deterministically.

These tests are RED until ``src/analytics/ti_feeds/circuit_breaker.py`` exists.
"""

from __future__ import annotations

import pytest


def _import_breaker():
    from src.analytics.ti_feeds.circuit_breaker import CircuitBreaker, CircuitState

    return CircuitBreaker, CircuitState


# ── Initial state ─────────────────────────────────────────────────────────────


def test_breaker_starts_closed():
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=3, open_timeout_s=600)
    assert cb.state == CircuitState.CLOSED
    assert cb.allow() is True


# ── CLOSED → OPEN ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("threshold", [1, 2, 3, 5, 10])
def test_breaker_opens_after_n_consecutive_failures(threshold, mock_monotonic):
    """After exactly *threshold* failures the breaker opens."""
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=threshold, open_timeout_s=600)

    for _ in range(threshold - 1):
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow() is False


def test_breaker_failure_count_resets_on_success(mock_monotonic):
    """A success between failures resets the counter so we don't open prematurely."""
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=3, open_timeout_s=600)

    cb.record_failure()
    cb.record_failure()
    cb.record_success()
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED  # only 2 failures since reset


# ── OPEN → HALF-OPEN ──────────────────────────────────────────────────────────


def test_breaker_transitions_to_half_open_after_timeout(mock_monotonic):
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=2, open_timeout_s=600)

    mock_monotonic.set(1000.0)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow() is False  # still inside timeout

    mock_monotonic.advance(599.0)
    assert cb.allow() is False

    mock_monotonic.advance(2.0)  # past 600 s
    assert cb.allow() is True
    assert cb.state == CircuitState.HALF_OPEN


# ── HALF-OPEN → CLOSED on success ──────────────────────────────────────────────


def test_breaker_closes_on_half_open_success(mock_monotonic):
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=2, open_timeout_s=600)

    mock_monotonic.set(0.0)
    cb.record_failure()
    cb.record_failure()
    mock_monotonic.advance(601.0)
    assert cb.allow() is True  # transitions to half-open
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


# ── HALF-OPEN → OPEN on failure (resets timeout) ──────────────────────────────


def test_breaker_reopens_on_half_open_failure(mock_monotonic):
    CircuitBreaker, CircuitState = _import_breaker()
    cb = CircuitBreaker(failure_threshold=2, open_timeout_s=600)

    mock_monotonic.set(0.0)
    cb.record_failure()
    cb.record_failure()
    mock_monotonic.advance(601.0)
    assert cb.allow() is True
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    # New OPEN must start a new timeout window
    mock_monotonic.advance(599.0)
    assert cb.allow() is False
    mock_monotonic.advance(2.0)
    assert cb.allow() is True  # enters half-open again


# ── State name as Prometheus value (0/1/2) ────────────────────────────────────


def test_circuit_state_has_prometheus_int_values():
    """Per PHASE_85.md §10.1: 0=closed, 1=half_open, 2=open."""
    CircuitBreaker, CircuitState = _import_breaker()
    assert int(CircuitState.CLOSED) == 0
    assert int(CircuitState.HALF_OPEN) == 1
    assert int(CircuitState.OPEN) == 2
