"""Phase 85 — chaos test: TAXII server unavailable.

Failure scenario: the TAXII server returns HTTP 503 for 5 consecutive polls.

Expected behaviour:
- Each failure increments the ``failure_count`` and eventually trips the
  circuit breaker CLOSED → OPEN.
- ``ja4proxy_ti_feed_circuit_state`` gauge reads ``2`` (OPEN).
- Subsequent polls are skipped (logged as ``poll.skipped`` with
  ``result="circuit_open"``) until the OPEN timeout expires.

These tests are RED until the runner + circuit breaker exist.
"""

from __future__ import annotations

import asyncio
from typing import Any

import fakeredis
import pytest


def _run(coro):
    return asyncio.run(coro)


def _import_pieces():
    from analytics.ti_feeds.base import FeedConfig
    from analytics.ti_feeds.circuit_breaker import CircuitBreaker, CircuitState
    from analytics.ti_feeds.runner import FeedRunner
    from analytics.ti_feeds.state import FeedState
    from analytics.ti_feeds.taxii import TAXIIClient

    return FeedConfig, CircuitBreaker, CircuitState, FeedRunner, FeedState, TAXIIClient


class _FailingServer:
    def __init__(self, status: int = 503) -> None:
        self.status = status
        self.calls = 0

    async def get_objects(self, collection_id: str, added_after=None, **kwargs):
        self.calls += 1
        err = RuntimeError(f"HTTP {self.status}")
        err.status = self.status  # type: ignore[attr-defined]
        raise err


@pytest.mark.chaos
def test_circuit_opens_after_5_failed_polls(stub_management_client):
    (
        FeedConfig,
        CircuitBreaker,
        CircuitState,
        FeedRunner,
        FeedState,
        TAXIIClient,
    ) = _import_pieces()

    redis = fakeredis.FakeRedis(decode_responses=True)
    state = FeedState(redis)
    server = _FailingServer(status=503)

    cfg = FeedConfig(
        id="flaky",
        type="taxii2",
        url="https://flaky/",
        collection_id="x",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=70,
        ban_ttl_hours=168,
    )

    breaker = CircuitBreaker(failure_threshold=3, open_timeout_s=600)
    client = TAXIIClient(
        config=cfg,
        mgmt=stub_management_client,
        state=state,
        taxii=server,
        breaker=breaker,
    )

    runner = FeedRunner(feeds=[client], state=state)

    for _ in range(5):
        _run(runner.run_once())

    # After 5 failures the breaker must be OPEN.
    assert breaker.state == CircuitState.OPEN

    # Prometheus gauge reflects OPEN (2)
    from prometheus_client import REGISTRY

    found = False
    for sample in REGISTRY.collect():
        for s in getattr(sample, "samples", []):
            if s.name == "ja4proxy_ti_feed_circuit_state":
                if s.labels.get("feed_id") == "flaky":
                    assert int(s.value) == 2
                    found = True
    assert found, "ja4proxy_ti_feed_circuit_state gauge not exposed"


@pytest.mark.chaos
def test_subsequent_polls_skipped_while_open(stub_management_client):
    (
        FeedConfig,
        CircuitBreaker,
        CircuitState,
        FeedRunner,
        FeedState,
        TAXIIClient,
    ) = _import_pieces()

    redis = fakeredis.FakeRedis(decode_responses=True)
    state = FeedState(redis)
    server = _FailingServer(status=503)
    cfg = FeedConfig(
        id="flaky2",
        type="taxii2",
        url="https://flaky/",
        collection_id="x",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=70,
        ban_ttl_hours=168,
    )
    breaker = CircuitBreaker(failure_threshold=3, open_timeout_s=600)
    client = TAXIIClient(
        config=cfg,
        mgmt=stub_management_client,
        state=state,
        taxii=server,
        breaker=breaker,
    )
    runner = FeedRunner(feeds=[client], state=state)

    for _ in range(3):
        _run(runner.run_once())
    calls_when_opened = server.calls

    # Next 10 polls must not hit the server at all
    for _ in range(10):
        _run(runner.run_once())
    assert server.calls == calls_when_opened
