"""Phase 85 — unit tests for ``analytics.ti_feeds.base``.

Verifies the ``FeedClient`` ABC contract and the ``FeedPollResult`` dataclass
serialisation round-trip.

These tests are RED until ``src/analytics/ti_feeds/base.py`` exists.
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses

import pytest


def test_feed_poll_result_can_be_imported():
    """The dataclass exists at the documented import path."""
    from src.analytics.ti_feeds.base import FeedPollResult  # noqa: F401

    assert dataclasses.is_dataclass(FeedPollResult)


def test_feed_poll_result_has_required_fields():
    """FeedPollResult exposes all fields enumerated in PHASE_85.md §5.2."""
    from src.analytics.ti_feeds.base import FeedPollResult

    field_names = {f.name for f in dataclasses.fields(FeedPollResult)}
    required = {
        "feed_id",
        "stix_ids_seen",
        "created",
        "skipped_below_confidence",
        "errors",
        "poll_duration_s",
    }
    missing = required - field_names
    assert not missing, f"FeedPollResult missing fields: {missing}"


def test_feed_poll_result_round_trip():
    """A FeedPollResult constructed by-name preserves all values."""
    from src.analytics.ti_feeds.base import FeedPollResult

    result = FeedPollResult(
        feed_id="taxii-isac",
        stix_ids_seen={"indicator--aaaa", "indicator--bbbb"},
        created=[("indicator--aaaa", "uuid-1"), ("indicator--bbbb", "1.2.3.4")],
        skipped_below_confidence=2,
        errors=["one bad indicator"],
        poll_duration_s=0.42,
    )
    assert result.feed_id == "taxii-isac"
    assert result.stix_ids_seen == {"indicator--aaaa", "indicator--bbbb"}
    assert ("indicator--aaaa", "uuid-1") in result.created
    assert result.skipped_below_confidence == 2
    assert result.errors == ["one bad indicator"]
    assert result.poll_duration_s == pytest.approx(0.42)


def test_feed_client_is_abstract():
    """FeedClient is an ABC and cannot be instantiated directly."""
    from src.analytics.ti_feeds.base import FeedClient

    assert inspect_abstract(FeedClient)
    # Direct instantiation must fail
    with pytest.raises(TypeError):
        FeedClient(config=None, mgmt=None, state=None)  # type: ignore[call-arg]


def inspect_abstract(cls) -> bool:
    """Helper: returns True iff *cls* declares at least one abstract method."""
    return bool(getattr(cls, "__abstractmethods__", set()))


def test_feed_client_poll_is_abstract():
    """``poll()`` is enforced abstract on the base class."""
    from src.analytics.ti_feeds.base import FeedClient

    assert "poll" in getattr(FeedClient, "__abstractmethods__", set())


def test_feed_client_subclass_must_implement_poll():
    """A subclass that omits ``poll`` cannot be instantiated."""
    from src.analytics.ti_feeds.base import FeedClient

    class IncompleteFeed(FeedClient):  # type: ignore[misc]
        pass

    with pytest.raises(TypeError):
        IncompleteFeed(config=None, mgmt=None, state=None)  # type: ignore[call-arg]


def test_feed_client_subclass_with_poll_can_be_instantiated():
    """A correctly-implemented subclass can be constructed and poll() awaited."""
    from src.analytics.ti_feeds.base import FeedClient, FeedPollResult

    class GoodFeed(FeedClient):  # type: ignore[misc]
        async def poll(self) -> FeedPollResult:  # type: ignore[override]
            return FeedPollResult(
                feed_id="good",
                stix_ids_seen=set(),
                created=[],
                skipped_below_confidence=0,
                errors=[],
                poll_duration_s=0.0,
            )

    feed = GoodFeed(config=None, mgmt=None, state=None)  # type: ignore[call-arg]
    result = asyncio.run(feed.poll())
    assert result.feed_id == "good"
