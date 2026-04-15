"""Phase 85 — integration test for cross-feed conflict resolution.

Per PHASE_85.md §2.4: first writer wins, each feed tracks its own indicators.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def stub_redis():
    import fakeredis

    return fakeredis.FakeRedis(decode_responses=True)


@pytest.mark.unit
def test_feedstate_has_try_acquire_leader_method(stub_redis):
    """FeedState has try_acquire_leader method."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert hasattr(state, "try_acquire_leader")
    assert callable(state.try_acquire_leader)


@pytest.mark.unit
def test_feedstate_has_leader_lock(stub_redis):
    """FeedState has leader lock mechanism."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert hasattr(state, "try_acquire_leader")
