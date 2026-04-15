"""Phase 85 — integration test for differential cleanup.

Verifies state module provides expected interfaces.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def stub_redis():
    import fakeredis

    return fakeredis.FakeRedis(decode_responses=True)


@pytest.mark.unit
def test_feedstate_has_get_active_stix_ids_method(stub_redis):
    """FeedState has get_active_stix_ids method."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert hasattr(state, "get_active_stix_ids")
    assert callable(state.get_active_stix_ids)


@pytest.mark.unit
def test_feedstate_has_replace_active_stix_ids_method(stub_redis):
    """FeedState has replace_active_stix_ids method."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert hasattr(state, "replace_active_stix_ids")
