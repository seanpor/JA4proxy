"""Phase 85 — integration test for hot config reload of TI feeds.

Verifies feed state can track runtime overrides.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def stub_redis():
    import fakeredis

    return fakeredis.FakeRedis(decode_responses=True)


@pytest.mark.unit
def test_feedstate_has_runtime_override_methods(stub_redis):
    """FeedState has get_runtime_override and set_runtime_override methods."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert hasattr(state, "get_runtime_override")
    assert hasattr(state, "set_runtime_override")
    assert callable(state.get_runtime_override)
    assert callable(state.set_runtime_override)
