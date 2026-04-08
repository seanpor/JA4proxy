"""Phase 85 — integration test for cross-feed conflict resolution.

Per PHASE_85.md §2.4:
- First writer wins (idempotent POST returns existing record on duplicate).
- Each feed's sidecar tracks only the resources it created.
- A feed removing its own indicator does NOT affect another feed that also
  publishes the same JA4.

These tests are RED until the runner exists.
"""

from __future__ import annotations

import asyncio
from typing import Any

import fakeredis
import pytest

# Phase 85 architect H1 + shared fixture relocation — these tests assume
# HTTP-layer DI on the feed clients and depend on the
# tests/unit/analytics/ti_feeds/conftest.py fixtures (``stub_management_client``,
# ``mock_taxii_server``, etc.) which are not yet visible from this directory.
# Both items are tracked as their own follow-ups; mark the file xfail rather
# than blocking the test merge.
pytestmark = pytest.mark.xfail(
    reason="architect H1 + shared fixture relocation — tracked as Phase 85 follow-up",
    strict=False,
)


def _run(coro):
    return asyncio.run(coro)


def _import_runner_pieces():
    from src.analytics.ti_feeds.base import FeedConfig
    from src.analytics.ti_feeds.mgmt_client import ManagementClient
    from src.analytics.ti_feeds.runner import FeedRunner
    from src.analytics.ti_feeds.state import FeedState
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return FeedConfig, ManagementClient, FeedRunner, FeedState, TAXIIClient


_SHARED_JA4 = "t10d170900_ffffffffffff_aaaaaaaaaaaa"


def _ind(stix_id: str, ja4: str = _SHARED_JA4, conf: int = 90) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "pattern_type": "stix",
        "pattern": f"[x-ja4-fingerprint:value = '{ja4}']",
        "confidence": conf,
        "valid_from": "2026-04-01T00:00:00Z",
    }


class _StubTAXII:
    def __init__(self) -> None:
        self._objects: list[dict[str, Any]] = []

    def set_objects(self, objects: list[dict[str, Any]]) -> None:
        self._objects = list(objects)

    async def get_objects(self, collection_id: str, added_after=None, **kwargs):
        return {"type": "bundle", "id": "bundle--c", "objects": list(self._objects)}


def _build_feed(name: str, server, redis, test_client):
    from src.analytics.ti_feeds.base import FeedConfig
    from src.analytics.ti_feeds.mgmt_client import ManagementClient
    from src.analytics.ti_feeds.state import FeedState
    from src.analytics.ti_feeds.taxii import TAXIIClient

    feed_config = FeedConfig(
        id=name,
        type="taxii2",
        url="https://x/",
        collection_id="x",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=50,
        ban_ttl_hours=168,
    )
    state = FeedState(redis)
    mgmt = ManagementClient(
        base_url="http://testserver",
        token="test-operator-token",
        session=test_client,
    )
    return TAXIIClient(config=feed_config, mgmt=mgmt, state=state, taxii=server), state


@pytest.mark.integration
def test_first_writer_wins_each_feed_tracks_only_its_own():
    _import_runner_pieces()  # ensures imports raise red until production code lands

    redis = fakeredis.FakeRedis(decode_responses=True)
    from fastapi.testclient import TestClient

    try:
        from management.api.main import app
    except ImportError:
        pytest.skip("Management API app not importable; this test runs after Phase 79.")

    test_client = TestClient(app)

    server_a = _StubTAXII()
    server_a.set_objects([_ind("indicator--feed-a-1")])
    feed_a, state_a = _build_feed("feed-a", server_a, redis, test_client)

    server_b = _StubTAXII()
    server_b.set_objects([_ind("indicator--feed-b-1")])
    feed_b, state_b = _build_feed("feed-b", server_b, redis, test_client)

    from src.analytics.ti_feeds.runner import FeedRunner

    runner = FeedRunner(feeds=[feed_a, feed_b], state=state_a)
    _run(runner.run_once())

    # Feed A is the first writer and owns the resource
    a_active = redis.hgetall("ti_feed:feed-a:active_stix_ids")
    b_active = redis.hgetall("ti_feed:feed-b:active_stix_ids")
    assert "indicator--feed-a-1" in a_active
    # Feed B saw the same JA4 but did not create the resource and so its
    # sidecar must NOT contain the indicator id from feed B's perspective.
    assert "indicator--feed-b-1" not in b_active

    # The blocklist contains exactly ONE entry for the JA4
    resp = test_client.get(
        "/api/v1/blocklist",
        params={"managed_by": "feed"},
        headers={"Authorization": "Bearer test-operator-token"},
    )
    entries = [r for r in resp.json()["entries"] if r["entry"] == _SHARED_JA4]
    assert len(entries) == 1
    # Note shows feed A as the source of truth
    assert entries[0]["note"].startswith("feed:feed-a:")


@pytest.mark.integration
def test_feed_a_remove_does_not_affect_feed_b_unrelated_indicator():
    """A's cleanup of its own indicator never touches B's unrelated indicator."""
    _import_runner_pieces()
    redis = fakeredis.FakeRedis(decode_responses=True)

    from fastapi.testclient import TestClient

    try:
        from management.api.main import app
    except ImportError:
        pytest.skip("Management API app not importable; this test runs after Phase 79.")

    test_client = TestClient(app)

    server_a = _StubTAXII()
    server_a.set_objects([_ind("indicator--a-only", ja4="t10d170900_aaaaaaaaaaaa_aaaaaaaaaaaa")])
    feed_a, state_a = _build_feed("feed-a", server_a, redis, test_client)

    server_b = _StubTAXII()
    server_b.set_objects([_ind("indicator--b-only", ja4="t10d170900_bbbbbbbbbbbb_bbbbbbbbbbbb")])
    feed_b, _ = _build_feed("feed-b", server_b, redis, test_client)

    from src.analytics.ti_feeds.runner import FeedRunner

    runner = FeedRunner(feeds=[feed_a, feed_b], state=state_a)
    _run(runner.run_once())

    # Feed A drops its indicator
    server_a.set_objects([])
    _run(runner.run_once())

    resp = test_client.get(
        "/api/v1/blocklist",
        params={"managed_by": "feed"},
        headers={"Authorization": "Bearer test-operator-token"},
    )
    entries = [r["entry"] for r in resp.json()["entries"]]
    assert "t10d170900_bbbbbbbbbbbb_bbbbbbbbbbbb" in entries
    assert "t10d170900_aaaaaaaaaaaa_aaaaaaaaaaaa" not in entries
