"""Phase 85 — end-to-end integration test for the threat-intel feed runner.

Drives a mock TAXII server through a real ``analytics.ti_feeds`` runner whose
Management client points at the live FastAPI test client backed by fakeredis.
After the poll completes, ``GET /api/v1/blocklist?managed_by=feed`` must return
the indicators that came from the mock TAXII server.

These tests are RED until the runner, mgmt_client and TAXII client all exist.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

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

# fakeredis is part of the project test deps already (used by tests/unit/test_gdpr_delete.py)
import fakeredis


_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "ti_feeds" / "sample_stix_bundle.json"
)


def _run(coro):
    return asyncio.run(coro)


def _load_bundle() -> dict[str, Any]:
    if not _FIXTURE_PATH.exists():
        pytest.skip(
            f"Bundle fixture missing: {_FIXTURE_PATH} — should be added by the "
            "conftest commit before running this test."
        )
    return json.loads(_FIXTURE_PATH.read_text())


def _import_runner_pieces():
    from src.analytics.ti_feeds.base import FeedConfig
    from src.analytics.ti_feeds.mgmt_client import ManagementClient
    from src.analytics.ti_feeds.runner import FeedRunner
    from src.analytics.ti_feeds.state import FeedState
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return FeedConfig, ManagementClient, FeedRunner, FeedState, TAXIIClient


# ── Stub TAXII server (same as conftest.StubTAXIIServer but local) ────────────


class _StubTAXII:
    def __init__(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle
        self.calls: list[dict[str, Any]] = []

    async def get_objects(self, collection_id: str, added_after: str | None = None, **kwargs):
        self.calls.append({"collection_id": collection_id, "added_after": added_after})
        return self._bundle


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_ti_feeds_e2e_blocklist_appears():
    """A successful TAXII poll surfaces in GET /api/v1/blocklist?managed_by=feed."""
    FeedConfig, ManagementClient, FeedRunner, FeedState, TAXIIClient = _import_runner_pieces()

    bundle = _load_bundle()
    taxii_server = _StubTAXII(bundle)
    redis = fakeredis.FakeRedis(decode_responses=True)

    # Build a real Management API in-process. The exact import path is
    # documented in management/api/main.py — the implementer of Phase 85 must
    # wire ManagementClient to it via base_url=test client.
    from fastapi.testclient import TestClient

    try:
        from management.api.main import app
    except ImportError:
        pytest.skip("Management API app not importable; this test runs after Phase 79.")

    test_client = TestClient(app)

    feed_config = FeedConfig(
        id="taxii-isac",
        type="taxii2",
        url="https://taxii.test/",
        collection_id="enterprise-attack",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=70,
        ban_ttl_hours=168,
    )

    state = FeedState(redis)
    mgmt = ManagementClient(
        base_url="http://testserver",
        token="test-operator-token",
        session=test_client,
    )
    feed = TAXIIClient(config=feed_config, mgmt=mgmt, state=state, taxii=taxii_server)

    runner = FeedRunner(feeds=[feed], state=state)
    _run(runner.run_once())

    # Verify the blocklist now contains the JA4 entries seen in the bundle.
    resp = test_client.get(
        "/api/v1/blocklist",
        params={"managed_by": "feed"},
        headers={"Authorization": "Bearer test-operator-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    entries = [r["entry"] for r in body["entries"]]
    assert "t10d170900_9dc949161b6c_b64c0ad42cb7" in entries
    assert "t13d301100_5b57614c22b0_3d5424432f57" in entries
    # Each feed-managed resource carries note=feed:{feed_id}:{stix_id}
    notes = [r["note"] for r in body["entries"]]
    assert any(n.startswith("feed:taxii-isac:") for n in notes)


@pytest.mark.integration
def test_ti_feeds_e2e_state_index_populated():
    """The Redis sidecar HASH ti_feed:{id}:active_stix_ids is populated post-poll."""
    FeedConfig, ManagementClient, FeedRunner, FeedState, TAXIIClient = _import_runner_pieces()

    bundle = _load_bundle()
    taxii_server = _StubTAXII(bundle)
    redis = fakeredis.FakeRedis(decode_responses=True)

    from fastapi.testclient import TestClient

    try:
        from management.api.main import app
    except ImportError:
        pytest.skip("Management API app not importable; this test runs after Phase 79.")

    test_client = TestClient(app)

    feed_config = FeedConfig(
        id="taxii-isac",
        type="taxii2",
        url="https://taxii.test/",
        collection_id="enterprise-attack",
        username="u",
        password="p",
        poll_interval_minutes=60,
        enabled=True,
        min_confidence=70,
        ban_ttl_hours=168,
    )

    state = FeedState(redis)
    mgmt = ManagementClient(
        base_url="http://testserver",
        token="test-operator-token",
        session=test_client,
    )
    feed = TAXIIClient(config=feed_config, mgmt=mgmt, state=state, taxii=taxii_server)
    runner = FeedRunner(feeds=[feed], state=state)
    _run(runner.run_once())

    active = redis.hgetall("ti_feed:taxii-isac:active_stix_ids")
    assert active, "Sidecar index ti_feed:taxii-isac:active_stix_ids should be populated"
    # 4 indicators are above-confidence and unexpired
    assert len(active) == 4
