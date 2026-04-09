"""Phase 85 — adversarial test for very large STIX bundles.

A feed returns 10,000 indicators. Acceptance criterion §12.3:
- The poll completes in under 60 s.
- 50-batch pacing is observable in the timing profile.
- No single batch exceeds 50 indicators.

These tests are RED until the production poller exists.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

# phase-85: H1 closed (commit 5223cdc) — feed clients now expose
# HTTP-layer DI seams; the shared stubs were extracted to
# tests/_helpers/ti_feed_stubs.py and re-exposed via
# tests/adversarial/conftest.py.
_ = pytest  # noqa: F841 — keep import marker active


def _run(coro):
    return asyncio.run(coro)


def _import_taxii():
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return TAXIIClient


def _make_config():
    from src.analytics.ti_feeds.base import FeedConfig

    return FeedConfig(
        id="huge",
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


class _StubServer:
    def __init__(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle

    async def get_objects(self, collection_id: str, added_after=None, **kwargs):
        return self._bundle


def _make_huge_bundle(n: int = 10_000) -> dict[str, Any]:
    objects = []
    for i in range(n):
        # IPv4 in TEST-NET-2 (198.51.100.0/24) extended deterministically
        a = (i // 65536) % 256
        b = (i // 256) % 256
        c = i % 256
        ip = f"198.51.{a}.{b}" if a != 0 else f"198.51.100.{c}"
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--huge-{i:06d}",
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "confidence": 90,
                "valid_from": "2026-04-01T00:00:00Z",
            }
        )
    return {"type": "bundle", "id": "bundle--huge", "objects": objects}


@pytest.mark.adversarial
def test_10k_bundle_completes_under_60s(stub_management_client):
    TAXIIClient = _import_taxii()
    bundle = _make_huge_bundle(10_000)
    server = _StubServer(bundle)

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )

    started = time.monotonic()
    result = _run(client.poll())
    elapsed = time.monotonic() - started

    assert elapsed < 60.0, f"10k poll took {elapsed:.1f}s; budget is 60s"
    assert result.poll_duration_s < 60.0


@pytest.mark.adversarial
def test_500_indicator_bundle_produces_500_post_calls(stub_management_client):
    """A 500-entry STIX bundle produces exactly 500 mgmt POSTs.

    The 50-per-batch / 50ms-inter-batch pacing contract from
    PHASE_85.md §2.5 is asserted directly in
    ``tests/unit/analytics/ti_feeds/test_mgmt_client.py
    ::test_bulk_blocklist_paces_50_per_batch``. This test only
    asserts the 1-to-1 indicator-to-POST mapping at scale — earlier
    versions added a trailing ``assert True`` and named themselves
    ``test_no_batch_exceeds_50_indicators``, which was a lie about
    what they actually checked.
    """
    TAXIIClient = _import_taxii()
    bundle = _make_huge_bundle(500)
    server = _StubServer(bundle)

    client = TAXIIClient(
        config=_make_config(),
        mgmt=stub_management_client,
        state=None,
        taxii=server,
    )
    _run(client.poll())

    bans = [r for r in stub_management_client.requests if r["method"] == "POST"]
    assert len(bans) == 500
