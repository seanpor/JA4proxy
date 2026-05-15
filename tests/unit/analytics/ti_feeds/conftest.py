"""Shared fixtures for Phase 85 — `analytics.ti_feeds.*` unit tests.

These fixtures are used red — the production modules under
`src/analytics/ti_feeds/` do not yet exist, so any test that imports them is
expected to fail at collection or first call. The coder agent will turn the
failures green in a follow-up round.

Provided fixtures
-----------------
- ``fakeredis_factory`` — yields fakeredis.FakeRedis instances suitable for
  driving the ``ti_feed:*`` sidecar index.
- ``stix_bundle`` — the canned STIX 2.1 bundle from
  ``tests/fixtures/ti_feeds/sample_stix_bundle.json``.
- ``stix_bundle_with_ja4_only`` — same bundle filtered to JA4 indicators.
- ``mock_taxii_server`` — factory that returns a stub TAXII 2.1 server.
- ``stub_management_client`` — minimal in-memory stub for the
  ``analytics.ti_feeds.mgmt_client.ManagementClient`` interface.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

# fakeredis is already a project test dependency (used by tests/unit/test_gdpr_delete.py)
import fakeredis
import pytest

_FIXTURE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "ti_feeds"
_BUNDLE_PATH = _FIXTURE_DIR / "sample_stix_bundle.json"


# ── Redis fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def fakeredis_factory():
    """Return a callable that yields independent fakeredis instances.

    Each call returns a fresh FakeRedis with ``decode_responses=True`` so that
    HGET / HSET round-trips return string keys and values, matching the way
    `analytics.ti_feeds.state.FeedState` is expected to interact with Redis.
    """
    instances: list[fakeredis.FakeRedis] = []

    def _make() -> fakeredis.FakeRedis:
        client = fakeredis.FakeRedis(decode_responses=True)
        instances.append(client)
        return client

    yield _make

    for inst in instances:
        try:
            inst.flushall()
            inst.close()
        except Exception:
            pass


@pytest.fixture
def fake_redis(fakeredis_factory):
    """Single shared fakeredis instance for tests that only need one."""
    return fakeredis_factory()


# ── STIX bundle fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def stix_bundle() -> dict[str, Any]:
    """Load the canned STIX 2.1 bundle from disk with dynamic dates.

    The bundle contains:
    - the JA4 extension-definition object
    - one ``x-ja4-fingerprint`` SCO
    - 2 JA4 indicators (one above-confidence, one Sliver)
    - 1 IPv4 indicator (above confidence)
    - 1 IPv6 indicator (above confidence)
    - 1 below-confidence IPv4 (must be skipped by the consumer)
    - 1 already-expired IPv4 (must be filtered out)

    Dates are patched at load time so tests don't go stale:
    - valid_from: 30 days ago
    - valid_until (valid): 365 days from now
    - valid_until (expired): 90 days ago
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    one_year_ahead = now + timedelta(days=365)
    ninety_days_ago = now - timedelta(days=90)

    fmt = "%Y-%m-%dT%H:%M:%SZ"

    if not _BUNDLE_PATH.exists():
        raise FileNotFoundError(
            f"STIX fixture missing: {_BUNDLE_PATH}. "
            "tests/fixtures/ti_feeds/sample_stix_bundle.json must be committed."
        )
    bundle = json.loads(_BUNDLE_PATH.read_text())

    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue

        obj["valid_from"] = thirty_days_ago.strftime(fmt)

        indicator_id = obj.get("id", "")
        if indicator_id == "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee2":
            obj["valid_until"] = one_year_ahead.strftime(fmt)
        elif indicator_id == "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeee5":
            obj["valid_until"] = ninety_days_ago.strftime(fmt)
        elif "valid_until" in obj:
            obj["valid_until"] = one_year_ahead.strftime(fmt)

    return bundle


@pytest.fixture
def stix_indicators_only(stix_bundle) -> list[dict[str, Any]]:
    """Return only the indicator objects from the bundle, in document order."""
    return [obj for obj in stix_bundle["objects"] if obj.get("type") == "indicator"]


@pytest.fixture
def stix_bundle_ja4_only(stix_indicators_only) -> list[dict[str, Any]]:
    """Return only the JA4-pattern indicators from the bundle."""
    pat = re.compile(r"\[x-ja4-fingerprint:value = '")
    return [ind for ind in stix_indicators_only if pat.search(ind.get("pattern", ""))]


@pytest.fixture
def stix_bundle_ip_only(stix_indicators_only) -> list[dict[str, Any]]:
    """Return only the IP-pattern indicators from the bundle."""
    pat = re.compile(r"\[ipv[46]-addr:value = '")
    return [ind for ind in stix_indicators_only if pat.search(ind.get("pattern", ""))]


# ── Mock TAXII server factory ──────────────────────────────────────────────────

# phase-85: stub classes live in tests/_helpers/ti_feed_stubs.py so the
# adversarial and chaos test subtrees can import them too. Re-exported here
# under their original names for backwards compatibility with existing
# imports inside this conftest module.
from tests._helpers.ti_feed_stubs import (  # noqa: E402
    StubManagementClient,
    StubTAXIIServer,
)


@pytest.fixture
def mock_taxii_server():
    """Factory returning ``StubTAXIIServer`` instances."""

    def _make(bundle: Optional[dict[str, Any]] = None) -> StubTAXIIServer:
        return StubTAXIIServer(bundle)

    return _make


# ── Stub Management API client ─────────────────────────────────────────────────


@pytest.fixture
def stub_management_client():
    """Return a fresh in-memory stub for the Management API client."""
    return StubManagementClient()


# ── Mock clock helper ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_monotonic(monkeypatch):
    """Replace ``time.monotonic`` with a controllable counter for circuit-breaker tests."""
    state = {"value": 0.0}

    def _set(seconds: float) -> None:
        state["value"] = float(seconds)

    def _advance(seconds: float) -> None:
        state["value"] += float(seconds)

    def _now() -> float:
        return state["value"]

    monkeypatch.setattr("time.monotonic", _now)

    class Clock:
        set = staticmethod(_set)
        advance = staticmethod(_advance)
        now = staticmethod(_now)

    return Clock()


# ── Dynamic date helpers for self-maintaining tests ─────────────────────────────


def _utc_now() -> Any:
    """Lazy import to avoid issues if called before datetime is needed."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def dynamic_valid_from(days_ago: int = 30) -> str:
    """Return ``valid_from`` date as ISO string, N days in the past."""
    from datetime import timedelta

    return (_utc_now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def dynamic_valid_until(days_ahead: int = 365) -> str:
    """Return ``valid_until`` date as ISO string, N days in the future."""
    from datetime import timedelta

    return (_utc_now() + timedelta(days=days_ahead)).strftime("%Y-%m-%dT%H:%M:%SZ")


def dynamic_expired(days_ago: int = 90) -> str:
    """Return an already-expired ``valid_until`` date as ISO string."""
    from datetime import timedelta

    return (_utc_now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
