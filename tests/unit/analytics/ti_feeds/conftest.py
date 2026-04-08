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

import pytest

# fakeredis is already a project test dependency (used by tests/unit/test_gdpr_delete.py)
import fakeredis


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
    """Load the canned STIX 2.1 bundle from disk.

    The bundle contains:
    - the JA4 extension-definition object
    - one ``x-ja4-fingerprint`` SCO
    - 2 JA4 indicators (one above-confidence, one Sliver)
    - 1 IPv4 indicator (above confidence)
    - 1 IPv6 indicator (above confidence)
    - 1 below-confidence IPv4 (must be skipped by the consumer)
    - 1 already-expired IPv4 (must be filtered out)
    """
    if not _BUNDLE_PATH.exists():
        raise FileNotFoundError(
            f"STIX fixture missing: {_BUNDLE_PATH}. "
            "tests/fixtures/ti_feeds/sample_stix_bundle.json must be committed."
        )
    return json.loads(_BUNDLE_PATH.read_text())


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


class StubTAXIIServer:
    """Minimal stand-in for a TAXII 2.1 server.

    The class records every call made to it and returns whichever bundle was
    most recently configured. The Phase 85 ``analytics.ti_feeds.taxii``
    client should be able to drive this object via injection in unit tests
    without an aiohttp listener.
    """

    def __init__(self, bundle: Optional[dict[str, Any]] = None) -> None:
        self._bundle = bundle or {"type": "bundle", "id": "bundle--empty", "objects": []}
        self.calls: list[dict[str, Any]] = []
        self._next_status: int = 200
        self._error_count_remaining: int = 0
        self._error_status: int = 503

    def set_bundle(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle

    def set_objects(self, objects: list[dict[str, Any]]) -> None:
        self._bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": objects,
        }

    def fail_n_times(self, n: int, status: int = 503) -> None:
        """Configure the next *n* calls to return ``status`` instead of the bundle."""
        self._error_count_remaining = n
        self._error_status = status

    async def get_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Return the configured bundle, or raise on configured failures."""
        self.calls.append(
            {
                "collection_id": collection_id,
                "added_after": added_after,
                "kwargs": kwargs,
            }
        )
        if self._error_count_remaining > 0:
            self._error_count_remaining -= 1
            err = RuntimeError(f"TAXII server returned HTTP {self._error_status}")
            err.status = self._error_status  # type: ignore[attr-defined]
            raise err
        return self._bundle


@pytest.fixture
def mock_taxii_server():
    """Factory returning ``StubTAXIIServer`` instances."""

    def _make(bundle: Optional[dict[str, Any]] = None) -> StubTAXIIServer:
        return StubTAXIIServer(bundle)

    return _make


# ── Stub Management API client ─────────────────────────────────────────────────


class StubManagementClient:
    """In-memory stub mirroring the Phase 85 ``ManagementClient`` interface.

    The real client is ``src.analytics.ti_feeds.mgmt_client.ManagementClient``.
    This stub records every call and pretends every POST succeeds with a
    new UUID. Signatures must match the production client exactly so the
    feed clients exercise the same call sites in tests as in production.
    """

    def __init__(self) -> None:
        self.bans: dict[str, dict[str, Any]] = {}
        self.blocklist: dict[str, dict[str, Any]] = {}
        self.requests: list[dict[str, Any]] = []
        self._next_status_for_path: dict[str, int] = {}
        self._uuid_counter: int = 0

    # ----- helpers --------------------------------------------------------

    def fail_path(self, method: str, path: str, status: int) -> None:
        self._next_status_for_path[f"{method.upper()} {path}"] = status

    # ----- ban endpoints --------------------------------------------------

    async def post_ban(
        self,
        ip: str,
        *,
        feed_id: str,
        ttl_s: int,
        reason: str,
    ) -> None:
        path = f"/api/v1/bans/{ip}"
        self.requests.append(
            {
                "method": "POST",
                "path": path,
                "feed_id": feed_id,
                "ttl_s": ttl_s,
                # Back-compat alias for older tests that read r["ttl"].
                "ttl": ttl_s,
                "reason": reason,
            }
        )
        forced = self._next_status_for_path.pop(f"POST {path}", None)
        if forced and forced >= 400:
            err = RuntimeError(f"HTTP {forced}")
            err.status = forced  # type: ignore[attr-defined]
            raise err
        self.bans[ip] = {"feed_id": feed_id, "ttl_s": ttl_s, "reason": reason}

    async def delete_ban(self, ip: str, *, feed_id: str) -> None:
        self.requests.append(
            {
                "method": "DELETE",
                "path": f"/api/v1/bans/{ip}",
                "feed_id": feed_id,
            }
        )
        self.bans.pop(ip, None)

    # ----- blocklist endpoints --------------------------------------------

    async def post_blocklist(
        self,
        *,
        feed_id: str,
        entry: str,
        note: str,
        expires_at: Optional[str] = None,
    ) -> Any:
        self.requests.append(
            {
                "method": "POST",
                "path": "/api/v1/blocklist",
                "feed_id": feed_id,
                "entry": entry,
                # Production hard-codes managed_by="feed"; record it for the
                # benefit of tests that assert provenance.
                "managed_by": "feed",
                "note": note,
                "expires_at": expires_at,
            }
        )
        # Idempotent: if same entry already exists, return that record.
        for record in self.blocklist.values():
            if record.entry == entry:
                return record
        self._uuid_counter += 1
        rid = f"00000000-0000-0000-0000-{self._uuid_counter:012d}"
        # Build the same envelope production returns. Imported lazily so
        # the conftest still loads when ti_feeds isn't on the path.
        from src.analytics.ti_feeds.mgmt_client import ResourceResult

        record = ResourceResult(
            id=rid,
            entry=entry,
            managed_by="feed",
            note=note,
        )
        self.blocklist[rid] = record
        return record

    async def delete_blocklist(self, resource_id: str, *, feed_id: str) -> None:
        self.requests.append(
            {
                "method": "DELETE",
                "path": f"/api/v1/blocklist/{resource_id}",
                "feed_id": feed_id,
            }
        )
        self.blocklist.pop(resource_id, None)

    async def list_blocklist(self, managed_by: Optional[str] = None) -> list[Any]:
        if managed_by is None:
            return list(self.blocklist.values())
        return [r for r in self.blocklist.values() if r.managed_by == managed_by]


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
