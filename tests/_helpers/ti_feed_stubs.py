"""Phase 85 — shared in-memory stubs for TI feed unit/adversarial/chaos tests.

These stubs are imported by:
- ``tests/unit/analytics/ti_feeds/conftest.py`` (the original home)
- ``tests/adversarial/test_ti_feeds_credential_leak.py``
- ``tests/chaos/test_ti_feed_redis_unavailable.py``

Each callsite either consumes them directly or wraps them in a local
pytest fixture. Keeping the classes in a regular import module lets
multiple non-overlapping conftest scopes use them without resorting to
``pytest.importorskip`` tricks or duplicating the implementation.
"""

from __future__ import annotations

from typing import Any, Optional


class StubTAXIIServer:
    """Minimal stand-in for a TAXII 2.1 server.

    The class records every call made to it and returns whichever bundle
    was most recently configured. The Phase 85 ``analytics.ti_feeds.taxii``
    client drives this object via injection in unit tests without an
    aiohttp listener.
    """

    def __init__(self, bundle: Optional[dict[str, Any]] = None) -> None:
        self._bundle = bundle or {
            "type": "bundle",
            "id": "bundle--empty",
            "objects": [],
        }
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


class StubManagementClient:
    """In-memory stub mirroring the Phase 85 ``ManagementClient`` interface.

    The real client is ``src.analytics.ti_feeds.mgmt_client.ManagementClient``.
    This stub records every call and pretends every POST succeeds with a
    new UUID. Signatures must match the production client exactly so the
    feed clients exercise the same call sites in tests as in production.
    """

    def __init__(self) -> None:
        self.bans: dict[str, dict[str, Any]] = {}
        self.blocklist: dict[str, Any] = {}
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
        # the helper still loads when ti_feeds isn't on the path.
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
