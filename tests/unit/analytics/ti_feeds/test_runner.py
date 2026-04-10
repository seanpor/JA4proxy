"""Unit tests for ``src.analytics.ti_feeds.runner.FeedRunner._poll_once``.

Phase 85.1 — closes the structural coverage gap surfaced by the test
integrity audit. Before this file existed, every test that imported
``FeedRunner`` was xfailed (the integration tests use a constructor
shape that no longer exists). The deletion-cap and snapshot-replace
logic in commit 78162eb / 7c8ccac landed without any test gating it.

What's covered here:

* C2 partial — 10% deletion cap math
    - dropped count well below cap → all dropped removed
    - dropped count above cap → exactly ``max(10, prev//10)`` removed,
      remainder carried forward in the new snapshot so the next poll's
      diff still sees them
    - cap floor of 10 honoured for small snapshots

* H7 — snapshot integrity
    - successful poll: every (stix_id, handle) returned by the stub
      client lands in ``active_stix_ids`` with the correct handle
    - the runner's ``_result_handle_iter`` includes idempotent re-applies
      (entries in ``stix_ids_seen`` but absent from ``created``) with
      empty handles, so they remain part of the snapshot for the next
      poll's diff

The runner is exercised through ``_poll_once`` directly, with a stub
``FeedClient`` and a stub ``ManagementClient`` that just record calls.
``FeedState`` runs against a real fakeredis instance so the snapshot
replace + cleanup paths execute the same Redis pipeline they hit in
production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Tuple

import fakeredis
import pytest
import pytest_asyncio

from src.analytics.ti_feeds.base import FeedConfig, FeedPollResult
from src.analytics.ti_feeds.runner import FeedRunner
from src.analytics.ti_feeds.state import FeedState

# ── Stubs ────────────────────────────────────────────────────────────────────


@dataclass
class _MgmtCall:
    method: str
    handle: str
    feed_id: str


class _StubMgmt:
    """Captures delete_ban / delete_blocklist calls without an HTTP layer."""

    def __init__(self) -> None:
        self.calls: List[_MgmtCall] = []
        self.fail_handles: set[str] = set()

    async def connect(self) -> None: ...
    async def close(self) -> None: ...

    async def delete_ban(self, handle: str, *, feed_id: str) -> None:
        if handle in self.fail_handles:
            raise RuntimeError(f"simulated mgmt failure for {handle}")
        self.calls.append(_MgmtCall("delete_ban", handle, feed_id))

    async def delete_blocklist(self, handle: str, *, feed_id: str) -> None:
        if handle in self.fail_handles:
            raise RuntimeError(f"simulated mgmt failure for {handle}")
        self.calls.append(_MgmtCall("delete_blocklist", handle, feed_id))


class _StubClient:
    """Minimal FeedClient stub that returns a pre-canned poll result."""

    def __init__(self, config: FeedConfig, result: FeedPollResult) -> None:
        self.config = config
        self._result = result
        self.previous_stix_ids: dict[str, str] = {}

    async def poll(self) -> FeedPollResult:
        return self._result

    async def close(self) -> None: ...


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_config() -> FeedConfig:
    return FeedConfig(
        id="unit-feed",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
    )


def _make_runner(redis: Any, mgmt: _StubMgmt, client: _StubClient) -> FeedRunner:
    """Build a runner with the stubs hot-swapped in.

    ``FeedRunner.__init__`` constructs its own ``ManagementClient`` and
    ``FeedState`` from the redis + mgmt_base_url args. We replace those
    fields after construction so the test owns the mgmt + state objects.
    """
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
        instance_id="unit-test",
    )
    runner._mgmt = mgmt  # type: ignore[assignment]
    runner._state = FeedState(redis)
    runner._clients = {client.config.id: client}  # type: ignore[dict-item]
    return runner


@pytest.fixture()
def redis():
    """Fresh fakeredis client per test — leader lock state must not leak.

    Uses the sync ``fakeredis.FakeStrictRedis`` because ``FeedState`` wraps
    sync clients in an async shim (``_SyncRedisShim``). The async
    ``fakeredis.aioredis.FakeRedis`` is *not* detected as async by
    ``_is_async_redis`` (its methods aren't ``async def`` — they return
    coroutines via a wrapper) and gets re-wrapped, double-awaiting the
    coroutines and breaking every call.
    """
    server = fakeredis.FakeServer()
    return fakeredis.FakeStrictRedis(server=server, decode_responses=True)


# ── C2 cap math ──────────────────────────────────────────────────────────────


async def _seed_previous_snapshot(
    state: FeedState,
    feed_id: str,
    pairs: List[Tuple[str, str]],
) -> None:
    """Drop ``pairs`` directly into the side indices + active_stix HASH."""
    for stix_id, handle in pairs:
        await state.mark(feed_id, stix_id=stix_id, handle=handle, kind="ban")


@pytest.mark.asyncio
async def test_cleanup_below_cap_removes_everything(redis):
    """50-entry snapshot, 5 dropped (cap=10) → all 5 removed, no defer."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    # Poll returns 45 still-present indicators; 5 went away.
    seen = {f"id-{i}" for i in range(45)}
    poll_result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[(f"id-{i}", f"ip-{i}") for i in range(45)],
    )
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    pairs = [(f"id-{i}", f"ip-{i}") for i in range(50)]
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    await runner._poll_once(cfg.id)

    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    assert len(deletes) == 5
    deleted_handles = sorted(c.handle for c in deletes)
    assert deleted_handles == sorted([f"ip-{i}" for i in range(45, 50)])

    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert len(snapshot) == 45
    assert all(f"id-{i}" not in snapshot for i in range(45, 50))


@pytest.mark.asyncio
async def test_cleanup_above_cap_caps_at_10pct_and_defers_remainder(redis):
    """200-entry snapshot, 100 dropped → cap=20 removed, 80 deferred into snapshot."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    # Poll returns the first 100 entries; the second 100 vanished.
    seen = {f"id-{i}" for i in range(100)}
    poll_result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[(f"id-{i}", f"ip-{i}") for i in range(100)],
    )
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    pairs = [(f"id-{i:03d}", f"ip-{i:03d}") for i in range(200)]
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)
    # Re-shape "seen" to use the same zero-padded ids so the diff matches.
    poll_result.stix_ids_seen = {f"id-{i:03d}" for i in range(100)}
    poll_result.created = [(f"id-{i:03d}", f"ip-{i:03d}") for i in range(100)]

    await runner._poll_once(cfg.id)

    # Cap = max(10, 200 // 10) = 20.
    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    assert len(deletes) == 20

    # Snapshot must still contain the 100 still-present entries plus the
    # 80 deferred entries (200 dropped - 20 removed = 80 carried forward).
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert len(snapshot) == 100 + 80, (
        f"snapshot size = {len(snapshot)}, expected 180 "
        f"(100 still-present + 80 deferred)"
    )
    # The 100 still-present entries keep their handles.
    for i in range(100):
        assert snapshot[f"id-{i:03d}"] == f"ip-{i:03d}"
    # The 80 deferred entries are present, with their original handles
    # (carried forward from previous_ids via the deferred_cleanup dict).
    deferred_count = sum(
        1 for k in snapshot if k not in {f"id-{i:03d}" for i in range(100)}
    )
    assert deferred_count == 80


@pytest.mark.asyncio
async def test_cleanup_floor_of_10_for_small_snapshots(redis):
    """5-entry snapshot, all dropped → cap=10 (floor) → all 5 removed."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)  # empty poll
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    pairs = [(f"id-{i}", f"ip-{i}") for i in range(5)]
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    await runner._poll_once(cfg.id)

    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    # 5 < cap of 10 → all 5 removed.
    assert len(deletes) == 5
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


@pytest.mark.asyncio
async def test_capped_cleanup_converges_across_two_polls(redis):
    """A 200→0 collapse over two polls: first removes 20, second the rest."""
    cfg = _make_config()
    mgmt = _StubMgmt()

    pairs = [(f"id-{i:03d}", f"ip-{i:03d}") for i in range(200)]

    # First poll: feed shows nothing.
    first_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, first_result)
    runner = _make_runner(redis, mgmt, client)
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    await runner._poll_once(cfg.id)
    snapshot_after_first = await runner._state.get_active_stix_ids(cfg.id)
    # max(10, 200//10) = 20 removed, 180 deferred.
    assert len(snapshot_after_first) == 180

    # Second poll: feed still shows nothing. Cap is now max(10, 180//10) = 18.
    runner._clients[cfg.id]._result = FeedPollResult(feed_id=cfg.id)  # type: ignore[attr-defined]
    # The leader lock is still held by this instance (30s TTL > test runtime).
    # SETNX would refuse a second acquisition, so drop the lock to let the
    # second _poll_once proceed. In production, refresh_leader handles this.
    redis.delete("ti_feed:leader_lock")
    await runner._poll_once(cfg.id)
    snapshot_after_second = await runner._state.get_active_stix_ids(cfg.id)
    assert len(snapshot_after_second) == 180 - 18

    total_deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    assert len(total_deletes) == 20 + 18


# ── H7 snapshot integrity ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_successful_poll_populates_snapshot_with_handles(redis):
    """A poll with 3 created indicators populates active_stix_ids correctly."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    seen = {"id-a", "id-b", "id-c"}
    poll_result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[("id-a", "1.1.1.1"), ("id-b", "2.2.2.2"), ("id-c", "3.3.3.3")],
    )
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    await runner._poll_once(cfg.id)

    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {
        "id-a": "1.1.1.1",
        "id-b": "2.2.2.2",
        "id-c": "3.3.3.3",
    }
    # Nothing was dropped on a fresh feed → no mgmt deletes.
    assert mgmt.calls == []


@pytest.mark.asyncio
async def test_idempotent_reapply_lands_in_snapshot_with_empty_handle(redis):
    """stix_ids_seen ⊃ created → re-applies stay in the snapshot with empty handle.

    The runner's _result_handle_iter yields the (created) entries first
    with their resource handles, then the (seen but not created) entries
    with empty handles. Both forms must end up in active_stix_ids so the
    next poll's diff treats them as still-present.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen={"id-new", "id-existing"},
        created=[("id-new", "9.9.9.9")],  # only id-new is freshly created
    )
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    await runner._poll_once(cfg.id)

    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot.get("id-new") == "9.9.9.9"
    # id-existing is in the snapshot (next poll's diff must treat it as
    # still-present), with an empty handle as the runner's contract.
    assert "id-existing" in snapshot
    assert snapshot["id-existing"] == ""
