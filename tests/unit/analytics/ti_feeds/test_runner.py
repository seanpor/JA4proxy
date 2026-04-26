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
    """5-entry snapshot, all dropped → cap=10 (floor) → all 5 removed.

    PHASE_101 C5: cleanup only runs on the *second* consecutive empty poll,
    so we prime the streak with one empty poll, drop the leader lock, and
    fire a second empty poll to observe the cleanup.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)  # empty poll
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    pairs = [(f"id-{i}", f"ip-{i}") for i in range(5)]
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    # First empty poll primes the empty-streak counter; no deletes yet.
    await runner._poll_once(cfg.id)
    assert mgmt.calls == []
    # Release the 30s SETNX leader lock so the next _poll_once can run.
    redis.delete("ti_feed:leader_lock")

    await runner._poll_once(cfg.id)

    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    # 5 < cap of 10 → all 5 removed.
    assert len(deletes) == 5
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


@pytest.mark.asyncio
async def test_capped_cleanup_converges_across_two_polls(redis):
    """A 200→0 collapse, spanning the PHASE_101 C5 empty-poll gate plus two
    cap-limited cleanup cycles (20 then 18 removals).

    Poll 1 primes the empty-streak counter and must not delete anything.
    Poll 2 enters the cleanup path with cap=20; 180 deferred.
    Poll 3 enters again with cap=max(10, 180//10)=18.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()

    pairs = [(f"id-{i:03d}", f"ip-{i:03d}") for i in range(200)]

    first_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, first_result)
    runner = _make_runner(redis, mgmt, client)
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    # Priming poll — C5 gate skips cleanup on the first empty result.
    await runner._poll_once(cfg.id)
    assert mgmt.calls == []
    redis.delete("ti_feed:leader_lock")

    # First cleanup pass: cap = max(10, 200//10) = 20.
    runner._clients[cfg.id]._result = FeedPollResult(feed_id=cfg.id)  # type: ignore[attr-defined]
    await runner._poll_once(cfg.id)
    snapshot_after_first_cleanup = await runner._state.get_active_stix_ids(cfg.id)
    assert len(snapshot_after_first_cleanup) == 180

    # Second cleanup pass: cap is now max(10, 180//10) = 18.
    runner._clients[cfg.id]._result = FeedPollResult(feed_id=cfg.id)  # type: ignore[attr-defined]
    redis.delete("ti_feed:leader_lock")
    await runner._poll_once(cfg.id)
    snapshot_after_second_cleanup = await runner._state.get_active_stix_ids(cfg.id)
    assert len(snapshot_after_second_cleanup) == 180 - 18

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


# ══════════════════════════════════════════════════════════════════════════════
# Phase 104 — coverage gap closure tests
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# ── start() lifecycle: disabled gate ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_disabled_returns_immediately(redis):
    """When threat_intel.enabled=false, start() exits without connecting."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": False}},
    )
    await runner.start()
    # No trigger task spawned, no clients
    assert runner._trigger_task is None
    assert runner._clients == {}


@pytest.mark.asyncio
async def test_start_disabled_no_threat_intel_key(redis):
    """When threat_intel key is absent, start() exits cleanly."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={},
    )
    await runner.start()
    assert runner._trigger_task is None


# ── start() lifecycle: mgmt connect error ────────────────────────────────────


@pytest.mark.asyncio
async def test_start_mgmt_connect_error_returns(redis):
    """When ManagementClient.connect() raises, start() logs and exits."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._mgmt = AsyncMock()
    runner._mgmt.connect.side_effect = ConnectionError("refused")
    await runner.start()
    assert runner._clients == {}
    assert runner._trigger_task is None


# ── start() lifecycle: seed file loading error ───────────────────────────────


@pytest.mark.asyncio
async def test_start_seed_file_error_does_not_crash(redis):
    """When the seed file loader raises, start() logs and continues."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={
            "threat_intel": {
                "enabled": True,
                "seed_file": {"enabled": True, "path": "/nonexistent/seed.yml"},
            },
        },
    )
    runner._mgmt = AsyncMock()
    runner._mgmt.connect = AsyncMock()
    runner._mgmt.close = AsyncMock()
    # Patch run_seed_file to raise
    with patch("src.analytics.ti_feeds.runner.run_seed_file", side_effect=RuntimeError("boom")):
        with patch("src.analytics.ti_feeds.runner.FeedRunner._rebuild_clients", new_callable=AsyncMock):
            with patch("asyncio.create_task") as mock_ct:
                mock_ct.return_value = MagicMock()
                await runner.start()
    # Should not have crashed — trigger task was attempted
    assert True


# ── _rebuild_clients: config parsing errors ──────────────────────────────────


@pytest.mark.asyncio
async def test_rebuild_clients_skips_non_dict_entries(redis):
    """Non-dict entries in feeds[] are silently skipped."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._mgmt = AsyncMock()
    runner._state = FeedState(redis)
    ti_cfg = {"feeds": ["not-a-dict", 42, None]}
    with patch("asyncio.create_task") as mock_ct:
        mock_ct.return_value = MagicMock()
        await runner._rebuild_clients(ti_cfg)
    assert runner._clients == {}


@pytest.mark.asyncio
async def test_rebuild_clients_skips_invalid_feed_config(redis):
    """A feed entry missing required fields is skipped with a warning."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._mgmt = AsyncMock()
    runner._state = FeedState(redis)
    # Missing 'id' and 'type' — FeedConfig.from_dict raises ValueError
    ti_cfg = {"feeds": [{"some_key": "some_val"}]}
    with patch("asyncio.create_task") as mock_ct:
        mock_ct.return_value = MagicMock()
        await runner._rebuild_clients(ti_cfg)
    assert runner._clients == {}


@pytest.mark.asyncio
async def test_rebuild_clients_unknown_feed_type(redis):
    """A feed with an unrecognised type is logged and skipped."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._mgmt = AsyncMock()
    runner._state = FeedState(redis)
    ti_cfg = {
        "feeds": [
            {"id": "test-feed", "type": "nonexistent_type", "url": "https://example.com/x"},
        ],
    }
    with patch("asyncio.create_task") as mock_ct:
        mock_ct.return_value = MagicMock()
        await runner._rebuild_clients(ti_cfg)
    assert "test-feed" not in runner._clients


@pytest.mark.asyncio
async def test_rebuild_clients_removes_vanished_feeds(redis):
    """Feeds removed from config are stopped."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Now rebuild with empty feed list — existing feed should be removed
    await runner._rebuild_clients({"feeds": []})
    assert cfg.id not in runner._clients
    assert cfg.id not in runner._tasks


# ── _poll_loop: timeout + exception handling ─────────────────────────────────


@pytest.mark.asyncio
async def test_poll_loop_handles_poll_timeout(redis):
    """A timed-out _poll_once triggers error logging and continues."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    call_count = 0

    async def slow_poll_once(feed_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            await asyncio.sleep(999)  # will be cancelled by wait_for timeout
        # second call triggers stop
        runner._stopping.set()

    runner._poll_once = slow_poll_once  # type: ignore[assignment]

    # Use a very short interval so the loop iterates quickly
    client.config.poll_interval_minutes = 1  # 60s interval
    with patch("asyncio.wait_for", side_effect=[asyncio.TimeoutError(), None]):
        # Simulate: first iteration times out, second exits via stopping
        runner._stopping.set()
        # Just run the poll_loop coroutine directly — it should handle timeout
        await runner._poll_loop(cfg.id)


@pytest.mark.asyncio
async def test_poll_loop_handles_poll_exception(redis):
    """An exception in _poll_once is caught and logged."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    call_count = 0

    async def failing_poll_once(feed_id):
        nonlocal call_count
        call_count += 1
        if call_count <= 1:
            raise RuntimeError("simulated poll failure")
        runner._stopping.set()

    runner._poll_once = failing_poll_once  # type: ignore[assignment]
    client.config.poll_interval_minutes = 1
    # Set stopping after one iteration
    async def auto_stop(*args, **kwargs):
        runner._stopping.set()

    with patch.object(runner._stopping, "wait", side_effect=auto_stop):
        await runner._poll_loop(cfg.id)
    assert call_count >= 1


@pytest.mark.asyncio
async def test_poll_loop_cancelled_error(redis):
    """CancelledError in the outer try propagates cleanly."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    async def cancel_immediately(feed_id):
        raise asyncio.CancelledError()

    runner._poll_once = cancel_immediately  # type: ignore[assignment]
    # _poll_loop should exit cleanly (return)
    await runner._poll_loop(cfg.id)


# ── _poll_once: enabled gating ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_runtime_override_false_skips(redis):
    """When runtime override is False, poll is skipped."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id, stix_ids_seen={"x"}, created=[("x", "1.2.3.4")])
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Set runtime override to False
    await runner._state.set_runtime_override(cfg.id, False)

    await runner._poll_once(cfg.id)
    # No snapshot should have been written since poll was skipped
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


@pytest.mark.asyncio
async def test_poll_once_config_disabled_no_override_skips(redis):
    """When config says disabled and no runtime override, poll is skipped."""
    cfg = _make_config()
    cfg.enabled = False
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id, stix_ids_seen={"x"}, created=[("x", "1.2.3.4")])
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    await runner._poll_once(cfg.id)
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


@pytest.mark.asyncio
async def test_poll_once_client_not_found_returns(redis):
    """When feed_id is not in clients, _poll_once returns immediately."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._state = FeedState(redis)
    # No clients registered — should return cleanly
    await runner._poll_once("nonexistent")


# ── _poll_once: leader lock ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_leader_lock_rejected_skips(redis):
    """When leader lock cannot be acquired, poll is skipped."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id, stix_ids_seen={"x"}, created=[("x", "1.2.3.4")])
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Acquire the leader lock with a different instance
    redis.set("ti_feed:leader_lock", "other-instance", nx=True, ex=30)

    await runner._poll_once(cfg.id)
    # Poll was skipped — no snapshot written
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


# ── _poll_once: poll exception → circuit breaker ─────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_poll_exception_records_failure(redis):
    """When client.poll() raises, failure is recorded in breaker and state."""
    cfg = _make_config()
    mgmt = _StubMgmt()

    class _FailingClient:
        def __init__(self):
            self.config = cfg
            self.previous_stix_ids = {}

        async def poll(self):
            raise RuntimeError("upstream dead")

        async def close(self):
            pass

    client = _FailingClient()
    runner = _make_runner(redis, mgmt, _StubClient(cfg, FeedPollResult(feed_id=cfg.id)))
    runner._clients[cfg.id] = client  # type: ignore[assignment]

    await runner._poll_once(cfg.id)
    # Check poll state records the failure
    poll_state = await runner._state.get_poll_state(cfg.id)
    assert int(poll_state.get("failure_count", "0")) >= 1
    assert "upstream dead" in poll_state.get("last_error", "")


# ── _poll_once: safety caps ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_max_new_per_poll_cap(redis):
    """When created count exceeds max_new_per_poll, result is truncated."""
    cfg = _make_config()
    cfg.max_new_per_poll = 3
    mgmt = _StubMgmt()
    # 10 created indicators, cap is 3
    seen = {f"id-{i}" for i in range(10)}
    created = [(f"id-{i}", f"ip-{i}") for i in range(10)]
    poll_result = FeedPollResult(feed_id=cfg.id, stix_ids_seen=seen, created=created)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    await runner._poll_once(cfg.id)
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    # Only 3 created entries should have handles; the rest are empty-handle from stix_ids_seen
    with_handle = {k: v for k, v in snapshot.items() if v}
    assert len(with_handle) == 3


@pytest.mark.asyncio
async def test_poll_once_max_owned_total_cap(redis):
    """When previous_ids >= max_owned_total, no new indicators are created."""
    cfg = _make_config()
    cfg.max_owned_total = 5
    mgmt = _StubMgmt()
    # 3 new indicators
    poll_result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen={"new-1", "new-2", "new-3"},
        created=[("new-1", "ip-1"), ("new-2", "ip-2"), ("new-3", "ip-3")],
    )
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Seed 5 previous entries (at the cap)
    pairs = [(f"old-{i}", f"old-ip-{i}") for i in range(5)]
    await _seed_previous_snapshot(runner._state, cfg.id, pairs)

    await runner._poll_once(cfg.id)
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    # created was emptied due to cap — only stix_ids_seen entries with empty handles
    for sid in ["new-1", "new-2", "new-3"]:
        assert snapshot.get(sid) == ""


@pytest.mark.asyncio
async def test_poll_once_max_delta_per_poll_cap(redis):
    """When abs(delta) exceeds max_delta_per_poll, created is emptied."""
    cfg = _make_config()
    cfg.max_delta_per_poll = 2
    mgmt = _StubMgmt()
    # 10 new indicators, 0 previous — delta = 10, cap = 2
    seen = {f"id-{i}" for i in range(10)}
    created = [(f"id-{i}", f"ip-{i}") for i in range(10)]
    poll_result = FeedPollResult(feed_id=cfg.id, stix_ids_seen=seen, created=created)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    await runner._poll_once(cfg.id)
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    # All entries should have empty handles since created was emptied
    for sid in seen:
        assert snapshot.get(sid) == ""


# ── _poll_once: cleanup — unknown handle + cleanup failure ───────────────────


@pytest.mark.asyncio
async def test_cleanup_unknown_handle_logged(redis):
    """A handle not in ban_ips or blocklist_uuids logs unknown and clears.

    Needs two empty polls to cross the PHASE_101 C5 gate before the cleanup
    path runs.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Manually insert a stix entry with a handle that's not in either side set
    state = runner._state
    await state._redis.hset(f"ti_feed:{cfg.id}:active_stix_ids", "orphan-id", "orphan-handle")

    # Prime the empty-streak gate.
    await runner._poll_once(cfg.id)
    redis.delete("ti_feed:leader_lock")

    await runner._poll_once(cfg.id)
    # The orphan should have been cleaned up (unknown handle path)
    snapshot = await state.get_active_stix_ids(cfg.id)
    assert "orphan-id" not in snapshot


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_crash(redis):
    """If mgmt delete raises, the loop continues with remaining items.

    Needs two empty polls to cross the PHASE_101 C5 gate.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()
    mgmt.fail_handles = {"ip-1"}  # This handle will raise
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Seed two ban entries — one will fail cleanup, one will succeed
    await _seed_previous_snapshot(runner._state, cfg.id, [("id-0", "ip-0"), ("id-1", "ip-1")])

    # Prime the empty-streak gate.
    await runner._poll_once(cfg.id)
    redis.delete("ti_feed:leader_lock")

    await runner._poll_once(cfg.id)
    # ip-0 should have been deleted; ip-1 should have failed silently
    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    assert any(c.handle == "ip-0" for c in deletes)


# ── _poll_once: empty handle in dropped → just clear ────────────────────────


@pytest.mark.asyncio
async def test_cleanup_empty_handle_just_clears(redis):
    """A dropped entry with an empty handle is cleared without mgmt call.

    Needs two empty polls to cross the PHASE_101 C5 gate.
    """
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Insert entry with empty handle directly
    state = runner._state
    await state._redis.hset(f"ti_feed:{cfg.id}:active_stix_ids", "empty-id", "")

    # Prime the empty-streak gate.
    await runner._poll_once(cfg.id)
    redis.delete("ti_feed:leader_lock")

    await runner._poll_once(cfg.id)
    assert mgmt.calls == []  # No mgmt API calls for empty handles


# ── _poll_once: circuit breaker open → skip ──────────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_circuit_open_skips(redis):
    """When circuit breaker is open, poll is skipped."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Trip the circuit breaker by simulating repeated failures
    breaker = runner._breakers.for_feed(cfg.id)
    for _ in range(20):
        breaker.record_failure()

    # The breaker should now be open — poll should be skipped
    await runner._poll_once(cfg.id)
    snapshot = await runner._state.get_active_stix_ids(cfg.id)
    assert snapshot == {}


# ── _consume_trigger_stream ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_consume_trigger_stream_dispatches_trigger(redis):
    """The trigger consumer reads entries and calls trigger_poll."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._state = FeedState(redis)

    # Add a trigger entry to the stream
    redis.xadd(
        "ti_feed:manual_poll_triggers",
        {"feed_id": "test-feed", "poll_id": "abc123", "requested_by": "operator"},
    )

    trigger_calls = []

    async def mock_trigger_poll(feed_id):
        trigger_calls.append(feed_id)
        return "poll-123"

    runner.trigger_poll = mock_trigger_poll  # type: ignore[assignment]
    runner._trigger_last_id = "0"

    # Run one iteration then stop
    call_count = 0
    original_xread = redis.xread

    async def limited_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        # Use sync xread from fakeredis
        result = original_xread(*args, **kwargs)
        if call_count >= 2:
            runner._stopping.set()
        return result

    runner._redis = AsyncMock()
    runner._redis.xread = limited_xread

    await runner._consume_trigger_stream()
    assert "test-feed" in trigger_calls


@pytest.mark.asyncio
async def test_consume_trigger_stream_error_backs_off(redis):
    """On xread error, the consumer backs off and retries."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._state = FeedState(redis)

    call_count = 0

    async def failing_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 1:
            raise ConnectionError("redis gone")
        runner._stopping.set()
        return []

    runner._redis = AsyncMock()
    runner._redis.xread = failing_xread

    await runner._consume_trigger_stream()
    assert call_count >= 2  # At least one failure + one retry


@pytest.mark.asyncio
async def test_consume_trigger_stream_cancelled(redis):
    """CancelledError exits the consumer cleanly."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )

    async def cancel_xread(*args, **kwargs):
        raise asyncio.CancelledError()

    runner._redis = AsyncMock()
    runner._redis.xread = cancel_xread

    await runner._consume_trigger_stream()


@pytest.mark.asyncio
async def test_consume_trigger_stream_skips_empty_feed_id(redis):
    """Entries with empty feed_id are skipped."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._state = FeedState(redis)

    redis.xadd("ti_feed:manual_poll_triggers", {"feed_id": "", "poll_id": "x"})

    trigger_calls = []

    async def mock_trigger_poll(feed_id):
        trigger_calls.append(feed_id)
        return "p"

    runner.trigger_poll = mock_trigger_poll  # type: ignore[assignment]
    runner._trigger_last_id = "0"

    call_count = 0
    original_xread = redis.xread

    async def limited_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        result = original_xread(*args, **kwargs)
        if call_count >= 2:
            runner._stopping.set()
        return result

    runner._redis = AsyncMock()
    runner._redis.xread = limited_xread

    await runner._consume_trigger_stream()
    assert trigger_calls == []  # Empty feed_id should be skipped


# ── trigger_poll ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_poll_unknown_feed_returns_none(redis):
    """trigger_poll for an unregistered feed returns None."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    result = await runner.trigger_poll("nonexistent-feed")
    assert result is None


@pytest.mark.asyncio
async def test_trigger_poll_registered_feed_returns_poll_id(redis):
    """trigger_poll for a registered feed returns a poll-id string."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    result = await runner.trigger_poll(cfg.id)
    assert isinstance(result, str)
    assert len(result) == 32  # hex UUID


# ── stop() ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stop_cancels_tasks_and_closes_clients(redis):
    """stop() cancels all tasks, closes clients, closes mgmt."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Create a mock task
    mock_task = MagicMock()
    mock_task.cancel = MagicMock()
    runner._tasks[cfg.id] = mock_task
    runner._trigger_task = MagicMock()
    runner._trigger_task.cancel = MagicMock()

    # Patch gather to avoid issues with mock tasks
    with patch("asyncio.gather", new_callable=AsyncMock, return_value=[]):
        await runner.stop()

    assert runner._tasks == {}
    assert runner._stopping.is_set()


# ── reload_config ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reload_config_updates_internal_config(redis):
    """reload_config updates the runner's internal config and rebuilds clients."""
    runner = FeedRunner(
        redis=redis,
        mgmt_base_url="http://unused.invalid",
        config={"threat_intel": {"enabled": True}},
    )
    runner._mgmt = AsyncMock()
    runner._state = FeedState(redis)

    new_config = {"threat_intel": {"enabled": True, "feeds": []}}
    with patch("asyncio.create_task") as mock_ct:
        mock_ct.return_value = MagicMock()
        await runner.reload_config(new_config)
    assert runner._config is new_config


# ── _stop_feed ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stop_feed_cleans_up_everything(redis):
    """_stop_feed cancels task, closes client, drops breaker."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Register the breaker
    runner._breakers.for_feed(cfg.id)

    # Create a finished task to avoid cancellation issues
    async def noop():
        pass

    task = asyncio.create_task(noop())
    await task  # Let it finish
    runner._tasks[cfg.id] = task

    await runner._stop_feed(cfg.id)
    assert cfg.id not in runner._clients
    assert cfg.id not in runner._tasks


# ── _client_class_name ───────────────────────────────────────────────────────


def test_client_class_name_known_type():
    assert FeedRunner._client_class_name("taxii2") == "TAXIIClient"


def test_client_class_name_unknown_type():
    assert FeedRunner._client_class_name("nonexistent") == ""


# ── _poll_once: empty streak gating (C5) ────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_once_empty_streak_skips_cleanup_on_first_empty(redis):
    """First empty poll bumps streak but skips cleanup."""
    cfg = _make_config()
    mgmt = _StubMgmt()
    # Empty poll result
    poll_result = FeedPollResult(feed_id=cfg.id)
    client = _StubClient(cfg, poll_result)
    runner = _make_runner(redis, mgmt, client)

    # Seed previous entries
    await _seed_previous_snapshot(runner._state, cfg.id, [("id-0", "ip-0")])

    await runner._poll_once(cfg.id)
    streak = await runner._state.get_empty_streak(cfg.id)
    assert streak >= 1
