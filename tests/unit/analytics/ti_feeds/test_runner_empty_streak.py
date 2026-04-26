"""PHASE_101 C5 — two-empty-poll gate before bulk cleanup.

A single empty poll is not enough to trigger deletion of a feed's
entire snapshot — upstream glitches, transient TAXII 500s, and mid-poll
rotations can all flash an empty result set once. We only proceed
with differential cleanup when ``empty_streak >= 2``.

Test matrix:
    * First empty poll   → cleanup skipped, streak=1
    * Second empty poll  → cleanup runs (still capped at 10%)
    * Non-empty poll     → streak reset to 0, cleanup proceeds normally
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

import fakeredis
import pytest

from src.analytics.ti_feeds.base import FeedConfig, FeedPollResult
from src.analytics.ti_feeds.runner import FeedRunner
from src.analytics.ti_feeds.state import FeedState


@dataclass
class _MgmtCall:
    method: str
    handle: str


class _StubMgmt:
    def __init__(self) -> None:
        self.calls: List[_MgmtCall] = []

    async def connect(self) -> None: ...
    async def close(self) -> None: ...

    async def delete_ban(self, handle: str, *, feed_id: str) -> None:
        self.calls.append(_MgmtCall("delete_ban", handle))

    async def delete_blocklist(self, handle: str, *, feed_id: str) -> None:
        self.calls.append(_MgmtCall("delete_blocklist", handle))


class _StubClient:
    def __init__(self, config: FeedConfig, result: FeedPollResult) -> None:
        self.config = config
        self._result = result
        self.previous_stix_ids: dict[str, str] = {}

    async def poll(self) -> FeedPollResult:
        return self._result

    async def close(self) -> None: ...


@pytest.fixture()
def redis():
    server = fakeredis.FakeServer()
    return fakeredis.FakeStrictRedis(server=server, decode_responses=True)


def _make_runner(redis: Any, mgmt: _StubMgmt, client: _StubClient) -> FeedRunner:
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


def _cfg() -> FeedConfig:
    return FeedConfig(
        id="streak-feed",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
    )


async def _seed_prev(state: FeedState, feed_id: str, n: int) -> None:
    for i in range(n):
        await state.mark(
            feed_id, stix_id=f"id-{i:03d}", handle=f"ip-{i:03d}", kind="ban"
        )


def _release_leader(redis: Any) -> None:
    """Drop the leader SETNX key so consecutive _poll_once() calls in the
    same test don't trip the 30s fail-closed window."""
    redis.delete("ti_feed:leader_lock")


# ── Tests ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_first_empty_poll_skips_cleanup(redis):
    """Previous=100, empty poll → NO deletes, streak=1."""
    cfg = _cfg()
    mgmt = _StubMgmt()
    result = FeedPollResult(feed_id=cfg.id, stix_ids_seen=set(), created=[])
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)
    await _seed_prev(runner._state, cfg.id, 100)

    await runner._poll_once(cfg.id)

    assert [c for c in mgmt.calls if c.method == "delete_ban"] == []
    streak = await runner._state.get_empty_streak(cfg.id)
    assert streak == 1


@pytest.mark.asyncio
async def test_second_consecutive_empty_poll_allows_cleanup(redis):
    """Two empties → the second runs the usual 10%-capped cleanup path."""
    cfg = _cfg()
    mgmt = _StubMgmt()
    result = FeedPollResult(feed_id=cfg.id, stix_ids_seen=set(), created=[])
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)
    await _seed_prev(runner._state, cfg.id, 100)

    # First empty poll primes the streak.
    await runner._poll_once(cfg.id)
    assert [c for c in mgmt.calls if c.method == "delete_ban"] == []

    # Second empty poll: cleanup runs, capped at max(10, 100//10) = 10.
    _release_leader(redis)
    await runner._poll_once(cfg.id)
    deletes = [c for c in mgmt.calls if c.method == "delete_ban"]
    assert len(deletes) == 10, (
        f"second empty poll should delete up to 10 (10% cap); got {len(deletes)}"
    )


@pytest.mark.asyncio
async def test_non_empty_poll_resets_streak(redis):
    """An empty poll then a non-empty poll → streak goes back to 0."""
    cfg = _cfg()
    mgmt = _StubMgmt()
    # First call: empty
    empty = FeedPollResult(feed_id=cfg.id, stix_ids_seen=set(), created=[])
    # Second call: non-empty
    seen = {f"id-{i:03d}" for i in range(90)}
    non_empty = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[(f"id-{i:03d}", f"ip-{i:03d}") for i in range(90)],
    )

    class _TwoStepClient:
        def __init__(self) -> None:
            self.config = cfg
            self._results = [empty, non_empty]
            self.previous_stix_ids: dict[str, str] = {}

        async def poll(self) -> FeedPollResult:
            return self._results.pop(0)

        async def close(self) -> None: ...

    runner = _make_runner(redis, mgmt, _TwoStepClient())
    await _seed_prev(runner._state, cfg.id, 100)

    await runner._poll_once(cfg.id)
    assert await runner._state.get_empty_streak(cfg.id) == 1

    _release_leader(redis)
    await runner._poll_once(cfg.id)
    assert await runner._state.get_empty_streak(cfg.id) == 0
