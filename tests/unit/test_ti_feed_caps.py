"""PHASE_101 C4 — per-feed safety caps enforcement.

Verifies that ``max_new_per_poll``, ``max_owned_total``, and
``max_delta_per_poll`` brake a misbehaving feed before it can
mass-ban legitimate traffic.

The three caps are enforced inside ``FeedRunner._poll_once`` after
``client.poll()`` returns. Each test drives ``_poll_once`` directly
with a stub client and asserts the result vector plus the
``ja4proxy_ti_feed_caps_hit_total{kind=...}`` counter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

import fakeredis
import pytest

from src.analytics.ti_feeds.base import FeedConfig, FeedPollResult
from src.analytics.ti_feeds.metrics import TI_FEED_CAPS_HIT
from src.analytics.ti_feeds.runner import FeedRunner
from src.analytics.ti_feeds.state import FeedState

# ── Stubs ────────────────────────────────────────────────────────────────────


@dataclass
class _MgmtCall:
    method: str
    args: tuple


class _StubMgmt:
    def __init__(self) -> None:
        self.calls: List[_MgmtCall] = []

    async def connect(self) -> None: ...
    async def close(self) -> None: ...

    async def delete_ban(self, handle: str, *, feed_id: str) -> None:
        self.calls.append(_MgmtCall("delete_ban", (handle, feed_id)))

    async def delete_blocklist(self, handle: str, *, feed_id: str) -> None:
        self.calls.append(_MgmtCall("delete_blocklist", (handle, feed_id)))


class _StubClient:
    def __init__(self, config: FeedConfig, result: FeedPollResult) -> None:
        self.config = config
        self._result = result
        self.previous_stix_ids: dict[str, str] = {}

    async def poll(self) -> FeedPollResult:
        return self._result

    async def close(self) -> None: ...


# ── Fixtures ─────────────────────────────────────────────────────────────────


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


def _cap_counter(feed_id: str, kind: str) -> float:
    return TI_FEED_CAPS_HIT.labels(feed_id=feed_id, kind=kind)._value.get()


# ── max_new_per_poll ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_max_new_per_poll_truncates_created_list(redis):
    """Feed returns 1000 new indicators but cap=100 → created truncated to 100."""
    cfg = FeedConfig(
        id="caps-new",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
        max_new_per_poll=100,
    )
    mgmt = _StubMgmt()
    seen = {f"id-{i}" for i in range(1000)}
    result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[(f"id-{i}", f"ip-{i}") for i in range(1000)],
    )
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)

    before = _cap_counter(cfg.id, "new")
    await runner._poll_once(cfg.id)
    after = _cap_counter(cfg.id, "new")

    assert len(result.created) == 100
    assert after - before == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_max_new_per_poll_no_trim_when_below_cap(redis):
    """Feed returns 50, cap=100 → unchanged, counter not bumped."""
    cfg = FeedConfig(
        id="caps-new-below",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
        max_new_per_poll=100,
    )
    mgmt = _StubMgmt()
    seen = {f"id-{i}" for i in range(50)}
    result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen=seen,
        created=[(f"id-{i}", f"ip-{i}") for i in range(50)],
    )
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)

    before = _cap_counter(cfg.id, "new")
    await runner._poll_once(cfg.id)
    after = _cap_counter(cfg.id, "new")

    assert len(result.created) == 50
    assert after == before


# ── max_owned_total ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_max_owned_total_refuses_new_indicators(redis):
    """Snapshot already has 50k entries → new indicators this poll are rejected."""
    cfg = FeedConfig(
        id="caps-total",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
        max_owned_total=10,
    )
    mgmt = _StubMgmt()
    state = FeedState(redis)
    for i in range(10):
        await state.mark(cfg.id, stix_id=f"existing-{i}", handle=f"ip-{i}", kind="ban")

    result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen={"new-1"},
        created=[("new-1", "ip-new-1")],
    )
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)
    runner._state = state

    before = _cap_counter(cfg.id, "total")
    await runner._poll_once(cfg.id)
    after = _cap_counter(cfg.id, "total")

    assert result.created == []
    assert after - before == pytest.approx(1.0)


# ── max_delta_per_poll ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_max_delta_per_poll_rejects_oversized_delta(redis):
    """Delta beyond cap → created emptied, counter bumped."""
    cfg = FeedConfig(
        id="caps-delta",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
        max_delta_per_poll=5,
    )
    mgmt = _StubMgmt()
    # Feed claims 100 new, previous had 0 → delta=100, well above cap.
    result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen={f"id-{i}" for i in range(100)},
        created=[(f"id-{i}", f"ip-{i}") for i in range(100)],
    )
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)

    before = _cap_counter(cfg.id, "delta")
    await runner._poll_once(cfg.id)
    after = _cap_counter(cfg.id, "delta")

    assert result.created == []
    assert after - before == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_max_delta_per_poll_zero_means_unlimited(redis):
    """Cap=0 is the documented sentinel for disabled."""
    cfg = FeedConfig(
        id="caps-delta-off",
        type="taxii2",
        enabled=True,
        url="https://example.invalid/",
        poll_interval_minutes=60,
        max_delta_per_poll=0,
    )
    mgmt = _StubMgmt()
    result = FeedPollResult(
        feed_id=cfg.id,
        stix_ids_seen={f"id-{i}" for i in range(50)},
        created=[(f"id-{i}", f"ip-{i}") for i in range(50)],
    )
    client = _StubClient(cfg, result)
    runner = _make_runner(redis, mgmt, client)

    before = _cap_counter(cfg.id, "delta")
    await runner._poll_once(cfg.id)
    after = _cap_counter(cfg.id, "delta")

    assert len(result.created) == 50
    assert after == before
