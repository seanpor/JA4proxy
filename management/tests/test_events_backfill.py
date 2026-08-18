"""The live feed must paint history on connect, not an empty table.

WHY THIS EXISTS
---------------
``_event_generator`` started at ``last_id = "$"`` — "only entries added after
this call". The dashboard's five ``animate-pulse`` placeholder rows were never
removed by anything. So on a stack holding 54,000 events but with no traffic in
flight, the operator opened the console and saw five pulsing grey bars and
nothing else, indefinitely. The feed looked broken, and the history it was
sitting on was unreachable from the page.

Live-only is the right default for a *tail*. It is the wrong default for the
*first paint*.

Testing note
------------
``test_events.py`` records that end-to-end SSE tests are impractical here
because the blocking XREAD stalls the ASGI transport. That applies to the tail
loop. The backfill runs *before* that loop, so driving the generator directly
and stopping at the ``backfill-complete`` marker tests the new behaviour with
no blocking call involved.
"""

from __future__ import annotations

import asyncio
import json

import fakeredis.aioredis
import pytest

from management.api.routes.events import _BACKFILL_COUNT, _STREAM_KEY, _event_generator


class _NeverDisconnects:
    """Minimal stand-in for `starlette.Request` — the generator only calls
    `is_disconnected()`, and only inside the tail loop we never reach."""

    async def is_disconnected(self) -> bool:
        return False


def _event(ip: str, ja4: str = "t13d1516h2_8daaf6152771_02713d6af862", **extra) -> dict:
    payload = {
        "@timestamp": "2026-08-18T15:53:22.660500326Z",
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "event.action": "block",
        "event.risk_score": 100,
    }
    payload.update(extra)
    return {"event": json.dumps(payload)}


async def _drain_backfill(redis, timeout: float = 5.0) -> tuple[list[dict], dict | None]:
    """Consume the generator up to and including the backfill marker.

    The timeout is load-bearing, not defensive boilerplate. If the backfill is
    ever removed the generator drops straight into its blocking XREAD tail and
    this helper never returns — mutation-testing this file without the deadline
    produced a hang instead of a failure, and a test that hangs on regression is
    barely better than one that passes. ``wait_for`` turns that back into a
    clean, fast assertion failure.
    """

    async def _consume() -> tuple[list[dict], dict | None]:
        rows: list[dict] = []
        marker: dict | None = None
        gen = _event_generator(_NeverDisconnects(), redis)
        try:
            async for item in gen:
                if item.get("event") == "backfill-complete":
                    marker = item
                    break
                # A keepalive here means we fell through to the tail loop
                # without ever emitting the marker.
                if "comment" in item:
                    break
                rows.append(item)
        finally:
            await gen.aclose()
        return rows, marker

    try:
        return await asyncio.wait_for(_consume(), timeout=timeout)
    except asyncio.TimeoutError:
        pytest.fail(
            f"the generator produced no backfill-complete marker within {timeout}s "
            "— it went straight to the live tail, which is the exact regression "
            "this file guards against"
        )


@pytest.fixture
async def redis():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_existing_events_are_painted_on_connect(redis) -> None:
    """The core regression: a populated stream must not render as empty."""
    for i in range(5):
        await redis.xadd(_STREAM_KEY, _event(f"203.0.113.{i}"))

    rows, marker = await _drain_backfill(redis)

    assert len(rows) == 5, "every stored event should be painted on first connect"
    assert marker is not None, "the client needs a signal that first paint is done"
    assert marker["data"] == "5", "the marker carries the row count"
    for i in range(5):
        assert any(f"203.0.113.{i}" in r["data"] for r in rows), f"missing .{i}"


@pytest.mark.asyncio
async def test_backfill_is_capped(redis) -> None:
    """A long stream must not be replayed in full — first byte stays fast."""
    for i in range(_BACKFILL_COUNT + 40):
        await redis.xadd(_STREAM_KEY, _event(f"198.51.100.{i % 250}"))

    rows, marker = await _drain_backfill(redis)

    assert len(rows) == _BACKFILL_COUNT
    assert marker is not None and marker["data"] == str(_BACKFILL_COUNT)


@pytest.mark.asyncio
async def test_backfill_order_is_oldest_first(redis) -> None:
    """The client prepends each row (``hx-swap="afterbegin"``).

    Feeding chronologically therefore leaves the NEWEST at the top, matching
    the order live events arrive in afterwards. Reversed, the newest event
    would sink to the bottom and the feed would read backwards.
    """
    for i in range(4):
        await redis.xadd(_STREAM_KEY, _event(f"192.0.2.{i}"))

    rows, _ = await _drain_backfill(redis)

    order = [next(i for i in range(4) if f"192.0.2.{i}" in r["data"]) for r in rows]
    assert order == [0, 1, 2, 3], f"expected oldest-first, got {order}"


@pytest.mark.asyncio
async def test_empty_stream_yields_a_zero_marker(redis) -> None:
    """An empty stream must still signal first paint.

    Otherwise the placeholder rows stay up on a brand-new install and "nothing
    has connected yet" is indistinguishable from "the feed is broken" — which
    is the state this whole change exists to remove.
    """
    rows, marker = await _drain_backfill(redis)

    assert rows == []
    assert marker is not None and marker["data"] == "0"


@pytest.mark.asyncio
async def test_backfill_failure_does_not_kill_the_stream(redis) -> None:
    """Fail open: a broken replay must still leave a working live tail.

    The feed is a monitoring surface. Losing history is an inconvenience;
    losing the live tail during an incident is not.
    """

    class _Boom:
        async def xrevrange(self, *a, **k):
            raise ConnectionError("redis went away")

    rows, marker = await _drain_backfill(_Boom())

    assert rows == []
    assert marker is not None, "the client must still be told to clear placeholders"
    assert marker["data"] == "0"


@pytest.mark.asyncio
async def test_malformed_event_does_not_abort_the_backfill(redis) -> None:
    """One bad JSON payload must not cost the operator every other row."""
    await redis.xadd(_STREAM_KEY, _event("203.0.113.1"))
    await redis.xadd(_STREAM_KEY, {"event": "{not json"})
    await redis.xadd(_STREAM_KEY, _event("203.0.113.3"))

    rows, marker = await _drain_backfill(redis)

    assert len(rows) == 3, "the malformed row should render blank, not vanish"
    assert marker is not None and marker["data"] == "3"
    assert any("203.0.113.1" in r["data"] for r in rows)
    assert any("203.0.113.3" in r["data"] for r in rows)
