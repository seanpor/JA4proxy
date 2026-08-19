"""Phase 828, outcomes O11 and O12.

**O11 — suggestions must never become automation.** `suggest_action` proposes
what an operator might do. The moment that becomes something the system can
apply on its own, `CLAUDE.md`'s core asymmetry stops being a design principle
and becomes an outage: the CGNAT case is one click from removing several hundred
real subscribers. The route carrying it is read-only, and this pins that.

**O12 — the profile scan must stay bounded.** The endpoints page backwards over
`events:connection`. Unbounded, a stream with ten million entries would make one
page load read all of them. The bound also has to be *reported*, so the console
can say "based on the last N events" rather than presenting a partial count as a
complete one.
"""

from __future__ import annotations

import json

import fakeredis.aioredis
import pytest

from management.api.routes.connections import (
    _PROFILE_SCAN_BATCH,
    _PROFILE_SCAN_LIMIT,
    _STREAM_KEY,
    _scan_stream,
)


@pytest.fixture
async def redis():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


def _event(i: int) -> dict:
    return {
        "event": json.dumps(
            {
                "@timestamp": "2026-08-19T09:00:00Z",
                "source.ip": f"203.0.113.{i % 250}",
                "event.action": "allow",
                "event.risk_score": 10,
                "ja4proxy.fingerprint.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
                "ja4proxy.event_phase": "final",
            }
        )
    }


# ── O12 ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_short_stream_is_not_reported_as_truncated(redis) -> None:
    """A complete scan must say so, or the UI hedges a number it need not."""
    for i in range(50):
        await redis.xadd(_STREAM_KEY, _event(i))

    entries, scanned, truncated = await _scan_stream(redis)

    assert len(entries) == 50
    assert scanned == 50
    assert truncated is False


@pytest.mark.asyncio
async def test_scan_pages_without_repeating_entries(redis) -> None:
    """The cursor steps past the last id seen.

    ``xrevrange``'s ``max`` is inclusive, so a naive cursor re-reads its own
    boundary entry on every page — inflating counts and, with a batch size of
    one, looping forever.
    """
    n = _PROFILE_SCAN_BATCH * 2 + 10
    for i in range(n):
        await redis.xadd(_STREAM_KEY, _event(i))

    entries, scanned, _ = await _scan_stream(redis)

    ids = [e[0] for e in entries]
    assert len(ids) == len(set(ids)), "the scan returned duplicate stream entries"
    assert scanned == n


def test_scan_limit_is_bounded_and_reported() -> None:
    """The cap exists and is finite.

    Asserted as a constant rather than by writing 100k entries to fakeredis: the
    behaviour under the cap is covered above, and this is the part a refactor
    could silently remove.
    """
    assert isinstance(_PROFILE_SCAN_LIMIT, int)
    assert 0 < _PROFILE_SCAN_LIMIT < 10_000_000
    assert _PROFILE_SCAN_BATCH < _PROFILE_SCAN_LIMIT


@pytest.mark.asyncio
async def test_scan_stops_at_the_limit(redis) -> None:
    """Truncation is reported, not silently applied.

    Uses a temporarily tiny limit so the assertion is about the mechanism rather
    than about writing 100,000 entries.
    """
    import management.api.routes.connections as conns

    original = conns._PROFILE_SCAN_LIMIT
    conns._PROFILE_SCAN_LIMIT = _PROFILE_SCAN_BATCH  # one batch, then stop
    try:
        for i in range(_PROFILE_SCAN_BATCH * 3):
            await redis.xadd(_STREAM_KEY, _event(i))

        _entries, scanned, truncated = await conns._scan_stream(redis)

        assert truncated is True, "hitting the cap must be reported to the caller"
        assert scanned <= _PROFILE_SCAN_BATCH
    finally:
        conns._PROFILE_SCAN_LIMIT = original


# ── O11 ───────────────────────────────────────────────────────────────────────


def test_suggestion_is_served_only_by_a_read_only_route() -> None:
    """No route may apply a suggestion.

    Scans every registered route for one that both mentions suggestions and
    accepts a mutating method. Written as a search rather than a check of one
    known path so that a future endpoint cannot quietly add one.
    """
    from management.api.main import create_app

    app = create_app()
    offenders = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if "suggest" not in path.lower():
            continue
        if methods - {"GET", "HEAD", "OPTIONS"}:
            offenders.append(f"{sorted(methods)} {path}")

    assert not offenders, f"suggestions must never be appliable: {offenders}"


def test_suggest_action_has_no_side_effects() -> None:
    """It is a pure function of what it is given.

    If it ever grew a Redis handle or a ban call, "advisory" would become a
    documentation claim rather than a property of the code.
    """
    import inspect

    from management.api.event_insight import suggest_action

    src = inspect.getsource(suggest_action)
    for forbidden in ("redis", "await", "requests", "httpx", "ban("):
        assert forbidden not in src, (
            f"suggest_action references {forbidden!r} — it must stay a pure function"
        )
