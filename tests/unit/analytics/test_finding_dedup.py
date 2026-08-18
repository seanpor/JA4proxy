"""Phase 827 — a repeating detection must not repeat in the operator's list.

WHY THIS EXISTS
---------------
Detection runs on a timer, and a subnet or fingerprint that qualifies once
generally qualifies on every subsequent cycle. Writing a finding each time
produced a column of identical entries — spotted immediately by an operator
looking at the Intelligence panel:

    MEDIUM 85%  slowscan  45 IPs in 172.25.200.0/24 made 112 connections ...
    MEDIUM 85%  slowscan  45 IPs in 172.25.200.0/24 made 112 connections ...
    MEDIUM 85%  slowscan  45 IPs in 172.25.200.0/24 made 111 connections ...

The panel looks busy while saying one thing, and a genuinely new finding gets
pushed off the bottom by copies of an old one — so the duplication actively
hides the signal it is burying.

The first fix covered only JA4 findings; campaign and slowscan still repeated.
These tests cover all three, which is the point: the bug was an omission, so
the guard has to be exhaustive rather than aimed at the one case that was seen.
"""

from __future__ import annotations

import fakeredis.aioredis
import pytest

from src.analytics.stream_consumer import _FINDING_DEDUP_TTL_S, StreamConsumer


@pytest.fixture
def consumer():
    c = StreamConsumer("redis://localhost:6379/0")
    c.redis = fakeredis.aioredis.FakeRedis()
    return c


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["campaign", "slowscan", "ja4"])
async def test_first_claim_wins_and_second_is_suppressed(consumer, kind):
    subject = "172.25.200.0/24"
    assert await consumer._claim_finding(kind, subject) is True
    assert await consumer._claim_finding(kind, subject) is False


@pytest.mark.asyncio
async def test_distinct_subjects_do_not_suppress_each_other(consumer):
    """Two different subnets under attack are two findings, not one."""
    assert await consumer._claim_finding("slowscan", "10.0.0.0/24") is True
    assert await consumer._claim_finding("slowscan", "10.0.1.0/24") is True


@pytest.mark.asyncio
async def test_kinds_are_independent(consumer):
    """The same subnet can legitimately be both a campaign and a slow scan."""
    assert await consumer._claim_finding("campaign", "10.0.0.0/24") is True
    assert await consumer._claim_finding("slowscan", "10.0.0.0/24") is True


@pytest.mark.asyncio
async def test_claim_expires_so_a_persistent_offender_resurfaces(consumer):
    """Suppression is temporary by design.

    A permanent marker would mean an attack that continues for hours is
    reported once and then never mentioned again — the opposite failure to
    duplication, and a worse one.
    """
    await consumer._claim_finding("slowscan", "10.0.0.0/24")
    ttl = await consumer.redis.ttl("analytics:finding:seen:slowscan:10.0.0.0/24")
    assert 0 < ttl <= _FINDING_DEDUP_TTL_S
    assert _FINDING_DEDUP_TTL_S >= 300, "too short to actually suppress a cycle"


@pytest.mark.asyncio
async def test_fails_open_when_redis_is_unavailable(consumer):
    """A duplicate is better than a dropped finding.

    Consistent with the project's fail-open rule: losing a finding an operator
    needs is worse than showing it twice.
    """
    import redis as redis_pkg

    class Broken:
        async def set(self, *a, **k):
            raise redis_pkg.RedisError("down")

    consumer.redis = Broken()
    assert await consumer._claim_finding("slowscan", "10.0.0.0/24") is True


@pytest.mark.asyncio
async def test_every_write_finding_call_is_guarded():
    """Structural: a new finding type must not reintroduce the bug.

    Checks the source rather than behaviour, because the failure is an
    omission — a fourth detector added later would be un-guarded and nothing
    behavioural would notice until it duplicated in production.
    """
    import ast
    import inspect

    from src.analytics import stream_consumer

    src = inspect.getsource(stream_consumer.StreamConsumer.run_detection_cycle)
    tree = ast.parse(src.lstrip() if src.startswith(" ") else src)

    writes = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and getattr(n.func, "id", getattr(n.func, "attr", "")) == "write_finding"
    )
    claims = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and getattr(n.func, "attr", "") == "_claim_finding"
    )
    assert writes > 0, "no write_finding calls found — did the method move?"
    assert claims >= writes, (
        f"{writes} write_finding call(s) but only {claims} _claim_finding "
        "guard(s) — an unguarded finding type will duplicate on every "
        "detection cycle"
    )
