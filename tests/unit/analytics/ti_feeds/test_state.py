"""Phase 85 — unit tests for ``analytics.ti_feeds.state.FeedState``.

Drives the ``ti_feed:*`` sidecar index defined in PHASE_85.md §2.2 against
fakeredis. Verifies:
- record_created(feed_id, stix_id, handle, kind)
- remove(feed_id, stix_id)
- replace_active_stix_ids(feed_id, new_ids)
- get_active_stix_ids(feed_id)
- read/write of poll_state HASH
- runtime_enabled toggle
- differential cleanup diff computation

These tests are RED until ``src/analytics/ti_feeds/state.py`` exists.
"""

from __future__ import annotations

import asyncio
import os

import pytest


def _run(coro):
    return asyncio.run(coro)


def _import_FeedState():
    from src.analytics.ti_feeds.state import FeedState

    return FeedState


# ── record_created / remove ───────────────────────────────────────────────────


def test_record_created_for_blocklist_resource(fake_redis):
    """A blocklist resource creation populates the active_stix_ids HASH."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="taxii-isac",
            stix_id="indicator--aaaa",
            handle="resource-uuid-1",
            kind="blocklist",
        )
    )

    active = fake_redis.hgetall("ti_feed:taxii-isac:active_stix_ids")
    assert active.get("indicator--aaaa") == "resource-uuid-1"
    assert "resource-uuid-1" in fake_redis.smembers("ti_feed:taxii-isac:blocklist_uuids")


def test_record_created_for_ban(fake_redis):
    """A ban creation populates active_stix_ids and ban_ips."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf",
            stix_id="indicator--bbbb",
            handle="198.51.100.42",
            kind="ban",
        )
    )

    assert fake_redis.hget("ti_feed:rf:active_stix_ids", "indicator--bbbb") == "198.51.100.42"
    assert "198.51.100.42" in fake_redis.smembers("ti_feed:rf:ban_ips")


def test_remove_clears_active_stix_id(fake_redis):
    """Removing an entry clears the HASH and the side index."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf",
            stix_id="indicator--bbbb",
            handle="198.51.100.42",
            kind="ban",
        )
    )
    _run(state.remove("rf", "indicator--bbbb"))

    assert fake_redis.hget("ti_feed:rf:active_stix_ids", "indicator--bbbb") is None
    assert "198.51.100.42" not in fake_redis.smembers("ti_feed:rf:ban_ips")


# ── get_active_stix_ids ───────────────────────────────────────────────────────


def test_get_active_stix_ids_returns_dict(fake_redis):
    """get_active_stix_ids returns a {stix_id → handle} dict."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--a", handle="uuid-a", kind="blocklist"
        )
    )
    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--b", handle="uuid-b", kind="blocklist"
        )
    )

    active = _run(state.get_active_stix_ids("rf"))
    assert isinstance(active, dict)
    assert active == {"indicator--a": "uuid-a", "indicator--b": "uuid-b"}


def test_get_active_stix_ids_empty_for_unknown_feed(fake_redis):
    """An unknown feed returns an empty mapping."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    active = _run(state.get_active_stix_ids("does-not-exist"))
    assert active == {}


# ── replace_active_stix_ids ────────────────────────────────────────────────────


def test_replace_active_stix_ids_overwrites(fake_redis):
    """replace_active_stix_ids drops the old set and writes the new one atomically."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    fake_redis.hset(
        "ti_feed:rf:active_stix_ids",
        mapping={"indicator--old": "uuid-old"},
    )

    _run(
        state.replace_active_stix_ids(
            "rf",
            new_ids={"indicator--new1": "uuid-1", "indicator--new2": "uuid-2"},
        )
    )

    active = fake_redis.hgetall("ti_feed:rf:active_stix_ids")
    assert "indicator--old" not in active
    assert active == {"indicator--new1": "uuid-1", "indicator--new2": "uuid-2"}


# ── poll_state ──────────────────────────────────────────────────────────────────


def test_poll_state_set_and_get(fake_redis):
    """poll_state HASH supports last_success_ts, last_added_after, etc."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.set_poll_state(
            "rf",
            {
                "last_success_ts": "1712534400",
                "last_added_after": "2026-04-08T00:00:00Z",
                "circuit_state": "closed",
                "failure_count": "0",
            },
        )
    )

    record = _run(state.get_poll_state("rf"))
    assert record["last_success_ts"] == "1712534400"
    assert record["last_added_after"] == "2026-04-08T00:00:00Z"
    assert record["circuit_state"] == "closed"


def test_poll_state_unknown_feed_returns_empty_dict(fake_redis):
    """Unknown feeds yield an empty mapping rather than None."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    record = _run(state.get_poll_state("nope"))
    assert record == {}


# ── runtime_enabled toggle ─────────────────────────────────────────────────────


def test_runtime_enabled_unset_returns_none(fake_redis):
    """An unset toggle is None (caller falls back to config)."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    assert _run(state.get_runtime_enabled("rf")) is None


def test_runtime_enabled_toggle_true(fake_redis):
    """Setting the toggle to True writes the documented '1' marker."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(state.set_runtime_enabled("rf", True))
    raw = fake_redis.get("ti_feed:rf:runtime_enabled")
    assert raw == "1"
    assert _run(state.get_runtime_enabled("rf")) is True


def test_runtime_enabled_toggle_false(fake_redis):
    """Setting the toggle to False writes the documented '0' marker."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(state.set_runtime_enabled("rf", False))
    raw = fake_redis.get("ti_feed:rf:runtime_enabled")
    assert raw == "0"
    assert _run(state.get_runtime_enabled("rf")) is False


# ── differential cleanup diff ──────────────────────────────────────────────────


def test_diff_against_seen_returns_dropped_ids(fake_redis):
    """compute_dropped(prev, seen) returns the items present before but not now."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--a", handle="uuid-a", kind="blocklist"
        )
    )
    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--b", handle="uuid-b", kind="blocklist"
        )
    )
    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--c", handle="uuid-c", kind="blocklist"
        )
    )

    dropped = _run(state.compute_dropped("rf", seen={"indicator--a", "indicator--c"}))
    assert dropped == [("indicator--b", "uuid-b")]


def test_diff_with_full_overlap_returns_empty(fake_redis):
    """If every previous indicator is still seen, no diff."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--a", handle="uuid-a", kind="blocklist"
        )
    )
    dropped = _run(state.compute_dropped("rf", seen={"indicator--a"}))
    assert dropped == []


def test_diff_with_empty_seen_drops_everything(fake_redis):
    """Empty seen set drops all previous indicators."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--a", handle="uuid-a", kind="blocklist"
        )
    )
    _run(
        state.record_created(
            feed_id="rf", stix_id="indicator--b", handle="uuid-b", kind="blocklist"
        )
    )

    dropped = _run(state.compute_dropped("rf", seen=set()))
    assert dropped == [
        ("indicator--a", "uuid-a"),
        ("indicator--b", "uuid-b"),
    ]


# ── Per-feed isolation ─────────────────────────────────────────────────────────


def test_two_feeds_do_not_share_state(fake_redis):
    """Each feed_id namespaces its own keys; cross-feed mutation is impossible."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(
        state.record_created(
            feed_id="feed-a", stix_id="ind--x", handle="uuid-ax", kind="blocklist"
        )
    )
    _run(
        state.record_created(
            feed_id="feed-b", stix_id="ind--x", handle="uuid-bx", kind="blocklist"
        )
    )

    a_active = _run(state.get_active_stix_ids("feed-a"))
    b_active = _run(state.get_active_stix_ids("feed-b"))
    assert a_active == {"ind--x": "uuid-ax"}
    assert b_active == {"ind--x": "uuid-bx"}

    _run(state.remove("feed-a", "ind--x"))
    assert _run(state.get_active_stix_ids("feed-b")) == {"ind--x": "uuid-bx"}


# ── Redis error swallowing (coverage gap closure) ────────────────────────────


class _BrokenRedis:
    """Redis stub that raises on every operation. Used to exercise all
    the try/except error-swallowing branches in FeedState."""

    def __init__(self, error=None):
        self._error = error or ConnectionError("simulated Redis failure")

    def __getattr__(self, name):
        def _raise(*args, **kwargs):
            raise self._error
        return _raise

    def pipeline(self):
        return _BrokenPipeline(self._error)


class _BrokenPipeline:
    def __init__(self, error):
        self._error = error

    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            return self
        return _noop

    async def execute(self):
        raise self._error


def _make_broken_state(error=None):
    """Build a FeedState backed by a broken Redis that raises on every call."""
    from src.analytics.ti_feeds.state import FeedState, _SyncRedisShim
    broken = _BrokenRedis(error)
    # Wrap in shim so FeedState sees async methods
    state = FeedState.__new__(FeedState)
    state._redis = _SyncRedisShim(broken)
    return state


@pytest.mark.parametrize("method_name,args,expected", [
    ("add_blocklist_uuid", ("feed1", "uuid-1"), None),
    ("remove_blocklist_uuid", ("feed1", "uuid-1"), None),
    ("get_blocklist_uuids", ("feed1",), set()),
    ("add_ban_ip", ("feed1", "1.2.3.4"), None),
    ("remove_ban_ip", ("feed1", "1.2.3.4"), None),
    ("get_ban_ips", ("feed1",), set()),
    ("get_active_stix_ids", ("feed1",), {}),
    ("get_poll_state", ("feed1",), {}),
    ("get_runtime_override", ("feed1",), None),
    ("set_runtime_override", ("feed1", True), None),
])
def test_redis_error_returns_neutral(method_name, args, expected):
    """Every FeedState method swallows Redis errors and returns a neutral value."""
    state = _make_broken_state()
    method = getattr(state, method_name)
    result = _run(method(*args))
    assert result == expected


def test_mark_swallows_redis_error():
    """mark() swallows pipeline errors."""
    state = _make_broken_state()
    # Should not raise
    _run(state.mark("feed1", "stix-1", "handle-1", "blocklist"))


def test_mark_ban_kind_swallows_redis_error():
    """mark() with kind=ban swallows pipeline errors."""
    state = _make_broken_state()
    _run(state.mark("feed1", "stix-1", "1.2.3.4", "ban"))


def test_clear_handle_swallows_redis_error():
    """clear_handle() swallows pipeline errors for all kinds."""
    state = _make_broken_state()
    _run(state.clear_handle("feed1", "stix-1", "handle-1", "blocklist"))
    _run(state.clear_handle("feed1", "stix-1", "1.2.3.4", "ban"))
    _run(state.clear_handle("feed1", "stix-1", "x", "unknown"))


def test_remove_swallows_redis_error():
    """remove() swallows Redis errors."""
    state = _make_broken_state()
    _run(state.remove("feed1", "stix-1"))


def test_set_poll_state_empty_mapping_returns_early():
    """set_poll_state with empty mapping is a no-op (no Redis call)."""
    FeedState = _import_FeedState()
    state = _make_broken_state()
    # Empty mapping should return early without hitting Redis
    _run(state.set_poll_state("feed1", {}))


def test_set_poll_state_swallows_redis_error():
    """set_poll_state swallows Redis errors."""
    state = _make_broken_state()
    _run(state.set_poll_state("feed1", {"key": "value"}))


def test_replace_active_stix_ids_swallows_redis_error():
    """replace_active_stix_ids swallows pipeline errors."""
    state = _make_broken_state()
    _run(state.replace_active_stix_ids("feed1", {"s1": "h1"}))


def test_replace_active_stix_ids_empty_swallows_redis_error():
    """replace_active_stix_ids with empty dict swallows pipeline errors."""
    state = _make_broken_state()
    _run(state.replace_active_stix_ids("feed1", {}))


def test_record_poll_success_swallows_redis_error():
    """record_poll_success swallows Redis errors."""
    state = _make_broken_state()
    _run(state.record_poll_success(
        "feed1",
        indicators_seen=10,
        created=5,
        removed=2,
        duration_s=1.5,
    ))


def test_record_poll_success_with_added_after_swallows_error():
    """record_poll_success with added_after swallows Redis errors."""
    state = _make_broken_state()
    _run(state.record_poll_success(
        "feed1",
        indicators_seen=10,
        created=5,
        removed=2,
        duration_s=1.5,
        added_after="2026-04-08T00:00:00Z",
    ))


def test_record_poll_failure_swallows_redis_error():
    """record_poll_failure swallows Redis errors."""
    state = _make_broken_state()
    _run(state.record_poll_failure(
        "feed1",
        error_message="test error",
        circuit_state="open",
    ))


def test_set_circuit_state_swallows_redis_error():
    """set_circuit_state swallows Redis errors."""
    state = _make_broken_state()
    _run(state.set_circuit_state("feed1", "half-open"))


def test_try_acquire_leader_returns_false_on_error():
    """try_acquire_leader fails closed (returns False) on Redis error."""
    state = _make_broken_state()
    result = _run(state.try_acquire_leader("instance-1"))
    assert result is False


def test_refresh_leader_returns_true_on_error():
    """refresh_leader returns True on Redis error (fail-safe: keep existing leader)."""
    state = _make_broken_state()
    result = _run(state.refresh_leader("instance-1"))
    assert result is True


# ── Empty streak error swallowing ───────────────────────────────────────────


def test_get_empty_streak_swallows_redis_error():
    """get_empty_streak returns 0 on Redis error."""
    state = _make_broken_state()
    result = _run(state.get_empty_streak("feed1"))
    assert result == 0


def test_bump_empty_streak_swallows_redis_error():
    """bump_empty_streak returns 1 on Redis error."""
    state = _make_broken_state()
    result = _run(state.bump_empty_streak("feed1"))
    assert result == 1


def test_reset_empty_streak_swallows_redis_error():
    """reset_empty_streak swallows Redis error silently."""
    state = _make_broken_state()
    _run(state.reset_empty_streak("feed1"))  # should not raise


# ── Empty streak happy path ─────────────────────────────────────────────────


def test_empty_streak_round_trip(fake_redis):
    """get/bump/reset empty streak work correctly with real Redis."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    assert _run(state.get_empty_streak("feed1")) == 0
    assert _run(state.bump_empty_streak("feed1")) == 1
    assert _run(state.bump_empty_streak("feed1")) == 2
    assert _run(state.get_empty_streak("feed1")) == 2
    _run(state.reset_empty_streak("feed1"))
    assert _run(state.get_empty_streak("feed1")) == 0


def test_get_empty_streak_handles_non_int_value(fake_redis):
    """get_empty_streak returns 0 on non-integer stored value."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)
    fake_redis.set("ti_feed:feed1:empty_streak", "not_a_number")
    result = _run(state.get_empty_streak("feed1"))
    assert result == 0


# ── SyncRedisShim non-callable attribute ────────────────────────────────────


def test_sync_shim_non_callable_passthrough():
    """_SyncRedisShim passes through non-callable attributes directly."""
    from src.analytics.ti_feeds.state import _SyncRedisShim

    class FakeSync:
        some_attr = 42

    shim = _SyncRedisShim(FakeSync())
    assert shim.some_attr == 42


# ── Leader election happy path ──────────────────────────────────────────────


def test_try_acquire_leader_success(fake_redis):
    """First acquire wins, second loses."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    assert _run(state.try_acquire_leader("inst-1")) is True
    assert _run(state.try_acquire_leader("inst-2")) is False


def test_refresh_leader_extends_lock(fake_redis):
    """refresh_leader returns True when we hold the lock, False otherwise."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(state.try_acquire_leader("inst-1"))
    assert _run(state.refresh_leader("inst-1")) is True
    assert _run(state.refresh_leader("inst-2")) is False


# ── remove() with existing handle ───────────────────────────────────────────


def test_remove_decodes_bytes_handle(fake_redis):
    """remove() decodes bytes handle (line 305 coverage)."""
    FeedState = _import_FeedState()
    state = FeedState(fake_redis)

    _run(state.mark("feed1", "stix-1", "handle-1", "blocklist"))
    # Verify it's there
    active = _run(state.get_active_stix_ids("feed1"))
    assert "stix-1" in active
    # Now remove — exercises the handle decode + pipeline cleanup path
    _run(state.remove("feed1", "stix-1"))
    active = _run(state.get_active_stix_ids("feed1"))
    assert "stix-1" not in active


# ── dump_keys_for ───────────────────────────────────────────────────────────


def test_dump_keys_for_returns_expected_keys():
    """dump_keys_for returns all 6 key patterns for a feed."""
    FeedState = _import_FeedState()
    state = FeedState.__new__(FeedState)
    keys = state.dump_keys_for("test-feed")
    assert "blocklist_uuids" in keys
    assert "ban_ips" in keys
    assert "active_stix_ids" in keys
    assert "poll_state" in keys
    assert "runtime_enabled" in keys
    assert "leader_lock" in keys
    assert keys["blocklist_uuids"] == "ti_feed:test-feed:blocklist_uuids"
