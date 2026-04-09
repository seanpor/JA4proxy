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
    assert dropped == {"indicator--b": "uuid-b"}


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
    assert dropped == {}


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
    assert set(dropped.keys()) == {"indicator--a", "indicator--b"}


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
