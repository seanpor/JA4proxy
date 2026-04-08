"""Redis sidecar index for the Phase 85 threat-intel feed runner.

Six key patterns per PHASE_85.md §2.2:

    ti_feed:{feed_id}:blocklist_uuids  — SET of resource UUIDs
    ti_feed:{feed_id}:ban_ips          — SET of IP strings
    ti_feed:{feed_id}:active_stix_ids  — HASH stix_id -> handle
    ti_feed:{feed_id}:poll_state       — HASH (last_success_ts, ...)
    ti_feed:{feed_id}:runtime_enabled  — String "0"/"1"
    ti_feed:leader_lock                — String + TTL (shared, single-key)

The Management API does not know about any of these — they are internal to
the feed runner and serve two purposes:

1. Provenance per feed, so cleanup touches only rules this feed created.
2. Differential cleanup, so indicators that disappear from a feed are
   removed from the Management API on the next poll.

``FeedState`` is a thin wrapper around an async Redis client
(``redis.asyncio.Redis``). All methods swallow Redis errors and return a
neutral value — the runner logs + metric-counts and moves on.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


_KEY_BLOCKLIST_UUIDS = "ti_feed:{feed_id}:blocklist_uuids"
_KEY_BAN_IPS = "ti_feed:{feed_id}:ban_ips"
_KEY_ACTIVE_STIX = "ti_feed:{feed_id}:active_stix_ids"
_KEY_POLL_STATE = "ti_feed:{feed_id}:poll_state"
_KEY_RUNTIME_ENABLED = "ti_feed:{feed_id}:runtime_enabled"
_KEY_LEADER_LOCK = "ti_feed:leader_lock"


def compute_dropped_ids(
    previous: dict[str, str],
    current: set[str],
) -> dict[str, str]:
    """Return the ``stix_id → handle`` mapping that was present previously but
    is absent from the latest poll.

    The caller uses the returned mapping to issue delete calls against the
    Management API in the order ``(stix_id, handle)`` pairs are returned.
    ``handle`` is either a blocklist resource UUID or a raw IP string.

    This is a pure function — it does not touch Redis. Isolated so it can be
    unit-tested without a Redis backend.
    """
    return {stix_id: handle for stix_id, handle in previous.items() if stix_id not in current}


class FeedState:
    """Async Redis wrapper for the six ``ti_feed:*`` keys.

    Args:
        redis: A ``redis.asyncio.Redis`` client. The runner injects the same
            instance used by the rest of the analytics container so there is
            one connection pool.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    # ── blocklist UUID set ────────────────────────────────────────────────

    async def add_blocklist_uuid(self, feed_id: str, resource_uuid: str) -> None:
        """Record a blocklist resource UUID created by this feed."""
        try:
            await self._redis.sadd(
                _KEY_BLOCKLIST_UUIDS.format(feed_id=feed_id),
                resource_uuid,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=blocklist_uuids | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def remove_blocklist_uuid(self, feed_id: str, resource_uuid: str) -> None:
        """Forget a blocklist resource UUID (after a successful delete call)."""
        try:
            await self._redis.srem(
                _KEY_BLOCKLIST_UUIDS.format(feed_id=feed_id),
                resource_uuid,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=blocklist_uuids | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def get_blocklist_uuids(self, feed_id: str) -> set[str]:
        """Return every blocklist UUID currently attributed to this feed."""
        try:
            members = await self._redis.smembers(
                _KEY_BLOCKLIST_UUIDS.format(feed_id=feed_id)
            )
            return {m.decode() if isinstance(m, bytes) else m for m in members}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=blocklist_uuids | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return set()

    # ── ban IP set ────────────────────────────────────────────────────────

    async def add_ban_ip(self, feed_id: str, ip: str) -> None:
        """Record an IP banned by this feed."""
        try:
            await self._redis.sadd(_KEY_BAN_IPS.format(feed_id=feed_id), ip)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=ban_ips | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def remove_ban_ip(self, feed_id: str, ip: str) -> None:
        """Forget an IP after a successful un-ban call."""
        try:
            await self._redis.srem(_KEY_BAN_IPS.format(feed_id=feed_id), ip)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=ban_ips | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def get_ban_ips(self, feed_id: str) -> set[str]:
        """Return every IP currently attributed to this feed."""
        try:
            members = await self._redis.smembers(_KEY_BAN_IPS.format(feed_id=feed_id))
            return {m.decode() if isinstance(m, bytes) else m for m in members}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=ban_ips | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return set()

    # ── active STIX id set (for differential cleanup) ────────────────────

    async def get_active_stix_ids(self, feed_id: str) -> dict[str, str]:
        """Return the previous-poll ``stix_id → handle`` mapping."""
        try:
            raw = await self._redis.hgetall(
                _KEY_ACTIVE_STIX.format(feed_id=feed_id)
            )
            return {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in raw.items()
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=active_stix_ids | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return {}

    async def mark(
        self,
        feed_id: str,
        stix_id: str,
        handle: str,
        kind: str,
    ) -> None:
        """Record a ``(stix_id, handle)`` pair for the current poll.

        ``kind`` is one of ``"blocklist"`` or ``"ban"`` and is persisted in
        the set indices above. The ``active_stix_ids`` HASH is replaced
        atomically at the end of the poll via :meth:`replace_active_stix_ids`.
        """
        try:
            pipe = self._redis.pipeline()
            pipe.hset(
                _KEY_ACTIVE_STIX.format(feed_id=feed_id),
                stix_id,
                handle,
            )
            if kind == "blocklist":
                pipe.sadd(
                    _KEY_BLOCKLIST_UUIDS.format(feed_id=feed_id),
                    handle,
                )
            elif kind == "ban":
                pipe.sadd(_KEY_BAN_IPS.format(feed_id=feed_id), handle)
            await pipe.execute()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=mark | feed=%s | stix_id=%s | error=%s",
                feed_id,
                stix_id,
                exc,
            )

    async def remove(self, feed_id: str, stix_id: str) -> None:
        """Remove an entry from the active STIX id HASH (cleanup path)."""
        try:
            await self._redis.hdel(
                _KEY_ACTIVE_STIX.format(feed_id=feed_id),
                stix_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=remove_stix | feed=%s | stix_id=%s | error=%s",
                feed_id,
                stix_id,
                exc,
            )

    async def replace_active_stix_ids(
        self,
        feed_id: str,
        new_ids: dict[str, str],
    ) -> None:
        """Atomically replace the ``active_stix_ids`` HASH with ``new_ids``.

        Called at the *end* of a successful poll, *after* the caller has
        computed and applied the diff against the previous snapshot — see
        the runner pseudo-code in PHASE_85.md §5.3. Doing it earlier
        would lose the information needed for differential cleanup.
        """
        key = _KEY_ACTIVE_STIX.format(feed_id=feed_id)
        try:
            pipe = self._redis.pipeline()
            pipe.delete(key)
            if new_ids:
                pipe.hset(key, mapping=new_ids)
            await pipe.execute()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=replace_active | feed=%s | error=%s",
                feed_id,
                exc,
            )

    # ── poll state HASH ───────────────────────────────────────────────────

    async def get_poll_state(self, feed_id: str) -> dict[str, str]:
        """Return the ``poll_state`` HASH (empty dict on Redis error)."""
        try:
            raw = await self._redis.hgetall(
                _KEY_POLL_STATE.format(feed_id=feed_id)
            )
            return {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in raw.items()
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=poll_state | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return {}

    async def record_poll_success(
        self,
        feed_id: str,
        *,
        indicators_seen: int,
        created: int,
        removed: int,
        duration_s: float,
        added_after: Optional[str] = None,
    ) -> None:
        """Update ``poll_state`` after a successful poll."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            mapping: dict[str, str] = {
                "last_success_ts": now,
                "last_indicators_seen": str(indicators_seen),
                "last_created": str(created),
                "last_removed": str(removed),
                "last_duration_s": f"{duration_s:.3f}",
                "consecutive_successes": str(
                    int((await self.get_poll_state(feed_id)).get("consecutive_successes", "0")) + 1
                ),
                "failure_count": "0",
                "last_error": "",
            }
            if added_after is not None:
                mapping["last_added_after"] = added_after
            await self._redis.hset(
                _KEY_POLL_STATE.format(feed_id=feed_id),
                mapping=mapping,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=poll_state_success | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def record_poll_failure(
        self,
        feed_id: str,
        *,
        error_message: str,
        circuit_state: str,
    ) -> None:
        """Update ``poll_state`` after a failed poll."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            existing = await self.get_poll_state(feed_id)
            failures = int(existing.get("failure_count", "0")) + 1
            mapping = {
                "last_error_ts": now,
                "last_error": error_message[:512],  # cap for log sanity
                "failure_count": str(failures),
                "consecutive_successes": "0",
                "circuit_state": circuit_state,
            }
            await self._redis.hset(
                _KEY_POLL_STATE.format(feed_id=feed_id),
                mapping=mapping,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=poll_state_failure | feed=%s | error=%s",
                feed_id,
                exc,
            )

    async def set_circuit_state(self, feed_id: str, new_state: str) -> None:
        """Persist a circuit-breaker state transition."""
        try:
            await self._redis.hset(
                _KEY_POLL_STATE.format(feed_id=feed_id),
                "circuit_state",
                new_state,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=circuit_state | feed=%s | error=%s",
                feed_id,
                exc,
            )

    # ── runtime toggle ────────────────────────────────────────────────────

    async def get_runtime_override(self, feed_id: str) -> Optional[bool]:
        """Return ``True``/``False`` if an operator has set the runtime toggle,
        or ``None`` if the toggle is unset (caller falls back to config).
        """
        try:
            raw = await self._redis.get(
                _KEY_RUNTIME_ENABLED.format(feed_id=feed_id)
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=runtime_enabled | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return None
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return raw == "1"

    async def set_runtime_override(self, feed_id: str, enabled: bool) -> None:
        """Write the runtime toggle used by the Management API enable/disable routes."""
        try:
            await self._redis.set(
                _KEY_RUNTIME_ENABLED.format(feed_id=feed_id),
                "1" if enabled else "0",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_write_failed | key=runtime_enabled | feed=%s | error=%s",
                feed_id,
                exc,
            )

    # ── leader election (Phase 8 pattern) ─────────────────────────────────

    async def try_acquire_leader(
        self,
        instance_id: str,
        ttl_seconds: int = 30,
    ) -> bool:
        """Attempt to acquire the shared leader lock.

        Returns ``True`` if this instance won the election or if Redis is
        unavailable (fail-open: if we cannot tell who the leader is, act as
        leader so polling does not stop entirely).
        """
        try:
            result = await self._redis.set(
                _KEY_LEADER_LOCK,
                instance_id,
                nx=True,
                ex=ttl_seconds,
            )
            return result is not None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=leader_lock | error=%s",
                exc,
            )
            return True

    async def refresh_leader(
        self,
        instance_id: str,
        ttl_seconds: int = 30,
    ) -> bool:
        """Extend the leader lock if this instance still holds it."""
        try:
            current = await self._redis.get(_KEY_LEADER_LOCK)
            if isinstance(current, bytes):
                current = current.decode()
            if current == instance_id:
                await self._redis.expire(_KEY_LEADER_LOCK, ttl_seconds)
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ti_feed | event=state_read_failed | key=leader_lock_refresh | error=%s",
                exc,
            )
            return True

    # ── debug helper ──────────────────────────────────────────────────────

    def dump_keys_for(self, feed_id: str) -> dict[str, str]:
        """Return the six key names this state module uses for a given feed.

        Not async — just string formatting. Handy for logs and unit tests.
        """
        return {
            "blocklist_uuids": _KEY_BLOCKLIST_UUIDS.format(feed_id=feed_id),
            "ban_ips": _KEY_BAN_IPS.format(feed_id=feed_id),
            "active_stix_ids": _KEY_ACTIVE_STIX.format(feed_id=feed_id),
            "poll_state": _KEY_POLL_STATE.format(feed_id=feed_id),
            "runtime_enabled": _KEY_RUNTIME_ENABLED.format(feed_id=feed_id),
            "leader_lock": _KEY_LEADER_LOCK,
        }
