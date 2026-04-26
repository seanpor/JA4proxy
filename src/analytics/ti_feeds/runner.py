"""AsyncIO scheduler for the Phase 85 threat-intel feed runner.

Owns:

* The :class:`ManagementClient` singleton used by every feed.
* The :class:`FeedState` wrapper over the shared Redis async client.
* The :class:`CircuitBreakerManager`.
* A dict of ``feed_id → asyncio.Task`` polling tasks.
* The seed-file one-shot loader.
* The config-reload subscriber.

Fail-open invariant: any exception inside the runner is logged + metric-
counted and never allowed to crash the analytics container. The proxy's
hot-path pipeline is entirely unaffected by anything happening here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

from .base import FeedClient, FeedConfig, FeedPollResult
from .circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerManager,
    CircuitState,
)
from .contribution import ContributionClient, ContributionConfig
from .crowdstrike import CrowdStrikeFalconClient
from .metrics import (
    TI_CIRCUIT_STATE as _CIRCUIT_STATE,
)
from .metrics import (
    TI_CLEANUP_REMOVALS as _CLEANUP_REMOVALS,
)
from .metrics import (
    TI_FEED_CAPS_HIT as _TI_FEED_CAPS_HIT,
)
from .metrics import (
    TI_INDICATORS_MANAGED as _INDICATORS_MANAGED,
)
from .metrics import (
    TI_LAST_SUCCESS_TS as _LAST_SUCCESS_TS,
)
from .metrics import (
    TI_POLL_TOTAL as _POLL_TOTAL,
)
from .mgmt_client import ManagementClient
from .recorded_future import RecordedFutureClient
from .rest_generic import RESTGenericClient
from .seed_file import run_once as run_seed_file
from .state import FeedState, compute_dropped_ids
from .taxii import TAXIIClient

logger = logging.getLogger(__name__)


_CIRCUIT_STATE_VALUE = {
    CircuitState.CLOSED: 0,
    CircuitState.HALF_OPEN: 1,
    CircuitState.OPEN: 2,
}

_CLIENT_CLASSES: dict[str, type[FeedClient]] = {
    "taxii2": TAXIIClient,
    "recorded_future": RecordedFutureClient,
    "crowdstrike": CrowdStrikeFalconClient,
    "rest": RESTGenericClient,
}


class FeedRunner:
    """Per-analytics-container feed runner."""

    def __init__(
        self,
        *,
        redis: Any,
        mgmt_base_url: str,
        config: dict[str, Any],
        instance_id: Optional[str] = None,
    ) -> None:
        self._redis = redis
        self._mgmt = ManagementClient(base_url=mgmt_base_url)
        self._state = FeedState(redis)
        self._config = config
        self._instance_id = instance_id or f"runner-{uuid4().hex[:8]}"

        cb_cfg = CircuitBreakerConfig(**(config.get("threat_intel", {}).get("circuit_breaker", {}) or {}))
        self._breakers = CircuitBreakerManager(cb_cfg)

        self._clients: dict[str, FeedClient] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._stopping = asyncio.Event()
        # phase-85 (security review H7): per-feed lock so a manual poll
        # trigger and the scheduled poll loop never run the same feed
        # concurrently and race the leader lock / snapshot replace.
        self._poll_locks: dict[str, asyncio.Lock] = {}
        # phase-85: manual-poll trigger stream consumed in start(). The
        # Management API XADDs to this stream when an Operator hits
        # POST /api/v1/threat-intel/feeds/{id}/poll. We track the last id
        # we've seen so a restart of the analytics container does not
        # replay every historical trigger.
        self._trigger_stream_key = "ti_feed:manual_poll_triggers"
        self._trigger_last_id = "$"
        self._trigger_task: Optional[asyncio.Task] = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the runner: open the mgmt client, load seed, spawn feed tasks."""
        ti_cfg = self._config.get("threat_intel") or {}
        if not ti_cfg.get("enabled", False):
            logger.info("ti_feed | event=runner_disabled | reason=threat_intel.enabled=false")
            return

        try:
            await self._mgmt.connect()
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ti_feed | event=runner_start_failed | reason=mgmt_connect | error=%s",
                exc,
            )
            return

        # One-shot seed file load
        seed_cfg = ti_cfg.get("seed_file", {}) or {}
        if seed_cfg.get("enabled", False):
            try:
                await run_seed_file(
                    mgmt=self._mgmt,
                    state=self._state,
                    path=seed_cfg.get("path", "config/known_bad_fingerprints.yml"),
                    min_entries=int(seed_cfg.get("min_entries", 10)),
                    instance_id=self._instance_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("ti_feed | event=seed_file_start_failed | error=%s", exc)

        # Spawn poll tasks
        await self._rebuild_clients(ti_cfg)

        # Spawn the manual-poll trigger consumer.
        self._trigger_task = asyncio.create_task(self._consume_trigger_stream(), name="ti_feed:trigger_consumer")

    async def stop(self) -> None:
        """Stop the runner. Cancels every poll task and closes the mgmt client."""
        self._stopping.set()
        if self._trigger_task is not None:
            self._trigger_task.cancel()
            try:
                await self._trigger_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._trigger_task = None
        for feed_id, task in list(self._tasks.items()):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        for client in self._clients.values():
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass
        await self._mgmt.close()

    async def reload_config(self, new_config: dict[str, Any]) -> None:
        """Hot-reload hook — called by the ConfigLoader callback."""
        self._config = new_config
        ti_cfg = new_config.get("threat_intel") or {}
        await self._rebuild_clients(ti_cfg)

    # ── client management ───────────────────────────────────────────────

    async def _rebuild_clients(self, ti_cfg: dict[str, Any]) -> None:
        """Diff the feeds in ``ti_cfg`` against current clients and update tasks."""
        feeds_raw = ti_cfg.get("feeds", []) or []
        wanted: dict[str, FeedConfig] = {}
        for raw in feeds_raw:
            if not isinstance(raw, dict):
                continue
            try:
                cfg = FeedConfig.from_dict(raw)
            except Exception as exc:  # noqa: BLE001
                # phase-85 (security review C2): never echo the raw feed
                # config — it carries credentials. Log only the id (if any)
                # and the validation error message.
                logger.warning(
                    "ti_feed | event=feed_config_invalid | feed=%s | error=%s",
                    raw.get("id", "<unknown>"),
                    exc,
                )
                continue
            wanted[cfg.id] = cfg

        # Remove vanished feeds — stop polling, but do NOT delete their rules
        for feed_id in list(self._clients.keys()):
            if feed_id not in wanted:
                await self._stop_feed(feed_id)

        # Add / update remaining feeds
        for feed_id, cfg in wanted.items():
            if feed_id in self._clients:
                # Config may have changed — swap the FeedClient instance
                existing = self._clients[feed_id]
                if type(existing).__name__ == self._client_class_name(cfg.type):
                    existing.config = cfg
                    continue
                await self._stop_feed(feed_id)
            client_cls = _CLIENT_CLASSES.get(cfg.type)
            if client_cls is None:
                logger.warning(
                    "ti_feed | event=feed_type_unknown | feed=%s | type=%s",
                    feed_id,
                    cfg.type,
                )
                continue
            client = client_cls(config=cfg, mgmt=self._mgmt, state=self._state)
            self._clients[feed_id] = client
            self._tasks[feed_id] = asyncio.create_task(self._poll_loop(feed_id), name=f"ti_feed:{feed_id}")
            logger.info(
                "ti_feed | event=feed_started | feed=%s | type=%s | enabled=%s",
                feed_id,
                cfg.type,
                cfg.enabled,
            )

    @staticmethod
    def _client_class_name(feed_type: str) -> str:
        cls = _CLIENT_CLASSES.get(feed_type)
        return cls.__name__ if cls else ""

    async def _stop_feed(self, feed_id: str) -> None:
        """Cancel a feed's poll task without deleting any rules it created."""
        task = self._tasks.pop(feed_id, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        client = self._clients.pop(feed_id, None)
        if client is not None:
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass
        self._breakers.drop(feed_id)
        logger.info(
            "ti_feed | event=feed_stopped | feed=%s | rules_retained=true",
            feed_id,
        )

    # ── poll loop ───────────────────────────────────────────────────────

    async def _poll_loop(self, feed_id: str) -> None:
        """Per-feed poll loop. Runs until the task is cancelled."""
        try:
            while not self._stopping.is_set():
                interval_s = max(
                    60,
                    (self._clients[feed_id].config.poll_interval_minutes or 60) * 60,
                )
                # phase-85 (security review): cap each poll at the poll
                # interval. A trickling TAXII server that holds bytes
                # indefinitely would otherwise wedge this loop and stop
                # all future polls + leader-lock refreshes for this feed.
                poll_timeout = max(60, min(interval_s, 600))
                lock = self._poll_locks.setdefault(feed_id, asyncio.Lock())
                try:
                    async with lock:
                        await asyncio.wait_for(self._poll_once(feed_id), timeout=poll_timeout)
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    logger.error(
                        "ti_feed | event=poll_timeout | feed=%s | timeout_s=%d",
                        feed_id,
                        poll_timeout,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "ti_feed | event=poll_loop_error | feed=%s | error=%s",
                        feed_id,
                        exc,
                    )
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=interval_s)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            return

    async def _poll_once(self, feed_id: str) -> None:
        """Gate, poll, apply differential cleanup, update metrics."""
        client = self._clients.get(feed_id)
        if client is None:
            return

        # Enabled gating: runtime toggle overrides config
        runtime_override = await self._state.get_runtime_override(feed_id)
        if runtime_override is False:
            return
        if runtime_override is None and not client.config.enabled:
            return

        breaker = self._breakers.for_feed(feed_id)
        if not breaker.allow_poll():
            _CIRCUIT_STATE.labels(feed_id=feed_id).set(_CIRCUIT_STATE_VALUE[breaker.state])
            _POLL_TOTAL.labels(feed_id=feed_id, result="circuit_open").inc()
            return

        # Leader-lock gate. C7 (architect review): the lock is **fail-closed**
        # — if Redis is unavailable, ``try_acquire_leader`` returns False and
        # we skip this cycle rather than have every replica simultaneously
        # act as leader. The next cycle retries.
        if not await self._state.try_acquire_leader(self._instance_id, ttl_seconds=30):
            logger.debug(
                "ti_feed | event=not_leader | feed=%s | instance=%s",
                feed_id,
                self._instance_id,
            )
            return

        previous_ids = await self._state.get_active_stix_ids(feed_id)

        # phase-85: hand the previous-id set to the client so its apply path
        # can label re-seen indicators as ``existing`` rather than ``created``
        # in the per-indicator outcome metric. Default-empty fallback (set in
        # FeedClient.__init__) means a fresh feed counts everything as new.
        client.previous_stix_ids = set(previous_ids)

        try:
            result = await client.poll()
        except Exception as exc:  # noqa: BLE001
            breaker.record_failure()
            _CIRCUIT_STATE.labels(feed_id=feed_id).set(_CIRCUIT_STATE_VALUE[breaker.state])
            await self._state.record_poll_failure(
                feed_id,
                error_message=str(exc),
                circuit_state=breaker.state.value,
            )
            await self._state.set_circuit_state(feed_id, breaker.state.value)
            logger.error(
                "ti_feed | event=poll_exception | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return

        # C4: Safety caps enforcement
        cfg = client.config
        original_created_count = len(result.created)

        if cfg.max_new_per_poll > 0 and len(result.created) > cfg.max_new_per_poll:
            result.created = result.created[: cfg.max_new_per_poll]
            _TI_FEED_CAPS_HIT.labels(feed_id=feed_id, kind="new").inc()
            logger.warning(
                "ti_feed | event=feed_capped_new | feed=%s | original=%d | capped=%d",
                feed_id,
                original_created_count,
                cfg.max_new_per_poll,
            )

        if cfg.max_owned_total > 0 and len(previous_ids) >= cfg.max_owned_total:
            result.created = []
            _TI_FEED_CAPS_HIT.labels(feed_id=feed_id, kind="total").inc()
            logger.warning(
                "ti_feed | event=feed_capped_total | feed=%s | owned=%d | max=%d",
                feed_id,
                len(previous_ids),
                cfg.max_owned_total,
            )

        if cfg.max_delta_per_poll > 0:
            delta = len(result.created) - len(previous_ids)
            if abs(delta) > cfg.max_delta_per_poll:
                result.created = []
                _TI_FEED_CAPS_HIT.labels(feed_id=feed_id, kind="delta").inc()
                logger.warning(
                    "ti_feed | event=feed_capped_delta | feed=%s | delta=%d | max=%d",
                    feed_id,
                    delta,
                    cfg.max_delta_per_poll,
                )

        # C5: Two-empty-poll gate. A single empty poll can be an upstream
        # glitch (TAXII 500, mid-poll rotation, etc.). We only run differential
        # cleanup once we've seen two consecutive empties. On the first empty
        # poll we preserve the existing snapshot verbatim so the next real poll
        # can still diff against it.
        empty_streak = await self._state.get_empty_streak(feed_id)
        skip_cleanup_first_empty = False
        if len(result.stix_ids_seen) == 0:
            await self._state.bump_empty_streak(feed_id)
            if empty_streak < 1:
                skip_cleanup_first_empty = True
                logger.info(
                    "ti_feed | event=cleanup_skipped_empty_streak | feed=%s | streak=%d",
                    feed_id,
                    empty_streak + 1,
                )
        else:
            await self._state.reset_empty_streak(feed_id)

        if skip_cleanup_first_empty:
            # Preserve the existing snapshot; do not delete anything this poll.
            breaker.record_success()
            _CIRCUIT_STATE.labels(feed_id=feed_id).set(_CIRCUIT_STATE_VALUE[breaker.state])
            _LAST_SUCCESS_TS.labels(feed_id=feed_id).set(time.time())
            _INDICATORS_MANAGED.labels(feed_id=feed_id).set(len(previous_ids))
            await self._state.record_poll_success(
                feed_id,
                indicators_seen=0,
                created=0,
                removed=0,
                duration_s=result.poll_duration_s,
            )
            self._emit_ecs_log(feed_id, result, 0)
            return

        # Differential cleanup. phase-85 (security review C8): the previous
        # implementation guessed the handle kind from string contents
        # (``"." in handle``) and had an operator-precedence bug that
        # mis-routed empty handles. We now read the kind from the
        # authoritative ``ban_ips`` and ``blocklist_uuids`` sets, and skip
        # any entry with an empty handle (those represent indicators that
        # were idempotently re-applied with no fresh resource).
        # phase-101g M11: returns a sorted list[tuple[str, str]] — already
        # deterministic, callers don't need to re-sort.
        dropped = compute_dropped_ids(previous_ids, result.stix_ids_seen)

        # phase-85.1 (security review C2 partial): cap each cleanup pass
        # at max(10, 10% of the previous snapshot). The full C2 fix
        # (two-consecutive-empty-poll gate, per-feed configurable cap) is
        # tracked in PHASE_101. The 10%-floor-10 cap here is the cheap
        # blast-radius brake: a feed that flips empty for a single cycle
        # because of an upstream glitch can drop at most ~10% of its rule
        # set per poll instead of all of them. Entries we *defer* must be
        # re-added to the new snapshot so the next poll's diff still sees
        # them and can finish (or skip) the cleanup.
        deferred_cleanup: list[tuple[str, str]] = []
        if dropped:
            cap = max(10, len(previous_ids) // 10)
            if len(dropped) > cap:
                logger.warning(
                    "ti_feed | event=cleanup_capped | feed=%s | dropped=%d | cap=%d | previous=%d",
                    feed_id,
                    len(dropped),
                    cap,
                    len(previous_ids),
                )
                # Deterministic split so repeat polls converge instead of
                # churning the same head every cycle. ``dropped`` is already
                # sorted by stix_id (M11) so head/tail slicing is stable.
                deferred_cleanup = dropped[cap:]
                dropped = dropped[:cap]

        ban_ips = await self._state.get_ban_ips(feed_id) if dropped else set()
        blocklist_uuids = await self._state.get_blocklist_uuids(feed_id) if dropped else set()
        # C7 (architect review): per-indicator cleanup is now a two-step
        # ordered operation:
        #   1. Management API delete (idempotent — 404 treated as success).
        #   2. Atomic Redis state clear via FeedState.clear_handle, which
        #      runs hdel + srem in a single MULTI/EXEC transaction.
        # If step 2 fails after step 1 succeeds, the next poll's diff will
        # re-attempt the clear (the handle is still in the side set) and the
        # mgmt API will return 404 — total operation is at-least-once and
        # converges.
        removed_count = 0
        for stix_id, handle in dropped:
            if not handle:
                # No resource to delete — just drop the snapshot entry.
                await self._state.clear_handle(feed_id, stix_id, handle="", kind="unknown")
                continue
            try:
                if handle in ban_ips:
                    kind = "ban"
                    await self._mgmt.delete_ban(handle, feed_id=feed_id)
                elif handle in blocklist_uuids:
                    kind = "blocklist"
                    await self._mgmt.delete_blocklist(handle, feed_id=feed_id)
                else:
                    logger.warning(
                        "ti_feed | event=cleanup_unknown_handle | feed=%s | stix_id=%s",
                        feed_id,
                        stix_id,
                    )
                    await self._state.clear_handle(feed_id, stix_id, handle=handle, kind="unknown")
                    continue
                await self._state.clear_handle(feed_id, stix_id, handle=handle, kind=kind)
                removed_count += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ti_feed | event=cleanup_failed | feed=%s | stix_id=%s | error=%s",
                    feed_id,
                    stix_id,
                    exc,
                )

        if removed_count:
            _CLEANUP_REMOVALS.labels(feed_id=feed_id).inc(removed_count)

        # Replace the active snapshot atomically. phase-85.1 (C2 partial):
        # carry deferred-cleanup entries forward so the next poll's diff
        # still sees them as candidates for removal.
        snapshot = {stix_id: handle for stix_id, handle in _result_handle_iter(result)}
        for stix_id, handle in deferred_cleanup:
            snapshot.setdefault(stix_id, handle)
        await self._state.replace_active_stix_ids(feed_id, snapshot)

        # Poll state / metrics
        breaker.record_success()
        _CIRCUIT_STATE.labels(feed_id=feed_id).set(_CIRCUIT_STATE_VALUE[breaker.state])
        _LAST_SUCCESS_TS.labels(feed_id=feed_id).set(time.time())
        _INDICATORS_MANAGED.labels(feed_id=feed_id).set(len(result.stix_ids_seen))
        await self._state.record_poll_success(
            feed_id,
            indicators_seen=len(result.stix_ids_seen),
            created=len(result.created),
            removed=removed_count,
            duration_s=result.poll_duration_s,
        )

        self._emit_ecs_log(feed_id, result, removed_count)

    def _emit_ecs_log(
        self,
        feed_id: str,
        result: FeedPollResult,
        removed: int,
    ) -> None:
        """Emit the Phase 80 ECS structured log line for this poll."""
        payload = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "kind": "event",
                "category": ["threat"],
                "action": "ti_feed.poll_complete",
                "outcome": "success" if not result.errors else "failure",
            },
            "feed": {
                "id": feed_id,
                "type": (self._clients[feed_id].config.type if feed_id in self._clients else "unknown"),
                "poll_duration_ms": int(result.poll_duration_s * 1000),
                "indicators_seen": len(result.stix_ids_seen),
                "created": len(result.created),
                "removed": removed,
                "skipped": result.skipped_below_confidence,
            },
        }
        logger.info(json.dumps(payload, separators=(",", ":")))

    # ── manual poll trigger (used by the Management API route) ─────────

    async def _consume_trigger_stream(self) -> None:
        """Consume the manual-poll trigger Redis stream forever.

        The Management API publishes one entry per Operator-issued
        ``POST /api/v1/threat-intel/feeds/{id}/poll`` to
        ``ti_feed:manual_poll_triggers`` (XADD with maxlen=1000). We do
        a blocking XREAD against the stream and dispatch each entry to
        :meth:`trigger_poll`.

        Per-replica state: ``self._trigger_last_id`` starts at ``"$"`` so
        each analytics replica only sees triggers issued *after* it
        booted — historical entries are not replayed. Leader gating
        inside :meth:`_poll_once` ensures only one replica actually
        polls when multiple replicas see the same trigger.
        """
        backoff = 1.0
        while not self._stopping.is_set():
            try:
                resp = await self._redis.xread(
                    {self._trigger_stream_key: self._trigger_last_id},
                    block=5000,
                    count=16,
                )
                backoff = 1.0
                if not resp:
                    continue
                for _stream, entries in resp:
                    for entry_id, fields in entries:
                        if isinstance(entry_id, bytes):
                            entry_id = entry_id.decode()
                        self._trigger_last_id = entry_id
                        decoded = {
                            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                            for k, v in fields.items()
                        }
                        feed_id = decoded.get("feed_id", "")
                        poll_id = decoded.get("poll_id", "")
                        if not feed_id:
                            continue
                        logger.info(
                            "ti_feed | event=manual_poll_received | feed=%s | poll_id=%s | requested_by=%s",
                            feed_id,
                            poll_id,
                            decoded.get("requested_by", "<unknown>"),
                        )
                        await self.trigger_poll(feed_id)
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001 — fail open
                logger.warning(
                    "ti_feed | event=trigger_consumer_error | error=%s | backoff_s=%.1f",
                    exc,
                    backoff,
                )
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 30.0)

    async def trigger_poll(self, feed_id: str) -> Optional[str]:
        """Request an immediate poll, returning a poll-id string.

        Per-feed serialisation: a manual trigger that arrives while the
        feed is mid-poll is coalesced — we acquire the per-feed lock,
        which blocks until the in-flight poll completes, then runs one
        more cycle. Multiple triggers stacked up while the loop is busy
        collapse to at most one extra poll.

        Returns None if the feed is not registered with the runner.
        Exceptions are swallowed per the fail-open invariant.
        """
        if feed_id not in self._clients:
            return None
        poll_id = uuid4().hex
        lock = self._poll_locks.setdefault(feed_id, asyncio.Lock())

        async def _runner() -> None:
            async with lock:
                try:
                    await self._poll_once(feed_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "ti_feed | event=manual_poll_failed | feed=%s | poll_id=%s | error=%s",
                        feed_id,
                        poll_id,
                        exc,
                    )

        asyncio.create_task(_runner(), name=f"ti_feed:manual:{feed_id}")
        return poll_id


def _result_handle_iter(result: FeedPollResult):
    """Yield ``(stix_id, handle)`` tuples suitable for replacing the active HASH.

    The handle is the resource UUID (or raw IP) created for the indicator.
    When the same stix_id appears multiple times in ``created`` (which should
    never happen but is handled defensively), the last write wins.
    """
    for stix_id, handle in result.created:
        yield stix_id, handle
    # Also include indicators we saw but that did not produce a created entry
    # (idempotency: the Management API returned an existing resource). We
    # keep them in the snapshot so differential cleanup counts them as
    # "still present".
    created_ids = {s for s, _ in result.created}
    for stix_id in result.stix_ids_seen:
        if stix_id in created_ids:
            continue
        yield stix_id, ""  # no handle → still in snapshot, no cleanup candidate
