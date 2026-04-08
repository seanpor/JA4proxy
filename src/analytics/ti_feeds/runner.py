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

from prometheus_client import Counter, Gauge

from .base import FeedClient, FeedConfig, FeedPollResult
from .circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerManager,
    CircuitState,
)
from .contribution import ContributionClient, ContributionConfig
from .crowdstrike import CrowdStrikeFalconClient
from .mgmt_client import ManagementClient
from .recorded_future import RecordedFutureClient
from .rest_generic import RESTGenericClient
from .seed_file import run_once as run_seed_file
from .state import FeedState, compute_dropped_ids
from .taxii import TAXIIClient

logger = logging.getLogger(__name__)


# ── Prometheus metrics ────────────────────────────────────────────────────────

_INDICATORS_MANAGED = Gauge(
    "ja4proxy_ti_feed_indicators_managed",
    "Current number of indicators managed by a TI feed",
    ["feed_id"],
)
_CLEANUP_REMOVALS = Counter(
    "ja4proxy_ti_feed_cleanup_removals_total",
    "Indicators removed by TI feed differential cleanup",
    ["feed_id"],
)
_CIRCUIT_STATE = Gauge(
    "ja4proxy_ti_feed_circuit_state",
    "TI feed circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["feed_id"],
)
_LAST_SUCCESS_TS = Gauge(
    "ja4proxy_ti_feed_last_success_timestamp_seconds",
    "Unix timestamp of the last successful TI feed poll",
    ["feed_id"],
)


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

        cb_cfg = CircuitBreakerConfig(
            **(
                config.get("threat_intel", {}).get("circuit_breaker", {})
                or {}
            )
        )
        self._breakers = CircuitBreakerManager(cb_cfg)

        self._clients: dict[str, FeedClient] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._stopping = asyncio.Event()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the runner: open the mgmt client, load seed, spawn feed tasks."""
        ti_cfg = self._config.get("threat_intel") or {}
        if not ti_cfg.get("enabled", False):
            logger.info(
                "ti_feed | event=runner_disabled | reason=threat_intel.enabled=false"
            )
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
                    path=seed_cfg.get(
                        "path", "config/known_bad_fingerprints.yml"
                    ),
                    min_entries=int(seed_cfg.get("min_entries", 10)),
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "ti_feed | event=seed_file_start_failed | error=%s", exc
                )

        # Spawn poll tasks
        await self._rebuild_clients(ti_cfg)

    async def stop(self) -> None:
        """Stop the runner. Cancels every poll task and closes the mgmt client."""
        self._stopping.set()
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
                logger.warning(
                    "ti_feed | event=feed_config_invalid | error=%s | raw=%s",
                    exc,
                    raw,
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
            self._tasks[feed_id] = asyncio.create_task(
                self._poll_loop(feed_id), name=f"ti_feed:{feed_id}"
            )
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
                try:
                    await self._poll_once(feed_id)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "ti_feed | event=poll_loop_error | feed=%s | error=%s",
                        feed_id,
                        exc,
                    )
                interval_s = max(
                    60,
                    (self._clients[feed_id].config.poll_interval_minutes or 60)
                    * 60,
                )
                try:
                    await asyncio.wait_for(
                        self._stopping.wait(), timeout=interval_s
                    )
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
            _CIRCUIT_STATE.labels(feed_id=feed_id).set(
                _CIRCUIT_STATE_VALUE[breaker.state]
            )
            return

        # Optional leader-lock — if another analytics replica is leading,
        # skip this cycle. Fail-open: no Redis → act as leader.
        if not await self._state.try_acquire_leader(
            self._instance_id, ttl_seconds=30
        ):
            logger.debug(
                "ti_feed | event=not_leader | feed=%s | instance=%s",
                feed_id,
                self._instance_id,
            )
            return

        previous_ids = await self._state.get_active_stix_ids(feed_id)

        try:
            result = await client.poll()
        except Exception as exc:  # noqa: BLE001
            breaker.record_failure()
            _CIRCUIT_STATE.labels(feed_id=feed_id).set(
                _CIRCUIT_STATE_VALUE[breaker.state]
            )
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

        # Differential cleanup
        dropped = compute_dropped_ids(previous_ids, result.stix_ids_seen)
        removed_count = 0
        for stix_id, handle in dropped.items():
            try:
                if handle and handle.count(".") >= 1 or ":" in (handle or ""):
                    # Looks like an IP
                    await self._mgmt.delete_ban(handle, feed_id=feed_id)
                    await self._state.remove_ban_ip(feed_id, handle)
                else:
                    await self._mgmt.delete_blocklist(handle, feed_id=feed_id)
                    await self._state.remove_blocklist_uuid(feed_id, handle)
                await self._state.remove(feed_id, stix_id)
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

        # Replace the active snapshot atomically
        await self._state.replace_active_stix_ids(
            feed_id,
            {stix_id: handle for stix_id, handle in _result_handle_iter(result)},
        )

        # Poll state / metrics
        breaker.record_success()
        _CIRCUIT_STATE.labels(feed_id=feed_id).set(
            _CIRCUIT_STATE_VALUE[breaker.state]
        )
        _LAST_SUCCESS_TS.labels(feed_id=feed_id).set(time.time())
        _INDICATORS_MANAGED.labels(feed_id=feed_id).set(
            len(result.stix_ids_seen)
        )
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
                "type": (
                    self._clients[feed_id].config.type
                    if feed_id in self._clients
                    else "unknown"
                ),
                "poll_duration_ms": int(result.poll_duration_s * 1000),
                "indicators_seen": len(result.stix_ids_seen),
                "created": len(result.created),
                "removed": removed,
                "skipped": result.skipped_below_confidence,
            },
        }
        logger.info(json.dumps(payload, separators=(",", ":")))

    # ── manual poll trigger (used by the Management API route) ─────────

    async def trigger_poll(self, feed_id: str) -> Optional[str]:
        """Request an immediate poll, returning a poll-id string.

        Returns None if the feed is not registered with the runner.
        Exceptions are swallowed per the fail-open invariant.
        """
        if feed_id not in self._clients:
            return None
        poll_id = uuid4().hex
        asyncio.create_task(self._poll_once(feed_id))
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
