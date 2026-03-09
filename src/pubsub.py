"""Redis pub/sub handler for cross-instance state synchronisation.

Channel: ``ja4proxy:invalidate``

Message types handled:

  whitelist_remove    Remove a JA4 fingerprint from the local whitelist cache
                      and in-process whitelist set. Effect: that fingerprint
                      will be re-evaluated from Redis on the next connection.

  ban_release         Release a per-IP ban immediately. The ban Redis key will
                      be deleted by the caller; this message propagates the
                      removal to all instances' local caches.

  ja4_blacklist_add   Add a JA4 fingerprint to the in-process blacklist set
                      so it is hard-blocked without waiting for the next
                      pipeline lookup cycle.

  dial_change         Update the dial value in all instances' local caches.
                      The authoritative value is in Redis (config:dial) but
                      the local cache is the hot-path read.

  config_reload       Trigger a hot reload of proxy.yml on all instances.
                      Same effect as SIGHUP.

  cidr_ban_add        Add a CIDR to the in-process BlocklistManager pytricia
                      trie immediately (Phase 11 — RDAP block expansion).
                      Published by RDAPEnricher._apply_expansion() when a
                      CIDR is auto-expanded. All other instances call
                      BlocklistManager.load_cidrs() to update their tries.

Design notes:
- Only removals, releases, and secops admin actions use pub/sub for
  immediate propagation. New blocks propagate via TTL + next lookup.
- The subscriber runs as a background asyncio Task; it never blocks
  the connection-handling hot path.
- On disconnect the subscriber reconnects with exponential backoff
  (1s → 2s → 4s → ... → 60s cap). A Prometheus counter tracks
  reconnect events so Grafana can alert on persistent Redis problems.
"""

import asyncio
import json
import logging
from typing import TYPE_CHECKING

from prometheus_client import Counter

if TYPE_CHECKING:
    from .cache.local_cache import LocalCache
    from .config.loader import ConfigLoader

logger = logging.getLogger(__name__)

CHANNEL = "ja4proxy:invalidate"

_PUBSUB_ERRORS = Counter(
    "ja4proxy_pubsub_errors_total",
    "Pub/sub connection errors and reconnects",
    ["reason"],
)
_PUBSUB_MESSAGES = Counter(
    "ja4proxy_pubsub_messages_total",
    "Pub/sub messages handled by type",
    ["msg_type"],
)


class PubSubHandler:
    """Subscribe to the ja4proxy invalidation channel and update local state.

    Args:
        redis_client: An ``redis.asyncio`` client instance (not a connection
                      pool reference — the handler keeps its own subscription).
        local_cache: The process-local :class:`~src.cache.local_cache.LocalCache`.
        config_loader: The :class:`~src.config.loader.ConfigLoader` to call
                       on ``config_reload`` messages.
        blacklist_set: Mutable ``set[str]`` of JA4 blacklisted fingerprints.
                       Updated in-place on ``ja4_blacklist_add`` messages.
        whitelist_set: Mutable ``set[str]`` of JA4 whitelisted fingerprints.
                       Updated in-place on ``whitelist_remove`` messages.
    """

    def __init__(
        self,
        redis_client: object,
        local_cache: "LocalCache",
        config_loader: "ConfigLoader",
        blacklist_set: set,
        whitelist_set: set,
        blocklist_manager: object = None,
    ) -> None:
        self._redis = redis_client
        self._cache = local_cache
        self._config_loader = config_loader
        self._blacklist = blacklist_set
        self._whitelist = whitelist_set
        self._blocklist_manager = blocklist_manager

    async def run(self) -> None:
        """Subscribe and process messages forever, reconnecting on error.

        This coroutine is intended to run as a long-lived asyncio Task::

            asyncio.create_task(pubsub_handler.run())

        It never returns under normal operation. On shutdown, cancel the task.
        """
        backoff = 1.0
        while True:
            try:
                async with self._redis.pubsub() as ps:
                    await ps.subscribe(CHANNEL)
                    backoff = 1.0  # Reset backoff on successful connection
                    logger.info(
                        "pubsub | event=subscribed | channel=%s", CHANNEL
                    )
                    async for raw_message in ps.listen():
                        if raw_message["type"] != "message":
                            continue
                        await self._dispatch(raw_message["data"])
            except asyncio.CancelledError:
                raise  # Propagate shutdown signal
            except Exception as exc:  # noqa: BLE001
                _PUBSUB_ERRORS.labels(reason="disconnect").inc()
                logger.warning(
                    "pubsub | event=disconnected | error=%s | reconnect_in=%.1fs",
                    exc,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    async def _dispatch(self, data: bytes | str) -> None:
        """Parse and dispatch a single pub/sub message."""
        try:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            msg = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("pubsub | event=malformed_message | error=%s", exc)
            _PUBSUB_ERRORS.labels(reason="malformed").inc()
            return

        msg_type = msg.get("type", "")
        value = msg.get("value")
        _PUBSUB_MESSAGES.labels(msg_type=msg_type).inc()

        match msg_type:
            case "whitelist_remove":
                if value:
                    self._cache.whitelist_decisions.delete(str(value))
                    self._whitelist.discard(str(value))
                    logger.debug(
                        "pubsub | event=whitelist_remove | ja4=%s", value
                    )

            case "ban_release":
                if value:
                    self._cache.block_decisions.delete(f"ban:{value}")
                    logger.debug(
                        "pubsub | event=ban_release | ip=%s", value
                    )

            case "ja4_blacklist_add":
                if value:
                    self._blacklist.add(str(value))
                    logger.debug(
                        "pubsub | event=ja4_blacklist_add | ja4=%s", value
                    )

            case "dial_change":
                try:
                    new_dial = int(value)
                    self._cache.dial = new_dial
                    logger.info(
                        "pubsub | event=dial_change | dial=%d", self._cache.dial
                    )
                except (TypeError, ValueError) as exc:
                    logger.warning(
                        "pubsub | event=dial_change | invalid_value=%r | error=%s",
                        value,
                        exc,
                    )

            case "config_reload":
                logger.info("pubsub | event=config_reload_triggered")
                try:
                    await self._config_loader.reload()
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "pubsub | event=config_reload_failed | error=%s", exc
                    )

            case "cidr_ban_add":
                # Phase 11: RDAP block expansion — add CIDR to in-process trie
                if value and self._blocklist_manager is not None:
                    try:
                        self._blocklist_manager.load_cidrs(
                            [str(value)],
                            "rdap_expansion",
                            {"name": "rdap_expansion", "enabled": True},
                        )
                        logger.debug(
                            "pubsub | event=cidr_ban_add | cidr=%s", value
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "pubsub | event=cidr_ban_add_error | cidr=%s | error=%s",
                            value,
                            exc,
                        )

            case _:
                logger.warning(
                    "pubsub | event=unknown_message_type | type=%s", msg_type
                )
