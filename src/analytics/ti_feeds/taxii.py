"""Hand-rolled TAXII 2.1 client for the Phase 85 threat-intel feed runner.

This is not a full TAXII implementation. It supports only the surface that
PHASE_85.md §5 needs:

1. ``GET {root}/collections/{collection_id}/objects/?added_after={ts}``
   with HTTP Basic auth.
2. Parse the JSON response as a STIX bundle (``objects: [...]``).
3. Filter for ``type == 'indicator'``, extract the pattern, route IP
   indicators to ``POST /api/v1/bans`` and JA4 indicators to
   ``POST /api/v1/blocklist`` — all through the Phase 79 Management API
   (``mgmt_client.ManagementClient``).

Why hand-rolled rather than ``taxii2-client``:

* ``taxii2-client==2.3.0`` is a synchronous ``requests`` client. We run in
  the same event loop as the rest of the analytics container and do not want
  to introduce a threadpool just for HTTP GETs.
* The spec surface we need is small (one auth mode, one endpoint, ``added_after``
  incremental cursor) — ~200 LoC that we can read and test in isolation.

See ``docs/decisions/ADR-024.md`` for the full rationale.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from base64 import b64encode
from typing import Any, Optional

try:  # pragma: no cover — optional at collection time, required at runtime
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

from .base import FeedClient, FeedConfig, FeedPollResult
from .metrics import (
    TI_INDICATORS_PROCESSED as _INDICATORS_PROCESSED,
    TI_POLL_DURATION as _POLL_DURATION,
    TI_POLL_TOTAL as _POLL_TOTAL,
)
from .stix_ja4 import (
    is_ip_pattern,
    is_ja4_pattern,
    parse_ip_from_pattern,
    parse_ja4_from_pattern,
    validate_ja4,
)

logger = logging.getLogger(__name__)

_BATCH_SIZE = 50
_INTER_BATCH_SLEEP_S = 0.05  # 50 ms per PHASE_85.md §2.5


class TAXIIClient(FeedClient):
    """Minimal TAXII 2.1 consumer.

    Configuration (from ``FeedConfig``):

    * ``url`` — TAXII API root, e.g. ``https://taxii.example.org/taxii2/``.
    * ``collection_id`` — collection to poll.
    * ``username`` / ``password`` — HTTP Basic credentials (expanded from
      ``${VAR}`` by the config loader). Unset → the feed is still polled,
      but only public collections will return data.
    * ``min_confidence`` — indicators below this value are counted and
      skipped.
    * ``ban_ttl_hours`` — TTL applied to IP bans.
    """

    def __init__(self, config: FeedConfig, mgmt, state) -> None:
        super().__init__(config=config, mgmt=mgmt, state=state)
        self._last_added_after: Optional[str] = None

    async def poll(self) -> FeedPollResult:
        """Poll the configured TAXII collection once.

        Fail-open: any exception is caught, metric-counted, and returned as
        part of ``FeedPollResult.errors``. The circuit breaker lives in the
        runner, not here.
        """
        feed_id = self.config.id
        start = time.monotonic()
        result = FeedPollResult(feed_id=feed_id)

        try:
            objects = await self._fetch_objects()
        except Exception as exc:  # noqa: BLE001 — fail-open
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            result.errors.append(f"fetch_failed: {exc}")
            result.poll_duration_s = time.monotonic() - start
            logger.warning(
                "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return result

        await self._process_objects(objects, result)

        result.poll_duration_s = time.monotonic() - start
        _POLL_DURATION.labels(feed_id=feed_id).observe(result.poll_duration_s)
        _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
        logger.info(
            "ti_feed | event=ti_feed.poll_complete | feed=%s | indicators=%d | "
            "created=%d | skipped=%d | duration_ms=%d",
            feed_id,
            len(result.stix_ids_seen),
            len(result.created),
            result.skipped_below_confidence,
            int(result.poll_duration_s * 1000),
        )
        return result

    # ── HTTP ─────────────────────────────────────────────────────────────

    async def _fetch_objects(self) -> list[dict[str, Any]]:
        """GET the objects endpoint and return the list of STIX objects.

        Hand-rolled: we do not discover the API root or enumerate
        collections. Caller is expected to configure the full objects URL
        implicitly — the standard path is
        ``{root}/collections/{collection_id}/objects/``.
        """
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp required for TAXIIClient")

        root = self.config.url.rstrip("/")
        collection = self.config.collection_id
        url = f"{root}/collections/{collection}/objects/"
        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": "ja4proxy-ti-feed/1.0",
        }
        if self.config.username or self.config.password:
            credentials = f"{self.config.username}:{self.config.password}"
            token = b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {token}"

        params: dict[str, str] = {}
        if self._last_added_after:
            params["added_after"] = self._last_added_after

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"TAXII server returned HTTP {resp.status}: {text[:256]}"
                    )
                body_text = await resp.text()

        try:
            body = json.loads(body_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"TAXII response was not valid JSON: {exc}") from exc

        objects = body.get("objects", [])
        if not isinstance(objects, list):
            raise RuntimeError("TAXII response.objects is not a list")

        # Update the cursor to the bundle's "modified" max so next poll is incremental.
        newest = _newest_modified(objects)
        if newest:
            self._last_added_after = newest
        return objects

    # ── STIX processing ──────────────────────────────────────────────────

    async def _process_objects(
        self,
        objects: list[dict[str, Any]],
        result: FeedPollResult,
    ) -> None:
        """Batch-apply the indicators from a STIX bundle through mgmt_client."""
        feed_id = self.config.id
        indicators = [o for o in objects if o.get("type") == "indicator"]

        for batch_start in range(0, len(indicators), _BATCH_SIZE):
            batch = indicators[batch_start : batch_start + _BATCH_SIZE]
            tasks = [self._apply_indicator(indicator, result) for indicator in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if batch_start + _BATCH_SIZE < len(indicators):
                await asyncio.sleep(_INTER_BATCH_SLEEP_S)

        logger.debug(
            "ti_feed | event=ti_feed.batch_complete | feed=%s | processed=%d",
            feed_id,
            len(indicators),
        )

    async def _apply_indicator(
        self,
        indicator: dict[str, Any],
        result: FeedPollResult,
    ) -> None:
        """Apply a single STIX indicator to the Management API."""
        feed_id = self.config.id
        stix_id = str(indicator.get("id") or "")
        if not stix_id:
            result.errors.append("indicator missing id")
            return

        confidence = int(indicator.get("confidence", 0) or 0)
        if confidence < self.config.min_confidence:
            result.skipped_below_confidence += 1
            _INDICATORS_PROCESSED.labels(
                feed_id=feed_id, outcome="below_confidence"
            ).inc()
            return

        result.stix_ids_seen.add(stix_id)

        pattern = indicator.get("pattern")
        valid_until = indicator.get("valid_until")

        if is_ip_pattern(pattern):
            ip = parse_ip_from_pattern(pattern)
            if not ip:
                _INDICATORS_PROCESSED.labels(
                    feed_id=feed_id, outcome="unsupported"
                ).inc()
                result.unsupported_pattern += 1
                return
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                _INDICATORS_PROCESSED.labels(
                    feed_id=feed_id, outcome="unsupported"
                ).inc()
                result.unsupported_pattern += 1
                result.errors.append(f"invalid IP: {ip}")
                return
            try:
                await self.mgmt.post_ban(
                    ip,
                    feed_id=feed_id,
                    ttl_s=self.ban_ttl_seconds(),
                    reason=f"feed:{feed_id}",
                )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"ban create failed: {exc}")
                return
            await self.state.mark(feed_id, stix_id, handle=ip, kind="ban")
            result.created.append((stix_id, ip))
            _INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="created").inc()
            return

        if is_ja4_pattern(pattern):
            ja4 = parse_ja4_from_pattern(pattern)
            if not ja4 or not validate_ja4(ja4):
                _INDICATORS_PROCESSED.labels(
                    feed_id=feed_id, outcome="unsupported"
                ).inc()
                result.unsupported_pattern += 1
                result.errors.append(f"invalid JA4: {ja4!r}")
                return
            try:
                resource = await self.mgmt.post_blocklist(
                    feed_id=feed_id,
                    entry=ja4,
                    note=f"feed:{feed_id}:{stix_id}",
                    expires_at=valid_until if isinstance(valid_until, str) else None,
                )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"blocklist create failed: {exc}")
                return
            await self.state.mark(
                feed_id, stix_id, handle=resource.id, kind="blocklist"
            )
            result.created.append((stix_id, resource.id))
            _INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="created").inc()
            return

        _INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="unsupported").inc()
        result.unsupported_pattern += 1


def _newest_modified(objects: list[dict[str, Any]]) -> Optional[str]:
    """Return the max ``modified`` timestamp across the bundle's objects.

    Used to advance the ``added_after`` cursor for incremental polling.
    Returns None if the bundle has no ``modified`` fields.
    """
    newest: Optional[str] = None
    for obj in objects:
        modified = obj.get("modified")
        if isinstance(modified, str) and (newest is None or modified > newest):
            newest = modified
    return newest
