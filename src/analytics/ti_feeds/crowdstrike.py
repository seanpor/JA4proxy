"""CrowdStrike Falcon Intel threat-intelligence connector.

Falcon Intel does not expose a TAXII endpoint — it's a plain REST API that
returns its own indicator JSON format. The poll flow is:

1. Exchange ``client_id``/``client_secret`` for a short-lived bearer token at
   ``POST https://api.crowdstrike.com/oauth2/token`` with
   ``grant_type=client_credentials`` and ``scope=indicators:read``.
2. Poll ``GET /intel/combined/indicators/v1?type={type}&malicious_confidence={conf}``
   paginated via the ``Meta.Pagination.Offset`` cursor.
3. Each indicator returned carries ``indicator``, ``type``, ``malicious_confidence``
   fields. We treat IP indicators exactly like the TAXII client does.

TODO: verify against the Falcon developer portal before production use. The
scope and query-parameter names come from PHASE_85.md §6.3 as written;
confirm with CrowdStrike docs before rollout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

try:  # pragma: no cover
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

from .base import FeedClient, FeedConfig, FeedPollResult
from .metrics import TI_POLL_TOTAL as _POLL_TOTAL

logger = logging.getLogger(__name__)


_FALCON_AUTH_URL = "https://api.crowdstrike.com/oauth2/token"
_FALCON_INDICATORS_URL = "https://api.crowdstrike.com/intel/combined/indicators/v1"

_PAGE_SIZE = 100
_BATCH_SLEEP_S = 0.05


class CrowdStrikeFalconClient(FeedClient):
    """OAuth2 + cursor-paginated Falcon Intel client."""

    def __init__(self, config: FeedConfig, mgmt, state) -> None:
        super().__init__(config=config, mgmt=mgmt, state=state)
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    async def poll(self) -> FeedPollResult:
        """Exchange credentials, iterate indicators, apply them via mgmt_client."""
        feed_id = self.config.id
        start = time.monotonic()
        result = FeedPollResult(feed_id=feed_id)

        try:
            await self._ensure_token()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"auth_failed: {exc}")
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            result.poll_duration_s = time.monotonic() - start
            logger.warning(
                "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return result

        try:
            await self._poll_all_pages(result)
            _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"poll_failed: {exc}")
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            logger.warning(
                "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                feed_id,
                exc,
            )

        result.poll_duration_s = time.monotonic() - start
        return result

    # ── OAuth2 ──────────────────────────────────────────────────────────

    async def _ensure_token(self) -> None:
        """Refresh ``self._token`` if it is missing or about to expire."""
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp required for CrowdStrikeFalconClient")

        if self._token and time.time() < (self._token_expires_at - 60):
            return
        if not self.config.client_id or not self.config.client_secret:
            raise RuntimeError(
                "CrowdStrike client_id / client_secret unset (env var unresolved?)"
            )

        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": "indicators:read",
            "grant_type": "client_credentials",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                _FALCON_AUTH_URL,
                data=data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"Falcon auth returned HTTP {resp.status}: {text[:256]}"
                    )
                body = await resp.json()
        access_token = body.get("access_token")
        if not access_token:
            raise RuntimeError("Falcon auth response missing access_token")
        expires_in = int(body.get("expires_in", 1800))
        self._token = access_token
        self._token_expires_at = time.time() + expires_in

    # ── Indicator pages ─────────────────────────────────────────────────

    async def _poll_all_pages(self, result: FeedPollResult) -> None:
        """Walk the paginated indicator endpoint until exhausted."""
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp required")
        assert self._token

        offset: Optional[int] = 0
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "ja4proxy-ti-feed/1.0",
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            while offset is not None:
                params = {
                    "limit": str(_PAGE_SIZE),
                    "offset": str(offset),
                    "type": ",".join(self.config.indicator_types or ["ip_address"]),
                    "malicious_confidence": self.config.min_malicious_confidence,
                }
                async with session.get(
                    _FALCON_INDICATORS_URL,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(
                            f"Falcon indicators returned HTTP {resp.status}: {text[:256]}"
                        )
                    body = await resp.json()

                resources = body.get("resources", []) or []
                await self._apply_batch(resources, result)

                meta = body.get("meta", {}) or {}
                pagination = meta.get("pagination", {}) or {}
                next_offset = pagination.get("offset")
                limit = pagination.get("limit", _PAGE_SIZE)
                total = pagination.get("total", 0)
                new_offset = (
                    next_offset + limit if isinstance(next_offset, int) else None
                )
                if new_offset is None or new_offset >= total or not resources:
                    offset = None
                else:
                    offset = new_offset
                    await asyncio.sleep(_BATCH_SLEEP_S)

    async def _apply_batch(
        self,
        resources: list[dict[str, Any]],
        result: FeedPollResult,
    ) -> None:
        """Apply a page of Falcon indicators to the Management API."""
        feed_id = self.config.id
        for resource in resources:
            ip = resource.get("indicator") or resource.get("value")
            if not isinstance(ip, str):
                result.unsupported_pattern += 1
                continue
            stix_id = resource.get("id") or f"falcon:{ip}"
            result.stix_ids_seen.add(str(stix_id))

            try:
                await self.mgmt.post_ban(
                    ip,
                    feed_id=feed_id,
                    ttl_s=self.ban_ttl_seconds(),
                    reason=f"feed:{feed_id}",
                )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"ban create failed: {exc}")
                continue
            await self.state.mark(feed_id, str(stix_id), handle=ip, kind="ban")
            result.created.append((str(stix_id), ip))
