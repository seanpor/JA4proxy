"""CrowdStrike Falcon Intel threat-intelligence connector.

Falcon Intel does not expose a TAXII endpoint — it's a plain REST API that
returns its own indicator JSON format. The poll flow is:

1. Exchange ``client_id``/``client_secret`` for a short-lived bearer token at
   ``POST https://api.crowdstrike.com/oauth2/token`` with
   ``grant_type=client_credentials``. The ``scope`` parameter is **not**
   sent in the body — Falcon scopes are configured at the API client
   level in the Falcon console (the API client must have the
   ``Indicators (Falcon Intelligence): Read`` permission). The earlier
   draft sent ``scope=indicators:read``; that was incorrect and has been
   removed (Phase 85 Chunk H, 2026-04-08).
2. Poll ``GET /intel/combined/indicators/v1`` with FQL filtering. The
   real Falcon API does not accept ``type`` or ``malicious_confidence``
   as direct query parameters — both have to be combined into a single
   ``filter`` expression in FQL syntax, e.g.
   ``filter=type:'ip_address'+malicious_confidence:'high'``.
3. Pagination uses the combined-API ``meta.pagination.offset`` field,
   which is a **string token**, not an integer. The loop continues
   while the next offset is truthy and stops when it is missing.
4. Each indicator returned carries ``indicator``, ``type``, ``malicious_confidence``
   fields. We treat IP indicators exactly like the TAXII client does.

Verified against the Falcon developer portal 2026-04-08 — see
``docs/phases/PHASE_85_notes.md`` Chunk H.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Optional

try:  # pragma: no cover
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

from .base import FeedClient, FeedConfig, FeedPollResult
from .metrics import TI_POLL_TOTAL as _POLL_TOTAL
from .mgmt_client import ManagementAPIError

# phase-101g M12: explicit-exception unions in place of bare ``except Exception``.
# See ``taxii.py`` for the rationale. Programmer bugs (``AttributeError``,
# ``KeyError``, ``ImportError``, …) are intentionally *not* caught.
_FEED_FETCH_ERRORS: tuple[type[BaseException], ...] = (
    aiohttp.ClientError if aiohttp is not None else OSError,
    asyncio.TimeoutError,
    RuntimeError,
    ValueError,
    OSError,
)
_FEED_WRITE_ERRORS: tuple[type[BaseException], ...] = (
    *_FEED_FETCH_ERRORS,
    ManagementAPIError,
)

logger = logging.getLogger(__name__)


_FALCON_AUTH_URL_DEFAULT = "https://api.crowdstrike.com/oauth2/token"
_FALCON_INDICATORS_URL_DEFAULT = (
    "https://api.crowdstrike.com/intel/combined/indicators/v1"
)

_PAGE_SIZE = 100


def _resolve_falcon_urls(config: FeedConfig) -> tuple[str, str]:
    """Resolve auth and API URLs for CrowdStrike.

    Supports regional endpoints (US-2, EU-1, GovCloud/laggar).
    """
    base = config.url or "https://api.crowdstrike.com"
    base = base.rstrip("/")
    return (f"{base}/oauth2/token", f"{base}/intel/combined/indicators/v1")


_BATCH_SLEEP_S = 0.05

# Falcon's malicious_confidence is a categorical, not a number. Higher is
# more confident; we accept indicators whose value is at or above the
# configured threshold.
_CONFIDENCE_RANK = {
    "unverified": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


class CrowdStrikeFalconClient(FeedClient):
    """OAuth2 + cursor-paginated Falcon Intel client."""

    def __init__(
        self,
        config: FeedConfig,
        mgmt,
        state,
        *,
        token_fetcher: Optional[Callable[[str, str, str], Awaitable[str]]] = None,
        page_fetcher: Optional[Callable[..., Awaitable[dict[str, Any]]]] = None,
    ) -> None:
        """Construct a CrowdStrike Falcon Intel client.

        Args:
            config: Feed config (carries client_id/client_secret/etc.).
            mgmt: ManagementClient (or test stub).
            state: FeedState (or ``None`` for tests).
            token_fetcher: Optional injected async callable
                ``(client_id, client_secret, scope) -> bearer``. When set,
                :meth:`fetch_bearer_token` calls it once and caches the
                result. Production leaves this ``None`` and uses the
                built-in aiohttp OAuth2 path. phase-85 architect H1.
            page_fetcher: Optional injected async callable
                ``(filters, offset=None, **kwargs) -> page_dict``. When
                set, :meth:`poll` uses it for cursor-paginated indicator
                fetches. phase-85 architect H1.
        """
        super().__init__(config=config, mgmt=mgmt, state=state)
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._token_fetcher = token_fetcher
        self._page_fetcher = page_fetcher
        self._auth_url, self._indicators_url = _resolve_falcon_urls(config)

    async def fetch_bearer_token(self) -> str:
        """Fetch and cache the OAuth2 bearer token via ``token_fetcher``.

        Test-facing helper. Production code should call :meth:`_ensure_token`
        which has its own freshness/expiry handling against the real Falcon
        endpoint.
        """
        if self._token is not None:
            return self._token
        if self._token_fetcher is None:
            raise RuntimeError(
                "CrowdStrikeFalconClient.fetch_bearer_token requires token_fetcher to be set"
            )
        self._token = await self._token_fetcher(
            self.config.client_id or "",
            self.config.client_secret or "",
            "indicators:read",
        )
        # Long enough that test-side cache hits don't trigger refresh.
        self._token_expires_at = time.time() + 3600
        return self._token

    def __repr__(self) -> str:
        # phase-85 (architect C3): never let the bearer token, client_id,
        # or client_secret leak into a stack trace, log line, or pytest
        # capture. The default dataclass-style repr would print self.config
        # which carries client_secret in plaintext.
        token_state = "<set>" if self._token else "<unset>"
        return (
            f"CrowdStrikeFalconClient(feed_id={self.config.id!r}, "
            f"token={token_state}, client_id=<redacted>, "
            f"client_secret=<redacted>)"
        )

    async def poll(self) -> FeedPollResult:
        """Exchange credentials, iterate indicators, apply them via mgmt_client."""
        feed_id = self.config.id
        start = time.monotonic()
        result = FeedPollResult(feed_id=feed_id)

        # phase-85 architect H1: when a test injects ``page_fetcher``,
        # drive the cursor-paginated flow against it directly. The token
        # exchange is bypassed because the test owns auth via
        # ``token_fetcher``. Production leaves both unset and falls
        # through to the aiohttp OAuth2 + indicator-pages path below.
        if self._page_fetcher is not None:
            try:
                await self._poll_paginated_via_fetcher(result)
                _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
            except _FEED_FETCH_ERRORS as exc:
                result.errors.append(f"poll_failed: {exc}")
                _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
                logger.warning(
                    "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                    feed_id,
                    exc,
                )
            result.poll_duration_s = time.monotonic() - start
            return result

        try:
            await self._ensure_token()
        except _FEED_FETCH_ERRORS as exc:
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
        except _FEED_FETCH_ERRORS as exc:
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

        # phase-85 Chunk H: Falcon's /oauth2/token endpoint takes only
        # client_id + client_secret. The grant type is implicit
        # (client_credentials) and there is no scope parameter — scopes
        # are configured at the API client level in the Falcon console.
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        # H6 (PHASE_101): SafeResolver blocks DNS-level SSRF to private/metadata IPs.
        from .safe_resolver import SafeResolver

        connector = aiohttp.TCPConnector(resolver=SafeResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                self._auth_url,
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
        """Walk the paginated indicator endpoint until exhausted.

        phase-85 Chunk H: the real Falcon API does not accept ``type`` /
        ``malicious_confidence`` as direct query parameters — they have
        to be combined into a single FQL ``filter`` expression. The
        ``offset`` field of ``meta.pagination`` is a string token, not
        an integer; the loop continues while it is truthy and stops when
        it is missing.
        """
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp required")
        if not self._token:
            raise RuntimeError("CrowdStrike token not set; call authenticate() first")

        offset: Optional[str] = None
        type_csv = ",".join(self.config.indicator_types or ["ip_address"])
        filter_expr = f"type:'{type_csv}'+malicious_confidence:'{self.config.min_malicious_confidence}'"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "ja4proxy-ti-feed/1.0",
        }
        first = True
        # H6 (PHASE_101): SafeResolver blocks DNS-level SSRF to private/metadata IPs.
        from .safe_resolver import SafeResolver

        connector = aiohttp.TCPConnector(resolver=SafeResolver())
        async with aiohttp.ClientSession(
            headers=headers, connector=connector
        ) as session:
            while first or offset:
                first = False
                params: dict[str, str] = {
                    "limit": str(_PAGE_SIZE),
                    "filter": filter_expr,
                }
                if offset:
                    params["offset"] = offset
                async with session.get(
                    self._indicators_url,
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
                if not next_offset or not resources:
                    offset = None
                else:
                    offset = str(next_offset)
                    await asyncio.sleep(_BATCH_SLEEP_S)

    async def _poll_paginated_via_fetcher(self, result: FeedPollResult) -> None:
        """Drive a cursor-paginated stream against an injected ``page_fetcher``."""
        if self._page_fetcher is None:
            raise RuntimeError("page_fetcher not set")
        offset: Optional[str] = None
        # Build a filters string mirroring the production query so the
        # test can inspect it if it wants to.
        filters = (
            f"type:'{','.join(self.config.indicator_types or ['ip_address'])}'"
            f"+malicious_confidence:'{self.config.min_malicious_confidence}'"
        )
        while True:
            page = await self._page_fetcher(filters, offset=offset)
            if not isinstance(page, dict):
                raise RuntimeError("page_fetcher returned non-dict page")
            resources = page.get("resources", []) or []
            await self._apply_batch(resources, result)
            meta = page.get("meta", {}) or {}
            pagination = meta.get("pagination", {}) or {}
            next_offset = pagination.get("offset")
            if next_offset is None:
                return
            offset = str(next_offset)

    async def _apply_batch(
        self,
        resources: list[dict[str, Any]],
        result: FeedPollResult,
    ) -> None:
        """Apply a page of Falcon indicators to the Management API."""
        feed_id = self.config.id
        threshold = _CONFIDENCE_RANK.get(
            (self.config.min_malicious_confidence or "high").lower(), 3
        )
        for resource in resources:
            ip = resource.get("indicator") or resource.get("value")
            if not isinstance(ip, str):
                result.unsupported_pattern += 1
                continue
            # phase-85: malicious_confidence is a categorical; the API can
            # be asked to filter server-side but the page_fetcher injection
            # path bypasses that, so enforce here too.
            confidence = (resource.get("malicious_confidence") or "").lower()
            if _CONFIDENCE_RANK.get(confidence, -1) < threshold:
                result.skipped_below_confidence += 1
                continue
            stix_id = resource.get("id") or f"falcon:{ip}"
            # phase-85 (security review H7): defer marking the indicator
            # as "seen" until after the mgmt write succeeds — see the
            # matching change in taxii.py for the rationale.

            try:
                await self.mgmt.post_ban(
                    ip,
                    feed_id=feed_id,
                    ttl_s=self.ban_ttl_seconds(),
                    reason=f"feed:{feed_id}",
                )
            except _FEED_WRITE_ERRORS as exc:
                result.errors.append(f"ban create failed: {exc}")
                continue
            if self.state is not None:
                await self.state.mark(feed_id, str(stix_id), handle=ip, kind="ban")
            result.stix_ids_seen.add(str(stix_id))
            result.created.append((str(stix_id), ip))


#: Test-facing alias.
CrowdStrikeClient = CrowdStrikeFalconClient
