"""Recorded Future threat-intelligence connector.

Recorded Future exposes threat data both as a TAXII 2.1 server and as REST
feeds; this module uses the TAXII front door so it can reuse
:class:`.taxii.TAXIIClient`. The only deltas from the plain TAXII path are:

1. **Authentication** — RF's TAXII 2.1 endpoint uses HTTP Basic. The
   username can be any value (the docs use ``"api"``); the password is the
   RF API key from ``${RF_API_TOKEN}``. There is no separate token-exchange
   step — clients send the API key on every request. The earlier draft of
   this module used an ``X-RFToken`` header; that was incorrect and has
   been removed (Phase 85 Chunk G, 2026-04-08).
2. **Collections** — RF publishes one TAXII collection per feed name
   (``ip_threat_intel``, ``c2_server_tracking``, etc.), so a single
   ``recorded_future`` YAML entry can span multiple RF collections by
   listing them in ``feeds: [...]``.
3. **Risk score filter** — RF indicators carry a ``confidence`` and an
   ``x_rf_risk_score`` extension; we treat ``min_rf_risk_score`` as a
   minimum on the latter.

Verified against the Recorded Future developer portal 2026-04-08 — see
``docs/phases/PHASE_85_notes.md`` Chunk G.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable, Optional

try:  # pragma: no cover
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

from .base import FeedClient, FeedConfig, FeedPollResult
from .metrics import TI_POLL_TOTAL as _POLL_TOTAL
from .taxii import (  # noqa: F401
    _BATCH_SIZE,
    _FEED_FETCH_ERRORS,
    _INTER_BATCH_SLEEP_S,
    TAXIIClient,
)

logger = logging.getLogger(__name__)


class RecordedFutureClient(FeedClient):
    """Thin wrapper over :class:`TAXIIClient` for Recorded Future collections.

    A single :class:`RecordedFutureClient` instance owns zero or more inner
    :class:`TAXIIClient` instances — one per RF feed name listed in
    ``FeedConfig.feeds``. On each poll we iterate them, aggregating results
    into a single :class:`FeedPollResult`. Errors in any inner poll do not
    stop the others.
    """

    def __init__(
        self,
        config: FeedConfig,
        mgmt,
        state,
        *,
        token_exchange: Optional[Callable[[str], Awaitable[str]]] = None,
        page_fetch: Optional[Callable[..., Awaitable[dict[str, Any]]]] = None,
    ) -> None:
        """Construct a Recorded Future client.

        Args:
            config: Feed config.
            mgmt: ManagementClient (or test stub).
            state: FeedState (or ``None`` for tests that skip the index).
            token_exchange: Optional async callable
                ``(api_token) -> bearer_token``. When set,
                :meth:`fetch_bearer_token` calls it once and caches the
                result. phase-85 architect H1.
            page_fetch: Optional async callable
                ``(collection_id, cursor=None, **kwargs) -> bundle_dict``.
                When set, :meth:`poll` uses it for cursor-paginated fetches
                and applies indicators through an inner injected TAXII
                client. Production leaves this ``None`` and falls back to
                the multi-collection TAXII delegation path. phase-85
                architect H1.
        """
        super().__init__(config=config, mgmt=mgmt, state=state)
        self._token_exchange = token_exchange
        self._page_fetch = page_fetch
        self._bearer_token: Optional[str] = None
        self._inner_clients: list[TAXIIClient] = []
        # The injected page_fetch path does not need pre-built inner
        # TAXIIClients — it builds them on demand from the bundle dicts.
        if page_fetch is None:
            for feed_name in config.feeds or ["default"]:
                inner_cfg = FeedConfig.from_dict(
                    {
                        **config.raw,
                        # phase-85 (C4): inner id must match the feed-id
                        # regex (no '/'). Use '_' as separator.
                        "id": f"{config.id}_{feed_name}",
                        "type": "taxii2",
                        "url": _resolve_rf_taxii_root(config),
                        "collection_id": feed_name,
                        # phase-85 Chunk G: RF TAXII 2.1 expects HTTP
                        # Basic. Username is any literal ("api" per RF
                        # docs); password is the API key from
                        # ${RF_API_TOKEN}, which the loader has already
                        # written into config.api_token.
                        "username": "api",
                        "password": config.api_token or "",
                        # Propagate gating knobs:
                        "min_confidence": max(
                            config.min_confidence, config.min_rf_risk_score
                        ),
                        "ban_ttl_hours": config.ban_ttl_hours,
                        "enabled": config.enabled,
                    }
                )
                self._inner_clients.append(
                    TAXIIClient(config=inner_cfg, mgmt=mgmt, state=state)
                )

    @property
    def collection_ids(self) -> list[str]:
        """Return the configured RF collection / feed names."""
        return list(self.config.feeds or ["default"])

    @property
    def _taxii_root(self) -> str:
        """Return the resolved TAXII root URL (for testing)."""
        return _resolve_rf_taxii_root(self.config)

    async def fetch_bearer_token(self) -> str:
        """Exchange ``api_token`` for a bearer token, caching the result.

        When :class:`RecordedFutureClient` is built with a ``token_exchange``
        callable (test or alternative integration path), the first call
        invokes the callable; subsequent calls return the cached value.
        """
        if self._bearer_token is not None:
            return self._bearer_token
        if self._token_exchange is None:
            raise RuntimeError(
                "RecordedFutureClient.fetch_bearer_token requires token_exchange to be set"
            )
        self._bearer_token = await self._token_exchange(self.config.api_token)
        return self._bearer_token

    async def poll(self) -> FeedPollResult:
        """Poll each configured RF collection in sequence.

        Header injection for ``X-RFToken`` happens inside
        :class:`TAXIIClient` via a monkey-patch pattern would get ugly — we
        instead override the inner HTTP call by making RF its own request
        method below. For MVP we inherit the TAXII flow and rely on the
        caller to set the token in the environment; the token is picked up
        by :meth:`_build_rf_headers`.
        """
        feed_id = self.config.id
        start = time.monotonic()
        combined = FeedPollResult(feed_id=feed_id)

        # phase-85 architect H1: when a test injects ``page_fetch``, drive
        # a single cursor-paginated stream against it and apply indicators
        # through a one-shot inner TAXIIClient. Production leaves
        # ``page_fetch`` unset and falls through to the inner-clients
        # iteration below.
        #
        # Note: ``collection_ids`` is passed only as a hint to ``page_fetch``
        # — RF's TAXII front door yields one paginated stream per
        # configured feed name, but the cursor sequence is opaque to us.
        # We pass the first collection name as a hint and let the stub
        # decide. Production-mode multi-collection iteration is the
        # ``page_fetch is None`` branch below.
        if self._page_fetch is not None:
            try:
                hint = (self.collection_ids or ["default"])[0]
                await self._poll_paginated(hint, combined)
                _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
            except _FEED_FETCH_ERRORS as exc:
                combined.errors.append(f"rf_poll_failed: {exc}")
                _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
                logger.warning(
                    "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                    feed_id,
                    exc,
                )
            combined.poll_duration_s = time.monotonic() - start
            return combined

        try:
            for inner in self._inner_clients:
                inner_result = await inner.poll()
                combined.stix_ids_seen.update(inner_result.stix_ids_seen)
                combined.created.extend(inner_result.created)
                combined.skipped_below_confidence += (
                    inner_result.skipped_below_confidence
                )
                combined.unsupported_pattern += inner_result.unsupported_pattern
                combined.errors.extend(inner_result.errors)
            _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
        except _FEED_FETCH_ERRORS as exc:
            combined.errors.append(f"rf_poll_failed: {exc}")
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            logger.warning(
                "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                feed_id,
                exc,
            )
        combined.poll_duration_s = time.monotonic() - start
        return combined

    async def _poll_paginated(
        self,
        collection_id: str,
        combined: FeedPollResult,
    ) -> None:
        """Walk a single RF collection via the injected ``page_fetch``.

        Each page is wrapped in a one-shot stub TAXII transport and handed
        to a fresh :class:`TAXIIClient` so the indicator-application logic
        (confidence gating, expiry filter, mgmt-client routing) is shared
        between RF and plain TAXII.
        """
        if self._page_fetch is None:
            raise RuntimeError("page_fetch not set")
        cursor: Optional[str] = None
        while True:
            bundle = await self._page_fetch(collection_id, cursor=cursor)
            if not isinstance(bundle, dict):
                raise RuntimeError("page_fetch returned non-dict bundle")
            inner_cfg = FeedConfig(
                id=f"{self.config.id}/{collection_id}",
                type="taxii2",
                enabled=True,
                collection_id=collection_id,
                min_confidence=max(
                    self.config.min_confidence, self.config.min_rf_risk_score
                ),
                ban_ttl_hours=self.config.ban_ttl_hours,
            )
            inner = TAXIIClient(
                config=inner_cfg,
                mgmt=self.mgmt,
                state=self.state,
                taxii=_OneShotBundle(bundle),
            )
            inner_result = await inner.poll()
            combined.stix_ids_seen.update(inner_result.stix_ids_seen)
            combined.created.extend(inner_result.created)
            combined.skipped_below_confidence += inner_result.skipped_below_confidence
            combined.unsupported_pattern += inner_result.unsupported_pattern
            combined.errors.extend(inner_result.errors)
            cursor = bundle.get("next")
            if not cursor:
                return


#: Base TAXII 2.1 API root for Recorded Future. Verified 2026-04-08
#: against the RF support portal: the TAXII 2.1 discovery endpoint lives
#: at ``api.recordedfuture.com/taxii2``. The legacy TAXII 1.x endpoint
#: ``api.recordedfuture.com/taxii`` is **not** what this client uses.
_RF_TAXII_ROOT_DEFAULT = "https://api.recordedfuture.com/taxii2"


def _resolve_rf_taxii_root(config: FeedConfig) -> str:
    """Resolve the TAXII root URL for Recorded Future.

    Honours config.url for regional endpoints (EU, APAC), falling back
    to the default US endpoint.
    """
    if config.url:
        return config.url.rstrip("/")
    return _RF_TAXII_ROOT_DEFAULT


class _OneShotBundle:
    """Tiny adapter that turns a STIX bundle dict into a TAXII transport.

    Implements the single-method contract expected by
    ``TAXIIClient(taxii=...)``: ``async get_objects(collection_id,
    added_after=None) -> dict``.
    """

    def __init__(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle

    async def get_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self._bundle
