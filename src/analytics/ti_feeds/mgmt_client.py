"""Async HTTP client for the Phase 79 Management API.

The feed runner talks to the Management API through this module. It is the
**only** place where the feed runner makes outbound REST calls that mutate
proxy rule state — no direct Redis writes to proxy SETs, no short-cuts.

Bans endpoint contract (this is the trap the earlier draft of PHASE_85.md
walked into):

    POST   /api/v1/bans/{ip:path}   body: {ttl, reason}
    DELETE /api/v1/bans/{ip:path}   body: (none)

The IP is in the URL path, URL-encoded so IPv6 addresses work. The body
carries only ``ttl`` and ``reason``. Do not add ``"ip"`` to the body.

Blocklist endpoint:

    POST   /api/v1/blocklist        body: ResourceCreate
                                    {entry, managed_by, note, expires_at}

``managed_by`` is always the string ``"feed"``; ``note`` is always
``"feed:{feed_id}:{stix_id}"`` so the source is recoverable without consulting
the sidecar index.

Retries:

* 5xx responses → retry with exponential backoff up to ``max_retries``.
* 4xx responses (including 409 Conflict from the canonical list idempotency
  path) → **no retry**, surfaced to the caller immediately.
* Network errors / timeouts → retried the same as 5xx.

Rate limiting:

* Callers (TAXII, RF, CS, REST) batch indicators in groups of 50 and sleep
  ``50ms`` between batches per PHASE_85.md §2.5.
* This client itself does **not** rate-limit — that logic belongs with the
  caller because only the caller knows how many indicators are in a poll.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

from .base import is_bannable_ip

try:  # pragma: no cover — optional at collection time, required at runtime
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

from .metrics import TI_MGMT_API_ERRORS as _MGMT_API_ERRORS

logger = logging.getLogger(__name__)


@dataclass
class ManagementAPIError(Exception):
    """Raised when the Management API returns an un-retryable error."""

    status_code: int
    message: str

    def __str__(self) -> str:  # pragma: no cover — trivial
        return f"Management API {self.status_code}: {self.message}"


@dataclass
class ResourceResult:
    """Minimal envelope returned by :meth:`ManagementClient.post_blocklist`."""

    id: str
    entry: str
    managed_by: str
    note: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ResourceResult":
        return cls(
            id=str(data.get("id", "")),
            entry=str(data.get("entry", "")),
            managed_by=str(data.get("managed_by", "")),
            note=str(data.get("note", "")),
        )


class ManagementClient:
    """Async client for the small subset of the Phase 79 API the feed runner needs.

    Args:
        base_url: Base URL, e.g. ``"http://management:8090"``.
        token_env_var: Environment variable carrying the bearer token. The
            default ``JA4PROXY_FEED_CLIENT_TOKEN`` matches the env var name in
            PHASE_85.md §2.1. Unresolved → the client still constructs but
            every call emits a 401-equivalent error so the feed disables itself.
        timeout_s: Per-request timeout.
        max_retries: How many attempts on retryable (5xx/network) failures
            before raising. Default 3.
        backoff_base_s: First retry delay. Doubles each attempt.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[str] = None,
        token_env_var: str = "JA4PROXY_FEED_CLIENT_TOKEN",
        timeout_s: float = 10.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        backoff_initial_s: Optional[float] = None,
        session: Optional[Any] = None,
        batch_size: int = 50,
        inter_batch_sleep_s: float = 0.05,
    ) -> None:
        """Construct the Management API client.

        Args:
            base_url: e.g. ``"http://management:8090"``.
            token: Bearer token. When provided, used directly. Otherwise
                falls back to ``os.environ[token_env_var]``. Tests pass
                ``token=`` directly so they don't have to set env vars.
            token_env_var: Env var name (default
                ``JA4PROXY_FEED_CLIENT_TOKEN``).
            timeout_s: Per-request timeout.
            max_retries: Retry budget for 5xx / network errors.
            backoff_base_s: Base for exponential backoff (legacy name).
            backoff_initial_s: Alias for ``backoff_base_s`` used by Phase 85
                tests; takes precedence when both are set.
            session: Pre-built aiohttp session (or test stub exposing
                ``post(url, json=, headers=)`` / ``delete(url, headers=)``
                that return context managers). When provided, the client
                does not create or close its own session. phase-85
                architect H1.
            batch_size: §2.5 bulk-ingest batch size for
                :meth:`bulk_post_blocklist`.
            inter_batch_sleep_s: §2.5 inter-batch sleep duration.
        """
        self._base_url = base_url.rstrip("/")
        if token is not None:
            self._token = token
        else:
            self._token = os.environ.get(token_env_var, "")
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._backoff_base_s = (
            backoff_initial_s if backoff_initial_s is not None else backoff_base_s
        )
        # Injected session bypasses lazy-construction inside connect().
        self._injected_session = session is not None
        self._session: Optional[Any] = session
        self._batch_size = batch_size
        self._inter_batch_sleep_s = inter_batch_sleep_s

    # ── session management ───────────────────────────────────────────────

    async def connect(self) -> None:
        """Create the shared aiohttp session. Idempotent.

        No-op when a session was injected via the constructor.
        """
        if self._injected_session:
            return
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError(
                "aiohttp is required for ManagementClient but is not installed"
            )
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._timeout_s),
                headers=self._default_headers(),
            )

    async def close(self) -> None:
        """Tear down the shared session. Idempotent.

        No-op when a session was injected — that session's lifetime is
        owned by the test fixture, not by us.
        """
        if self._injected_session:
            return
        if self._session is not None:
            try:
                await self._session.close()
            except Exception as exc:  # noqa: BLE001 — best-effort shutdown
                logger.debug(
                    "ti_feed | event=mgmt_client_close_error | error=%s", exc
                )
            self._session = None

    def _default_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    # ── low-level request helper ─────────────────────────────────────────

    def _open_request(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Return the per-request context manager.

        Routes through ``session.post()`` / ``session.delete()`` when an
        injected session is in use (the Phase 85 unit-test stub style),
        and through ``session.request()`` for the production aiohttp
        path. Both shapes return an async context manager that yields a
        response object exposing ``status`` and ``text()``.
        """
        assert self._session is not None
        headers = self._default_headers() if self._injected_session else None
        if self._injected_session:
            method_up = method.upper()
            if method_up == "POST":
                return self._session.post(url, json=json_body, headers=headers)
            if method_up == "DELETE":
                return self._session.delete(url, headers=headers)
            if method_up == "GET":
                return self._session.get(url, headers=headers)
            raise RuntimeError(f"unsupported method on injected session: {method}")
        return self._session.request(method, url, json=json_body)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        feed_id: str = "_unknown",
        json_body: Optional[dict[str, Any]] = None,
    ) -> tuple[int, dict[str, Any]]:
        """Make a single request with bounded retries.

        Returns:
            ``(status_code, body_dict)``. Empty response bodies are returned
            as ``{}``.

        Raises:
            ManagementAPIError: If the server returns a 4xx response, or if
                every retry of a 5xx / network failure is exhausted.
        """
        if self._session is None:
            await self.connect()
        assert self._session is not None  # narrow for type checkers

        if not self._token:
            # Surface clearly — no silent retries.
            _MGMT_API_ERRORS.labels(feed_id=feed_id, status_code="no_token").inc()
            raise ManagementAPIError(
                status_code=401,
                message="JA4PROXY_FEED_CLIENT_TOKEN is not set; feed disabled",
            )

        url = f"{self._base_url}{path}"
        attempt = 0
        last_error: Optional[str] = None

        while attempt <= self._max_retries:
            try:
                async with self._open_request(
                    method, url, json_body=json_body
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    # phase-85 §2.5: retry 5xx and 429 (rate limit). Other
                    # 4xx codes are final — retrying a 422 will just hit the
                    # same validation error and waste budget.
                    if status >= 500 or status == 429:
                        _MGMT_API_ERRORS.labels(
                            feed_id=feed_id, status_code=str(status)
                        ).inc()
                        last_error = f"HTTP {status}: {text[:256]}"
                        await self._sleep_backoff(attempt)
                        attempt += 1
                        continue
                    if status >= 400:
                        _MGMT_API_ERRORS.labels(
                            feed_id=feed_id, status_code=str(status)
                        ).inc()
                        raise ManagementAPIError(
                            status_code=status, message=text[:512]
                        )
                    body: dict[str, Any] = {}
                    if text:
                        try:
                            parsed = json.loads(text)
                            if isinstance(parsed, dict):
                                body = parsed
                        except json.JSONDecodeError:
                            # 204 No Content returns empty string; that's fine.
                            pass
                    return status, body
            except ManagementAPIError:
                raise
            except Exception as exc:  # noqa: BLE001
                _MGMT_API_ERRORS.labels(
                    feed_id=feed_id, status_code="network"
                ).inc()
                last_error = f"network: {exc}"
                await self._sleep_backoff(attempt)
                attempt += 1

        raise ManagementAPIError(
            status_code=503,
            message=f"exhausted retries ({self._max_retries}): {last_error}",
        )

    async def _sleep_backoff(self, attempt: int) -> None:
        """Exponential backoff: ``base * 2**attempt`` seconds."""
        delay = self._backoff_base_s * (2 ** attempt)
        await asyncio.sleep(delay)

    # ── high-level helpers ───────────────────────────────────────────────

    async def post_ban(
        self,
        ip: str,
        *,
        feed_id: str = "_unknown",
        ttl_s: Optional[int] = None,
        ttl: Optional[int] = None,
        reason: str,
    ) -> None:
        """Create a ban via ``POST /api/v1/bans/{ip:path}``.

        Args:
            ip: IPv4 or IPv6 address (canonical string form).
            feed_id: The feed id for metric labels.
            ttl_s: TTL in seconds (preferred name).
            ttl: Alias for ``ttl_s`` accepted by the Phase 85 unit tests.
            reason: Audit reason, typically ``"feed:{feed_id}"``.
        """
        if ttl_s is None and ttl is not None:
            ttl_s = ttl
        if ttl_s is None:
            raise TypeError("post_ban requires ttl_s (or ttl) keyword argument")
        # phase-85 (security review C5): never let a feed-supplied IP turn
        # into a ban for loopback / RFC1918 / link-local / multicast space.
        # The choke point lives here so every feed client (TAXII, RF, CS,
        # REST) inherits the guard.
        if not is_bannable_ip(ip):
            logger.warning(
                "ti_feed | event=ban_rejected_unsafe_ip | feed=%s | ip=%s",
                feed_id,
                ip,
            )
            raise ManagementAPIError(
                status_code=400,
                message=f"refusing to ban non-public ip {ip}",
            )
        encoded_ip = urllib.parse.quote(ip, safe="")
        path = f"/api/v1/bans/{encoded_ip}"
        body: dict[str, Any] = {"ttl": ttl_s, "reason": reason}
        await self._request("POST", path, feed_id=feed_id, json_body=body)

    async def delete_ban(self, ip: str, *, feed_id: str = "_unknown") -> None:
        """Lift a ban via ``DELETE /api/v1/bans/{ip:path}``."""
        encoded_ip = urllib.parse.quote(ip, safe="")
        path = f"/api/v1/bans/{encoded_ip}"
        try:
            await self._request("DELETE", path, feed_id=feed_id)
        except ManagementAPIError as exc:
            # 404 means the ban already expired or was lifted manually.
            if exc.status_code == 404:
                return
            raise

    async def post_blocklist(
        self,
        *,
        feed_id: str = "_unknown",
        entry: str,
        note: str,
        managed_by: str = "feed",
        expires_at: Optional[str] = None,
    ) -> ResourceResult:
        """Create a blocklist entry via ``POST /api/v1/blocklist``.

        The ``managed_by`` field is always ``"feed"`` — Phase 85 is the only
        caller that should produce feed-managed entries.
        """
        # phase-85: ``managed_by`` is always "feed" in production. The
        # kwarg is accepted only for symmetry with the Phase 79 ResourceCreate
        # body shape used by the Phase 85 mgmt-client unit tests; any other
        # value here would be a misconfiguration.
        body: dict[str, Any] = {
            "entry": entry,
            "managed_by": managed_by or "feed",
            "note": note,
        }
        if expires_at:
            body["expires_at"] = expires_at
        _, response_body = await self._request(
            "POST",
            "/api/v1/blocklist",
            feed_id=feed_id,
            json_body=body,
        )
        return ResourceResult.from_json(response_body)

    async def delete_blocklist(
        self,
        resource_id: str,
        *,
        feed_id: str = "_unknown",
    ) -> None:
        """Remove a blocklist entry via ``DELETE /api/v1/blocklist/{resource_id}``."""
        path = f"/api/v1/blocklist/{resource_id}"
        try:
            await self._request("DELETE", path, feed_id=feed_id)
        except ManagementAPIError as exc:
            if exc.status_code == 404:
                return
            raise

    async def bulk_post_blocklist(
        self,
        entries: list[dict[str, Any]],
        *,
        feed_id: str = "_unknown",
    ) -> list[Any]:
        """Bulk-create blocklist entries with §2.5 batch pacing.

        Splits ``entries`` into ``batch_size`` chunks (default 50) and
        ``await asyncio.gather(..., return_exceptions=True)`` for each
        batch, sleeping ``inter_batch_sleep_s`` between batches. Returns
        the flattened list of results — one entry per input — where
        each element is either a :class:`ResourceResult` or an
        ``Exception`` instance for the entries that failed.
        """
        results: list[Any] = []
        total = len(entries)
        for batch_start in range(0, total, self._batch_size):
            batch = entries[batch_start : batch_start + self._batch_size]
            tasks = [
                self.post_blocklist(
                    feed_id=feed_id,
                    entry=item["entry"],
                    note=item.get("note", ""),
                    managed_by=item.get("managed_by", "feed"),
                    expires_at=item.get("expires_at"),
                )
                for item in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend(batch_results)
            if batch_start + self._batch_size < total:
                await asyncio.sleep(self._inter_batch_sleep_s)
        return results
