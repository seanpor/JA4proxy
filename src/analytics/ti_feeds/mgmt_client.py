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
        token_env_var: str = "JA4PROXY_FEED_CLIENT_TOKEN",
        timeout_s: float = 10.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = os.environ.get(token_env_var, "")
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._session: Optional[Any] = None

    # ── session management ───────────────────────────────────────────────

    async def connect(self) -> None:
        """Create the shared aiohttp session. Idempotent."""
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
        """Tear down the shared session. Idempotent."""
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

    async def _request(
        self,
        method: str,
        path: str,
        *,
        feed_id: str,
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
                async with self._session.request(
                    method,
                    url,
                    json=json_body,
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    if status >= 500:
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
        feed_id: str,
        ttl_s: int,
        reason: str,
    ) -> None:
        """Create a ban via ``POST /api/v1/bans/{ip:path}``.

        Args:
            ip: IPv4 or IPv6 address (canonical string form).
            feed_id: The feed id for metric labels.
            ttl_s: TTL in seconds.
            reason: Audit reason, typically ``"feed:{feed_id}"``.
        """
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

    async def delete_ban(self, ip: str, *, feed_id: str) -> None:
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
        feed_id: str,
        entry: str,
        note: str,
        expires_at: Optional[str] = None,
    ) -> ResourceResult:
        """Create a blocklist entry via ``POST /api/v1/blocklist``.

        The ``managed_by`` field is always ``"feed"`` — Phase 85 is the only
        caller that should produce feed-managed entries.
        """
        body: dict[str, Any] = {
            "entry": entry,
            "managed_by": "feed",
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
        feed_id: str,
    ) -> None:
        """Remove a blocklist entry via ``DELETE /api/v1/blocklist/{resource_id}``."""
        path = f"/api/v1/blocklist/{resource_id}"
        try:
            await self._request("DELETE", path, feed_id=feed_id)
        except ManagementAPIError as exc:
            if exc.status_code == 404:
                return
            raise
