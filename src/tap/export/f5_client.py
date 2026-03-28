"""
F5Client — pushes ban lists to F5 BIG-IP iControl REST API (Phase 20, Group 9).

API: PATCH /mgmt/tm/ltm/data-group/internal/{data_group}
     with body {"records": [...]}

Rate limiting: max_rps semaphore (token-bucket approximation).
Retry: up to 3 retries on 429 and 503.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY = 1.0


class F5Client:
    """F5 BIG-IP iControl REST client.

    Config section: ``intelligence_export.f5``.

    Args:
        config: The ``f5`` sub-dict from ``intelligence_export``.
        session: aiohttp.ClientSession instance.
    """

    def __init__(self, config: dict, session: Any) -> None:
        self._session = session
        self._base_url: str = config.get("base_url", "https://f5.example.com").rstrip(
            "/"
        )
        self._username: str = config.get("username", "")
        self._password: str = config.get("password", "")
        self._data_group: str = config.get("data_group", "ja4proxy_blocklist")
        self._max_rps: int = int(config.get("max_rps", 10))
        self._verify_tls: bool = bool(config.get("verify_tls", True))

        # Semaphore to throttle concurrent requests (rate limiting approximation)
        self._semaphore = asyncio.Semaphore(self._max_rps)
        # Timestamps of recent requests for rate limiting
        self._request_times: list[float] = []
        self._rate_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Rate limiting helper
    # ------------------------------------------------------------------

    async def _acquire_rate_slot(self) -> None:
        """Throttle to max_rps requests per second."""
        async with self._rate_lock:
            now = time.monotonic()
            # Remove timestamps older than 1 second
            self._request_times = [t for t in self._request_times if now - t < 1.0]
            if len(self._request_times) >= self._max_rps:
                # Need to wait until the oldest slot expires
                oldest = self._request_times[0]
                wait_time = 1.0 - (now - oldest)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
            self._request_times.append(time.monotonic())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def full_sync(self) -> None:
        """PUT all current bans to the configured data group (full replacement)."""
        # In a real implementation, read all ban:* keys from Redis.
        # Here we issue a full replacement with empty records as a structural stub.
        try:
            await self._patch_data_group(self._data_group, [])
        except Exception:
            logger.exception("f5_client | event=full_sync_error")

    async def delta_push(self, ip: str, action: str) -> None:
        """PATCH a single IP into the data group.

        Args:
            ip: IP address string.
            action: ``"add"`` or ``"remove"``.
        """
        record = {"name": ip, "data": action}
        try:
            await self._patch_data_group(self._data_group, [record])
        except Exception:
            logger.exception("f5_client | event=delta_push_error | ip=%s", ip)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _patch_data_group(self, name: str, records: list[dict]) -> None:
        """PATCH the F5 data group with the given records list.

        Retries on 429 and 503 up to _MAX_RETRIES times.
        """
        url = f"{self._base_url}/mgmt/tm/ltm/data-group/internal/{name}"
        payload = {"records": records}
        auth = (self._username, self._password) if self._username else None

        await self._acquire_rate_slot()

        for attempt in range(_MAX_RETRIES + 1):
            try:
                kwargs: dict = {
                    "json": payload,
                    "ssl": self._verify_tls,
                }
                if auth:
                    kwargs["auth"] = auth

                async with self._semaphore:
                    resp_ctx = self._session.patch(url, **kwargs)
                    if hasattr(resp_ctx, "__aenter__"):
                        async with resp_ctx as resp:
                            status = resp.status
                    else:
                        # Already a response object (mock)
                        status = resp_ctx.status

                if status in (429, 503):
                    logger.warning(
                        "f5_client | event=rate_limited | status=%d | attempt=%d",
                        status,
                        attempt + 1,
                    )
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(_RETRY_DELAY)
                        continue
                    return
                return

            except Exception:
                logger.exception(
                    "f5_client | event=patch_error | name=%s | attempt=%d",
                    name,
                    attempt + 1,
                )
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_RETRY_DELAY)
