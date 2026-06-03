"""
PaloAltoClient — registers/unregisters IPs with tags via Palo Alto XML API (Phase 20, Group 9).

API: GET /api/?type=user-id&action=set&key={api_key}&cmd=<uid-message>...</uid-message>
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _build_uid_xml(operation: str, ip: str, tags: list[str]) -> str:
    """Build the XML for a Palo Alto UID message.

    Args:
        operation: ``"register"`` or ``"unregister"``.
        ip: IP address string.
        tags: List of tag strings.
    """
    tag_entries = "".join(f"<member>{t}</member>" for t in tags)
    entry = f'<entry ip="{ip}" persistent="1"><tag>{tag_entries}</tag></entry>'
    return (
        f"<uid-message><payload>"
        f"<{operation}>{entry}</{operation}>"
        f"</payload></uid-message>"
    )


class PaloAltoClient:
    """Palo Alto Networks XML API client.

    Config section: ``intelligence_export.palo_alto``.

    Args:
        config: The ``palo_alto`` sub-dict from ``intelligence_export``.
        session: aiohttp.ClientSession instance.
    """

    def __init__(self, config: dict, session: Any) -> None:
        self._session = session
        self._base_url: str = config.get("base_url", "https://pa.example.com").rstrip(
            "/"
        )
        self._api_key: str = config.get("api_key", "")
        self._tags: list[str] = config.get("tags", ["ja4proxy-ban"])
        self._verify_tls: bool = bool(config.get("verify_tls", True))

        if not self._verify_tls:
            logger.warning(
                "palo_alto_client | event=tls_verification_disabled | "
                "effect=TLS certificate validation is disabled; connection is not verified"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register_ip(self, ip: str, tags: list[str]) -> None:
        """Register an IP with the given tags on the Palo Alto device."""
        cmd = _build_uid_xml("register", ip, tags)
        await self._call_api(cmd)

    async def unregister_ip(self, ip: str, tags: list[str]) -> None:
        """Unregister an IP/tag mapping from the Palo Alto device."""
        cmd = _build_uid_xml("unregister", ip, tags)
        await self._call_api(cmd)

    async def full_sync(self) -> None:
        """Re-register all currently active bans.

        Stub implementation: In production this would enumerate ban:* keys from
        Redis and call register_ip for each.
        """
        # No-op stub — real implementation would read bans from Redis
        logger.info("palo_alto_client | event=full_sync_started")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _call_api(self, cmd: str) -> None:
        """Issue a GET to the Palo Alto XML API."""
        url = (
            f"{self._base_url}/api/"
            f"?type=user-id&action=set&key={self._api_key}"
            f"&cmd={cmd}"
        )
        try:
            kwargs: dict = {"ssl": self._verify_tls}
            resp_ctx = self._session.get(url, **kwargs)
            if hasattr(resp_ctx, "__aenter__"):
                async with resp_ctx as resp:
                    status = resp.status
                    if status >= 400:
                        logger.warning(
                            "palo_alto_client | event=api_error | status=%d", status
                        )
            else:
                status = getattr(resp_ctx, "status", 0)
        except Exception:
            logger.exception("palo_alto_client | event=request_error")
