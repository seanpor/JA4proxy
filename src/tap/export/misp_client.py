"""
MISPClient — pushes ban events to a MISP instance (Phase 20, Group 9).

Creates a daily MISP event (or reuses today's existing one) and adds
ip-dst and (optionally) JA4 fingerprint attributes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class MISPClient:
    """MISP REST API client.

    Config section: ``intelligence_export.misp``.

    Args:
        config: The ``misp`` sub-dict from ``intelligence_export``.
        session: aiohttp.ClientSession instance.
    """

    def __init__(self, config: dict, session: Any) -> None:
        self._session = session
        self._base_url: str = config.get("base_url", "https://misp.example.com").rstrip("/")
        self._api_key: str = config.get("api_key", "")
        self._verify_tls: bool = bool(config.get("verify_tls", True))
        self._event_distribution: int = int(config.get("event_distribution", 0))
        self._event_threat_level: int = int(config.get("event_threat_level", 1))

        # Daily event cache
        self._daily_event_id: Optional[str] = None
        self._daily_event_date: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def push_ban(
        self,
        ip: str,
        score: int,
        reason: str,
        ja4: Optional[str] = None,
    ) -> None:
        """Push a ban to MISP as ip-dst attribute on today's event.

        Swallows all errors (logs WARNING, never raises).
        """
        try:
            event_id = await self._get_or_create_daily_event()
            await self._add_attribute(
                event_id,
                "ip-dst",
                ip,
                f"score={score} reason={reason}",
            )
            if ja4 is not None:
                await self._add_attribute(
                    event_id,
                    "other",
                    ja4,
                    "JA4 fingerprint",
                )
        except Exception:
            logger.warning(
                "misp_client | event=push_ban_failed | ip=%s | score=%d",
                ip, score,
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _get_or_create_daily_event(self) -> str:
        """Return today's MISP event ID; create one if necessary."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if self._daily_event_id and self._daily_event_date == today:
            return self._daily_event_id

        # Create a new event for today
        title = f"JA4proxy bans {today}"
        payload = {
            "info": title,
            "distribution": self._event_distribution,
            "threat_level_id": self._event_threat_level,
            "analysis": 0,
            "date": today,
        }
        headers = self._headers()
        url = f"{self._base_url}/events"

        try:
            kwargs: dict = {
                "json": {"Event": payload},
                "headers": headers,
                "ssl": self._verify_tls,
            }
            resp_ctx = self._session.post(url, **kwargs)
            if hasattr(resp_ctx, "__aenter__"):
                async with resp_ctx as resp:
                    data = await resp.json()
            else:
                data = await resp_ctx.json()

            event_id = str(
                data.get("Event", {}).get("id")
                or data.get("id")
                or ""
            )
        except Exception:
            logger.warning("misp_client | event=create_event_failed | title=%s", title)
            event_id = ""

        if event_id:
            self._daily_event_id = event_id
            self._daily_event_date = today

        return event_id

    async def _add_attribute(
        self,
        event_id: str,
        type_: str,
        value: str,
        comment: str,
    ) -> None:
        """POST an attribute to the MISP event.

        Silently skips on 409 (duplicate).  Logs WARNING for other errors.
        """
        if not event_id:
            return

        headers = self._headers()
        url = f"{self._base_url}/attributes/add/{event_id}"
        payload = {
            "type": type_,
            "value": value,
            "comment": comment,
        }

        try:
            kwargs: dict = {
                "json": payload,
                "headers": headers,
                "ssl": self._verify_tls,
            }
            resp_ctx = self._session.post(url, **kwargs)
            if hasattr(resp_ctx, "__aenter__"):
                async with resp_ctx as resp:
                    if resp.status == 409:
                        # Duplicate — silently skip
                        return
                    if resp.status >= 400:
                        logger.warning(
                            "misp_client | event=add_attribute_failed | "
                            "status=%d | type=%s | value=%s",
                            resp.status, type_, value,
                        )
            else:
                status = getattr(resp_ctx, "status", 0)
                if status == 409:
                    return
                if status >= 400:
                    logger.warning(
                        "misp_client | event=add_attribute_failed | "
                        "status=%d | type=%s | value=%s",
                        status, type_, value,
                    )
        except Exception:
            logger.warning(
                "misp_client | event=add_attribute_error | type=%s | value=%s",
                type_, value,
            )

    def _headers(self) -> dict:
        return {
            "Authorization": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
