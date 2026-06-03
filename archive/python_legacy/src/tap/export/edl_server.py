"""
EDL Server — serves External Dynamic Lists of banned IPs/CIDRs over HTTP (Phase 20, Group 9).

Endpoints:
    GET /edl/{list_name}  — plaintext IP/CIDR list

List names: ``banned_ips``, ``banned_cidrs``, ``combined``

Authentication: optional ``X-API-Key`` header.
Source IP restriction: optional ``allowed_ips`` config list.
ETag caching: sha256[:16] of list content; returns 304 on match.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Optional

from aiohttp import web

logger = logging.getLogger(__name__)


class EDLServer:
    """Aiohttp-based EDL server.

    Config section: ``intelligence_export.edl``.

    Args:
        config: Full proxy config dict.
        redis: Redis client instance.
    """

    def __init__(self, config: dict, redis: Any) -> None:
        self._redis = redis
        edl_cfg: dict = config.get("intelligence_export", {}).get("edl", {})
        self._port: int = int(edl_cfg.get("port", 8091))
        self._api_key: str = edl_cfg.get("api_key", "")
        self._allowed_ips: list[str] = edl_cfg.get("allowed_ips", []) or []
        self._max_age_hours: int = int(edl_cfg.get("max_age_hours", 24))
        self._min_score: int = int(edl_cfg.get("min_score", 0))
        self._include_comments: bool = bool(edl_cfg.get("include_comments", False))
        lists_cfg: dict = edl_cfg.get("lists", {})
        self._list_banned_ips: bool = bool(lists_cfg.get("banned_ips", True))
        self._list_banned_cidrs: bool = bool(lists_cfg.get("banned_cidrs", True))
        self._list_combined: bool = bool(lists_cfg.get("combined", True))

        # In-memory lists keyed by list_name → list[str]
        self._lists: dict[str, list[str]] = {
            "banned_ips": [],
            "banned_cidrs": [],
            "combined": [],
        }
        # ETag per list
        self._etags: dict[str, str] = {}

        self._runner: Optional[web.AppRunner] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/edl/{list_name}", self._handle_request)
        return app

    async def start(self) -> None:
        """Build in-memory lists and start the aiohttp server."""
        await self._rebuild_lists()
        app = self._create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        logger.info(
            json.dumps(
                {
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "edl_server",
                    "event": "edl_server_started",
                    "port": self._port,
                }
            )
        )

    async def close(self) -> None:
        """Stop the HTTP server."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------
    # List building
    # ------------------------------------------------------------------

    async def _rebuild_lists(self) -> None:
        """Read ``ban:*`` keys from Redis and build in-memory lists.

        Applies ``max_age_hours`` and ``min_score`` filters.
        """
        banned_ips: list[str] = []
        banned_cidrs: list[str] = []
        cutoff_ts = time.time() - self._max_age_hours * 3600

        try:
            keys = self._redis.keys("ban:*")
        except Exception:
            logger.exception("edl_server | event=redis_keys_error")
            keys = []

        for key in keys:
            try:
                raw = self._redis.get(key)
                if raw is None:
                    # key expired between KEYS and GET
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode()

                # Attempt JSON parse for metadata
                entry_ip: str = ""
                entry_score: int = 0
                entry_ts: float = 0.0

                if isinstance(raw, str):
                    try:
                        meta = json.loads(raw)
                        if isinstance(meta, dict):
                            entry_ip = meta.get("ip", "")
                            entry_score = int(meta.get("score", 0))
                            entry_ts = float(meta.get("timestamp", 0))
                        else:
                            # plain string value (just the IP)
                            entry_ip = str(meta)
                    except (json.JSONDecodeError, ValueError):
                        entry_ip = raw.strip()

                if not entry_ip:
                    # Derive IP from key: ban:{ip}
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    entry_ip = (
                        key_str[len("ban:") :]
                        if key_str.startswith("ban:")
                        else key_str
                    )

                # Apply filters
                if self._max_age_hours > 0 and entry_ts > 0 and entry_ts < cutoff_ts:
                    continue
                if entry_score < self._min_score:
                    continue

                # Classify as IP or CIDR
                if "/" in entry_ip:
                    banned_cidrs.append(entry_ip)
                else:
                    banned_ips.append(entry_ip)

            except Exception:
                logger.exception("edl_server | event=entry_parse_error | key=%s", key)

        self._lists["banned_ips"] = sorted(set(banned_ips))
        self._lists["banned_cidrs"] = sorted(set(banned_cidrs))
        self._lists["combined"] = sorted(set(banned_ips + banned_cidrs))

        for list_name, entries in self._lists.items():
            content = "\n".join(entries)
            self._etags[list_name] = hashlib.sha256(content.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Request handler
    # ------------------------------------------------------------------

    async def _handle_request(self, request: web.Request) -> web.Response:
        list_name = request.match_info["list_name"]
        return await self.handle_edl_request(list_name, request)

    async def handle_edl_request(
        self, list_name: str, request: web.Request
    ) -> web.Response:
        """Handle a GET /edl/{list_name} request.

        Returns 403 if auth fails, 304 if ETag matches, or 200 with plaintext list.
        """
        # Source IP restriction
        if self._allowed_ips:
            remote = getattr(request, "remote", None) or request.headers.get(
                "X-Real-IP", ""
            )
            if remote not in self._allowed_ips:
                return web.Response(status=403, text="Forbidden")

        # API key auth
        if self._api_key:
            provided = request.headers.get("X-API-Key", "")
            if provided != self._api_key:
                return web.Response(status=403, text="Forbidden")

        if list_name not in self._lists:
            return web.Response(status=404, text="Not found")

        etag = self._etags.get(list_name, "")
        # ETag comparison
        if_none_match = request.headers.get("If-None-Match", "")
        if if_none_match and if_none_match.strip('"') == etag:
            return web.Response(status=304)

        entries = self._lists[list_name]
        lines: list[str] = []

        if self._include_comments:
            lines.append(f"# JA4proxy EDL - {list_name}")
            for entry in entries:
                lines.append(entry)
        else:
            lines = list(entries)

        body = "\n".join(lines)
        if body:
            body += "\n"

        headers = {
            "ETag": etag,
            "Content-Type": "text/plain; charset=utf-8",
        }
        return web.Response(status=200, text=body, headers=headers)
