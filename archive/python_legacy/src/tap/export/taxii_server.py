"""
TaxiiServer — minimal TAXII 2.1 HTTP API for STIX indicator export (Phase 20, Group 9).

Endpoints:
    GET /taxii2/                               — Discovery
    GET /taxii2/api/collections/               — Collection list
    GET /taxii2/api/collections/{id}/objects/  — STIX bundle (supports ?added_after=)

Authentication: optional ``X-API-Key`` header.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from aiohttp import web

logger = logging.getLogger(__name__)

_TAXII_CONTENT_TYPE = "application/taxii+json; version=2.1"


class TaxiiServer:
    """Minimal TAXII 2.1 server backed by Redis ban data.

    Config section: ``intelligence_export.taxii``.

    Args:
        config: Full proxy config dict.
        redis: Redis client instance.
    """

    def __init__(self, config: dict, redis: Any) -> None:
        self._redis = redis
        taxii_cfg: dict = config.get("intelligence_export", {}).get("taxii", {})
        self._port: int = int(taxii_cfg.get("port", 8092))
        self._api_key: str = taxii_cfg.get("api_key", "")
        self._collection_id: str = taxii_cfg.get("collection_id", "ja4proxy-bans")
        self._collection_title: str = taxii_cfg.get(
            "collection_title", "JA4proxy Ban List"
        )

        self._runner: Optional[web.AppRunner] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/taxii2/", self._handle_discovery)
        app.router.add_get("/taxii2/api/collections/", self._handle_collections)
        app.router.add_get(
            "/taxii2/api/collections/{collection_id}/objects/",
            self._handle_objects,
        )
        return app

    async def start(self) -> None:
        """Start the TAXII HTTP server."""
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
                    "subsystem": "taxii_server",
                    "event": "taxii_server_started",
                    "port": self._port,
                }
            )
        )

    async def close(self) -> None:
        """Stop the TAXII HTTP server."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------
    # Request handlers
    # ------------------------------------------------------------------

    async def _handle_discovery(self, request: web.Request) -> web.Response:
        return await self.handle_taxii_request("/taxii2/", request)

    async def _handle_collections(self, request: web.Request) -> web.Response:
        return await self.handle_taxii_request("/taxii2/api/collections/", request)

    async def _handle_objects(self, request: web.Request) -> web.Response:
        collection_id = request.match_info.get("collection_id", "")
        path = f"/taxii2/api/collections/{collection_id}/objects/"
        return await self.handle_taxii_request(path, request)

    async def handle_taxii_request(
        self, path: str, request: web.Request
    ) -> web.Response:
        """Dispatch a TAXII request by path prefix."""
        # Auth check for objects endpoint
        if "/objects/" in path or "/collections/" in path or path == "/taxii2/":
            # Auth only required for objects endpoint per spec
            if "/objects/" in path:
                if self._api_key:
                    provided = request.headers.get("X-API-Key", "")
                    if provided != self._api_key:
                        return web.Response(
                            status=401,
                            text=json.dumps({"title": "Unauthorized"}),
                            content_type=_TAXII_CONTENT_TYPE,
                        )

        if path == "/taxii2/":
            body = {
                "title": "JA4proxy TAXII",
                "description": "JA4proxy intelligence export (TAXII 2.1)",
                "api_roots": ["/taxii2/api/"],
            }
            return web.Response(
                status=200,
                text=json.dumps(body),
                content_type=_TAXII_CONTENT_TYPE,
            )

        if path == "/taxii2/api/collections/":
            body = {
                "collections": [
                    {  # type: ignore[list-item]
                        "id": self._collection_id,
                        "title": self._collection_title,
                        "can_read": True,
                        "can_write": False,
                        "media_types": ["application/stix+json;version=2.1"],
                    }
                ]
            }
            return web.Response(
                status=200,
                text=json.dumps(body),
                content_type=_TAXII_CONTENT_TYPE,
            )

        if "/objects/" in path:
            return await self._objects_response(request)

        return web.Response(status=404, text="Not found")

    async def _objects_response(self, request: web.Request) -> web.Response:
        """Build and return a STIX bundle of indicators."""
        # Parse added_after filter
        added_after_str = request.rel_url.query.get("added_after", "")
        added_after_ts: float = 0.0
        if added_after_str:
            try:
                dt = datetime.fromisoformat(added_after_str.replace("Z", "+00:00"))
                added_after_ts = dt.timestamp()
            except Exception:
                pass

        indicators: list[dict] = []
        try:
            keys = self._redis.keys("ban:*")
        except Exception:
            keys = []

        for key in keys:
            try:
                raw = self._redis.get(key)
                if raw is None:
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode()

                ip = ""
                score = 0
                reason = ""
                ja4 = None
                entry_ts: float = time.time()

                try:
                    meta = json.loads(raw)
                    if isinstance(meta, dict):
                        ip = meta.get("ip", "")
                        score = int(meta.get("score", 0))
                        reason = meta.get("reason", "")
                        ja4 = meta.get("ja4")
                        entry_ts = float(meta.get("timestamp", entry_ts))
                    else:
                        ip = str(meta)
                except (json.JSONDecodeError, ValueError):
                    ip = raw.strip()

                if not ip:
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    ip = (
                        key_str[len("ban:") :]
                        if key_str.startswith("ban:")
                        else key_str
                    )

                # Apply added_after filter
                if added_after_ts > 0 and entry_ts <= added_after_ts:
                    continue

                indicators.append(self._build_stix_indicator(ip, score, reason, ja4))
            except Exception:
                logger.exception("taxii_server | event=entry_parse_error | key=%s", key)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": indicators,
        }
        return web.Response(
            status=200,
            text=json.dumps(bundle),
            content_type=_TAXII_CONTENT_TYPE,
        )

    def _build_stix_indicator(
        self,
        ip: str,
        score: int,
        reason: str,
        ja4: Optional[str],
    ) -> dict:
        """Build a STIX 2.1 indicator object for a banned IP."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Use IPv6-aware pattern
        if ":" in ip:
            pattern = f"[ipv6-addr:value = '{ip}']"
        else:
            pattern = f"[ipv4-addr:value = '{ip}']"

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "name": f"Banned IP: {ip}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
            "extensions": {
                "x-ja4proxy": {
                    "score": score,
                    "reason": reason,
                    "ja4": ja4,
                }
            },
        }
