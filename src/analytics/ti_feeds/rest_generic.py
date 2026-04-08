"""Generic REST threat-intelligence connector.

For internal platforms and niche vendors that expose a plain JSON endpoint
instead of TAXII / STIX. Configuration supplies JSONPath expressions to
extract IP, TTL, and optionally JA4 and confidence values from the response
body.

Example YAML (from PHASE_85.md §6.4)::

    - id: internal-ti
      type: rest
      url: "https://threatintel.corp.internal/api/v1/indicators"
      auth:
        type: bearer
        token: "${INTERNAL_TI_TOKEN}"
      ip_jsonpath: "$.indicators[*].value"
      ttl_jsonpath: "$.indicators[*].expires_in"
      ban_ttl_hours: 24
      poll_interval_minutes: 15

Supported auth modes:

* ``bearer`` — Authorization: Bearer {token}
* ``basic`` — HTTP Basic with username/password
* ``api_key`` — X-API-Key: {key} header

Anything else falls back to sending the request without authentication and
warns once at startup.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from base64 import b64encode
from typing import Any, Optional

try:  # pragma: no cover
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

try:  # pragma: no cover — optional runtime dep
    from jsonpath_ng import parse as jsonpath_parse  # type: ignore
    from jsonpath_ng.exceptions import JsonPathParserError  # type: ignore

    _JSONPATH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _JSONPATH_AVAILABLE = False
    JsonPathParserError = Exception  # type: ignore

    def jsonpath_parse(expr: str):  # type: ignore
        raise RuntimeError(
            "jsonpath-ng is required for the REST generic feed client"
        )


from .base import FeedClient, FeedConfig, FeedPollResult
from .metrics import TI_POLL_TOTAL as _POLL_TOTAL
from .stix_ja4 import validate_ja4

logger = logging.getLogger(__name__)


class RESTGenericClient(FeedClient):
    """JSONPath-driven generic REST feed poller."""

    def __init__(self, config: FeedConfig, mgmt, state) -> None:
        super().__init__(config=config, mgmt=mgmt, state=state)
        self._ip_expr = self._compile_jsonpath(config.ip_jsonpath)
        self._ttl_expr = self._compile_jsonpath(config.ttl_jsonpath)
        self._ja4_expr = self._compile_jsonpath(config.ja4_jsonpath)
        self._confidence_expr = self._compile_jsonpath(config.confidence_jsonpath)

    @staticmethod
    def _compile_jsonpath(expr: str):
        if not expr or not _JSONPATH_AVAILABLE:
            return None
        try:
            return jsonpath_parse(expr)
        except (JsonPathParserError, Exception) as exc:
            logger.warning(
                "ti_feed | event=jsonpath_compile_failed | expr=%s | error=%s",
                expr,
                exc,
            )
            return None

    async def poll(self) -> FeedPollResult:
        """Fetch the configured URL, extract indicators, apply them."""
        feed_id = self.config.id
        start = time.monotonic()
        result = FeedPollResult(feed_id=feed_id)

        if aiohttp is None:  # pragma: no cover
            result.errors.append("aiohttp not installed")
            return result

        if not _JSONPATH_AVAILABLE:
            result.errors.append("jsonpath-ng not installed")
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            result.poll_duration_s = time.monotonic() - start
            return result

        if self._ip_expr is None and self._ja4_expr is None:
            result.errors.append(
                "rest feed missing both ip_jsonpath and ja4_jsonpath"
            )
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            result.poll_duration_s = time.monotonic() - start
            return result

        try:
            body = await self._fetch_json()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"fetch_failed: {exc}")
            _POLL_TOTAL.labels(feed_id=feed_id, result="failure").inc()
            result.poll_duration_s = time.monotonic() - start
            logger.warning(
                "ti_feed | event=ti_feed.poll_failed | feed=%s | error=%s",
                feed_id,
                exc,
            )
            return result

        await self._apply_body(body, result)

        _POLL_TOTAL.labels(feed_id=feed_id, result="success").inc()
        result.poll_duration_s = time.monotonic() - start
        return result

    # ── HTTP ─────────────────────────────────────────────────────────────

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "ja4proxy-ti-feed/1.0",
        }
        auth = self.config.auth or {}
        auth_type = str(auth.get("type", "")).lower()
        if auth_type == "bearer":
            token = auth.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "basic":
            username = auth.get("username", "")
            password = auth.get("password", "")
            if username or password:
                creds = b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"
        elif auth_type == "api_key":
            key = auth.get("key", "") or auth.get("token", "")
            if key:
                headers["X-API-Key"] = key
        elif auth_type:
            logger.warning(
                "ti_feed | event=rest_auth_unknown | feed=%s | type=%s",
                self.config.id,
                auth_type,
            )
        return headers

    async def _fetch_json(self) -> Any:
        assert aiohttp is not None
        async with aiohttp.ClientSession(headers=self._build_headers()) as session:
            async with session.get(
                self.config.url,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"REST feed returned HTTP {resp.status}: {text[:256]}"
                    )
                return await resp.json()

    # ── Apply ────────────────────────────────────────────────────────────

    async def _apply_body(self, body: Any, result: FeedPollResult) -> None:
        feed_id = self.config.id

        # IP indicators
        if self._ip_expr is not None:
            ip_values = [m.value for m in self._ip_expr.find(body)]
            ttl_values = (
                [m.value for m in self._ttl_expr.find(body)]
                if self._ttl_expr is not None
                else []
            )
            for i, ip in enumerate(ip_values):
                if not isinstance(ip, str):
                    result.unsupported_pattern += 1
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    result.unsupported_pattern += 1
                    continue
                stix_id = f"rest:{feed_id}:{ip}"
                result.stix_ids_seen.add(stix_id)
                ttl_s = self.ban_ttl_seconds()
                if i < len(ttl_values):
                    try:
                        ttl_s = max(60, int(ttl_values[i]))
                    except (TypeError, ValueError):
                        pass
                try:
                    await self.mgmt.post_ban(
                        ip,
                        feed_id=feed_id,
                        ttl_s=ttl_s,
                        reason=f"feed:{feed_id}",
                    )
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"ban create failed: {exc}")
                    continue
                await self.state.mark(feed_id, stix_id, handle=ip, kind="ban")
                result.created.append((stix_id, ip))
                await asyncio.sleep(0)  # cooperative yield

        # JA4 indicators
        if self._ja4_expr is not None:
            ja4_values = [m.value for m in self._ja4_expr.find(body)]
            for ja4 in ja4_values:
                if not isinstance(ja4, str) or not validate_ja4(ja4):
                    result.unsupported_pattern += 1
                    continue
                stix_id = f"rest:{feed_id}:ja4:{ja4}"
                result.stix_ids_seen.add(stix_id)
                try:
                    resource = await self.mgmt.post_blocklist(
                        feed_id=feed_id,
                        entry=ja4,
                        note=f"feed:{feed_id}:{stix_id}",
                    )
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"blocklist create failed: {exc}")
                    continue
                await self.state.mark(
                    feed_id, stix_id, handle=resource.id, kind="blocklist"
                )
                result.created.append((stix_id, resource.id))
