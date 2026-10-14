"""Prometheus HTTP API client for the management console.

Phase 821a:
- Based on httpx.AsyncClient(timeout=2.0, follow_redirects=False).
- Three-state result: Ok(value, fetched_at) | Empty(fetched_at) | Unavailable(reason, last_ok_at).
- Closed allowlist queries by Tile ID only, never arbitrary user PromQL.
- Caching layer with TTL=10s and single-flight deduplication.
- Safe URL validation on startup.
- Instruments self-observability counter: ja4proxy_console_prometheus_queries_total{result=...}.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from management.api.prometheus_metrics import PROMETHEUS_QUERIES

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Ok:
    value: Any
    fetched_at: float


@dataclass(frozen=True)
class Empty:
    fetched_at: float


@dataclass(frozen=True)
class Unavailable:
    reason: str
    last_ok_at: Optional[float] = None


QueryResult = Ok | Empty | Unavailable


def validate_prometheus_url(url: str) -> str:
    """Validate Prometheus URL at startup.
    Scheme must be http or https, and no userinfo allowed.
    """
    if not url:
        raise ValueError("PROMETHEUS_URL cannot be empty")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme in PROMETHEUS_URL: {parsed.scheme!r}. Must be http or https.")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo (username/password) is forbidden in PROMETHEUS_URL")
    if not parsed.hostname:
        raise ValueError(f"No hostname in PROMETHEUS_URL: {url!r}")
    return url.rstrip("/")


class PrometheusClient:
    """Async Prometheus client with 2.0s timeout, no redirect following,
    10s caching, single-flight deduplication, and 3-state results.
    """

    def __init__(self, base_url: Optional[str] = None, timeout: float = 2.0, ttl: float = 10.0):
        raw_url = base_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
        self.base_url = validate_prometheus_url(raw_url)
        self.timeout = timeout
        self.ttl = ttl

        # Cache: query_str -> (QueryResult, timestamp)
        self._cache: dict[str, tuple[QueryResult, float]] = {}
        # In-flight deduplication: query_str -> asyncio.Future
        self._inflight: dict[str, asyncio.Future[QueryResult]] = {}
        # Track last successful timestamp per query
        self._last_ok_at: dict[str, float] = {}

    async def query_instant(self, query: str) -> QueryResult:
        """Execute an instant PromQL query (/api/v1/query) with caching and single-flight."""
        now = time.time()

        # Check cache
        if query in self._cache:
            result, cached_at = self._cache[query]
            if now - cached_at < self.ttl:
                return result

        # Check in-flight single flight
        if query in self._inflight:
            return await self._inflight[query]

        # Register our in-flight task
        loop = asyncio.get_running_loop()
        future: asyncio.Future[QueryResult] = loop.create_future()
        self._inflight[query] = future

        try:
            result = await self._execute_query(query)
            if isinstance(result, Ok):
                self._last_ok_at[query] = result.fetched_at
            elif isinstance(result, Unavailable) and query in self._last_ok_at:
                result = Unavailable(reason=result.reason, last_ok_at=self._last_ok_at[query])

            self._cache[query] = (result, time.time())
            future.set_result(result)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error during Prometheus query execution: %s", exc)
            err_res = Unavailable(reason=str(exc), last_ok_at=self._last_ok_at.get(query))
            future.set_result(err_res)
            return err_res
        finally:
            self._inflight.pop(query, None)

    async def _execute_query(self, query: str) -> QueryResult:
        url = f"{self.base_url}/api/v1/query"
        params = {"query": query}

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                resp = await client.get(url, params=params)

                if resp.status_code != 200:
                    PROMETHEUS_QUERIES.labels(result="error").inc()
                    return Unavailable(reason=f"HTTP {resp.status_code}")

                data = resp.json()
                if data.get("status") != "success":
                    PROMETHEUS_QUERIES.labels(result="error").inc()
                    return Unavailable(reason=data.get("error", "query failed"))

                result_data = data.get("data", {})
                result_type = result_data.get("resultType")
                result_vector = result_data.get("result", [])

                now = time.time()
                if not result_vector:
                    PROMETHEUS_QUERIES.labels(result="empty").inc()
                    return Empty(fetched_at=now)

                PROMETHEUS_QUERIES.labels(result="ok").inc()
                # If vector, parse the first value if scalar-like or return full vector
                if result_type == "vector":
                    if len(result_vector) == 1 and "value" in result_vector[0]:
                        val_str = result_vector[0]["value"][1]
                        try:
                            val = float(val_str)
                            return Ok(value=val, fetched_at=now)
                        except (ValueError, TypeError):
                            return Ok(value=val_str, fetched_at=now)
                    return Ok(value=result_vector, fetched_at=now)

                if result_type == "matrix":
                    return Ok(value=result_vector, fetched_at=now)

                if result_type == "scalar" and "value" in result_data:
                    return Ok(value=float(result_data["value"][1]), fetched_at=now)

                return Ok(value=result_vector, fetched_at=now)

        except httpx.TimeoutException:
            PROMETHEUS_QUERIES.labels(result="timeout").inc()
            return Unavailable(reason="query timeout")
        except httpx.RequestError as exc:
            PROMETHEUS_QUERIES.labels(result="error").inc()
            return Unavailable(reason=f"network error: {exc}")
        except Exception as exc:  # noqa: BLE001
            PROMETHEUS_QUERIES.labels(result="error").inc()
            return Unavailable(reason=str(exc))


# Default singleton client
_DEFAULT_CLIENT: Optional[PrometheusClient] = None


def get_prometheus_client() -> PrometheusClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = PrometheusClient()
    return _DEFAULT_CLIENT
