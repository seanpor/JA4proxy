"""
Phase 23 — AlienVault OTX Integration.

Provides reputation scoring from AlienVault OTX (Open Threat Exchange) API.
Identifies IPs associated with known pulse/indicators (malware, C2, phishing).
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

import redis
from prometheus_client import Counter, Gauge

from .feed_health import FeedHealthMonitor
from .models import RiskSignal
from .ti_provider import TIProvider, TIProviderConfig, retry_with_backoff

try:
    import aiohttp
except ImportError:
    aiohttp = None

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache
    from .feed_health import CircuitBreaker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_LOOKUP_TOTAL = Counter(
    "ja4proxy_alienvault_lookup_total",
    "AlienVault OTX API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_alienvault_enrichment_queue_depth",
    "Current depth of the AlienVault enrichment queue",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_alienvault_cache_hit_ratio",
    "Rolling 5-minute approximation of the AlienVault cache hit ratio",
)


@dataclass
class OTXConfig(TIProviderConfig):
    """Configuration for AlienVaultOTXProvider."""
    pulse_score: int = 15  # Score per pulse the IP is associated with

    @classmethod
    def from_config(cls, config: dict) -> "OTXConfig":
        cfg = config.get("alienvault", {})
        api_key = cfg.get("api_key", "") or os.environ.get("OTX_API_KEY", "")
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=api_key,
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 3600)),  # 1h default
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 5)),
            score_cap=int(cfg.get("score_cap", 45)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 2)),
            pulse_score=int(cfg.get("pulse_score", 15))
        )


class AlienVaultOTXProvider(TIProvider):
    """
    Async AlienVault OTX reputation provider.
    """

    def __init__(
        self,
        config: OTXConfig,
        redis_client: redis.asyncio.Redis,
        local_cache: "LocalCache",
        session: "aiohttp.ClientSession",
        health_monitor: Optional[FeedHealthMonitor] = None,
    ) -> None:
        self._config = config
        self._redis = redis_client
        self._local_cache = local_cache
        self._session = session
        self._health_monitor = health_monitor
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_size)
        self._workers: List[asyncio.Task] = []
        self._hits = 0
        self._total = 0

    async def start(self) -> None:
        if not self._config.enabled:
            return
        self._workers = [
            asyncio.create_task(self._worker_loop(), name=f"alienvault-worker-{i}")
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "alienvault",
                "event": "started",
                "worker_count": self._config.worker_count
            })
        )

    async def stop(self) -> None:
        for w in self._workers:
            w.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

    def get_signal(self, ip: str) -> Optional[RiskSignal]:
        if not self._config.enabled:
            return None

        self._total += 1
        # Tier 1: Local LRU
        cached = self._local_cache.alienvault_scores.get(ip)
        if cached is not None:
            self._hits += 1
            self._update_metrics()
            return self._to_signal(ip, cached)

        # Tier 2+: Async lookup
        asyncio.create_task(self._maybe_lookup(ip))
        self._update_metrics()
        return None

    def _update_metrics(self):
        if self._total > 0:
            _CACHE_HIT_RATIO.set(self._hits / self._total)
        _QUEUE_DEPTH.set(self._queue.qsize())

    def _to_signal(self, ip: str, data: dict) -> Optional[RiskSignal]:
        """Convert cached OTX data to a RiskSignal."""
        pulse_count = data.get("pulse_count", 0)
        if pulse_count == 0:
            return None

        # Score scales with pulse count up to cap
        score = min(pulse_count * self._config.pulse_score, self._config.score_cap)

        return RiskSignal(
            name="alienvault_otx",
            score=score,
            reason=f"AlienVault OTX associated with {pulse_count} pulse(s)"
        )

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis; if miss, enqueue API lookup."""
        try:
            val = await self._redis.get(f"alienvault:data:{ip}")
            if val:
                data = json.loads(val)
                self._local_cache.alienvault_scores.set(ip, data)
                return
        except Exception as e:
            logger.warning(f"alienvault | event=redis_read_error | ip={ip} | error={e}")

        # Bloom dedup
        try:
            added = await self._redis.bf().add("bloom:alienvault_enriched", ip)
            if added in (0, False):
                return
            await self._redis.expire("bloom:alienvault_enriched", 86400)
        except Exception:
            pass

        try:
            self._queue.put_nowait(ip)
        except asyncio.QueueFull:
            pass

    async def _worker_loop(self):
        while True:
            try:
                ip = await self._queue.get()
                try:
                    await self._process_lookup(ip)
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"alienvault | event=worker_error | error={e}")

    async def _process_lookup(self, ip: str):
        if not self._config.api_key:
            return

        # Circuit breaker: skip API call if feed is consistently failing
        cb: Optional["CircuitBreaker"] = None
        if self._health_monitor:
            cb = self._health_monitor.get_circuit_breaker("alienvault_otx")
            if cb.is_open():
                logger.debug("alienvault | event=circuit_open_skip | ip=%s", ip)
                return

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self._config.api_key, "Accept": "application/json"}

        async def _do_request():
            async with self._session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    result = {"pulse_count": pulse_count}
                    _LOOKUP_TOTAL.labels(result="success").inc()
                elif resp.status == 404:
                    result = {"pulse_count": 0}
                    _LOOKUP_TOTAL.labels(result="not_found").inc()
                else:
                    logger.warning(
                        "alienvault | event=api_error | status=%d | ip=%s",
                        resp.status, ip,
                    )
                    _LOOKUP_TOTAL.labels(result="error").inc()
                    raise RuntimeError(f"alienvault API error: status={resp.status}")
                return result

        t0 = time.monotonic()
        try:
            result = await retry_with_backoff(
                _do_request,
                feed_name="alienvault_otx",
            )
            # Cache result
            await self._redis.setex(
                f"alienvault:data:{ip}",
                self._config.cache_ttl_seconds,
                json.dumps(result),
            )
            self._local_cache.alienvault_scores.set(ip, result)
            if cb:
                cb.record_success(time.monotonic() - t0)

        except asyncio.TimeoutError:
            _LOOKUP_TOTAL.labels(result="timeout").inc()
            if cb:
                cb.record_failure()
        except Exception as e:
            logger.error("alienvault | event=api_exception | ip=%s | error=%s", ip, e)
            _LOOKUP_TOTAL.labels(result="error").inc()
            if cb:
                cb.record_failure()

    def on_config_reload(self, new_config: dict) -> None:
        self._config = OTXConfig.from_config(new_config)
