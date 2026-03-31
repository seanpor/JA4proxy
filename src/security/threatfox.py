"""
Phase 46 — ThreatFox Threat Intelligence Integration.

Provides reputation scoring from ThreatFox (Abuse.ch) API.
Identifies IPs associated with known malicious indicators (malware, botnets, C2).
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

import redis
from prometheus_client import Counter, Gauge

from .models import RiskSignal
from .ti_provider import TIProvider, TIProviderConfig

try:
    import aiohttp
except ImportError:
    aiohttp = None

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache
    from .adaptive_cache import AdaptiveCacheManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_LOOKUP_TOTAL = Counter(
    "ja4proxy_threatfox_lookup_total",
    "ThreatFox API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_threatfox_enrichment_queue_depth",
    "Current depth of the ThreatFox enrichment queue",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_threatfox_cache_hit_ratio",
    "Rolling 5-minute approximation of the ThreatFox cache hit ratio",
)


@dataclass
class ThreatFoxConfig(TIProviderConfig):
    """Configuration for ThreatFoxProvider."""
    ioc_score: int = 25  # Score per ThreatFox IOC match

    @classmethod
    def from_config(cls, config: dict) -> "ThreatFoxConfig":
        cfg = config.get("threatfox", {})
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=cfg.get("api_key", ""),
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 3600)),  # 1h default
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 5)),
            score_cap=int(cfg.get("score_cap", 60)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 2)),
            ioc_score=int(cfg.get("ioc_score", 25)),
        )


class ThreatFoxProvider(TIProvider):
    """
    Async ThreatFox reputation provider.
    """

    def __init__(
        self,
        config: ThreatFoxConfig,
        redis_client: redis.asyncio.Redis,
        local_cache: "LocalCache",
        session: "aiohttp.ClientSession",
        adaptive_cache: Optional["AdaptiveCacheManager"] = None,
    ) -> None:
        self._config = config
        self._redis = redis_client
        self._local_cache = local_cache
        self._session = session
        self._adaptive_cache = adaptive_cache
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_size)
        self._workers: List[asyncio.Task] = []
        self._hits = 0
        self._total = 0

    async def start(self) -> None:
        if not self._config.enabled:
            return
        self._workers = [
            asyncio.create_task(self._worker_loop(), name=f"threatfox-worker-{i}")
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "threatfox",
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
        cached = self._local_cache.threatfox_scores.get(ip)
        if cached is not None:
            self._hits += 1
            self._update_metrics()
            
            # Record cache hit for adaptive caching
            if self._adaptive_cache:
                asyncio.create_task(self._adaptive_cache.record_cache_hit("threatfox"))
            
            return self._to_signal(ip, cached)

        # Tier 2+: Async lookup
        asyncio.create_task(self._maybe_lookup(ip))
        self._update_metrics()
        return None

    def _update_metrics(self):
        if self._total > 0:
            _CACHE_HIT_RATIO.set(self._hits / self._total)
        _QUEUE_DEPTH.set(self._queue.qsize())

    def _to_signal(self, ip: str, data: dict, confidence_weight: float = 1.0) -> Optional[RiskSignal]:
        """Convert cached ThreatFox data to a RiskSignal."""
        ioc_count = data.get("ioc_count", 0)
        if ioc_count == 0:
            return None

        # Score scales with IOC count up to cap
        score = min(ioc_count * self._config.ioc_score, self._config.score_cap)

        return RiskSignal(
            name="threatfox",
            score=score,
            reason=f"ThreatFox associated with {ioc_count} IOC(s)",
            weight=confidence_weight
        )

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis; if miss, enqueue API lookup."""
        try:
            val = await self._redis.get(f"threatfox:data:{ip}")
            if val:
                data = json.loads(val)
                self._local_cache.threatfox_scores.set(ip, data)
                return
        except Exception as e:
            logger.warning(f"threatfox | event=redis_read_error | ip={ip} | error={e}")

        # Bloom dedup
        try:
            added = await self._redis.bf().add("bloom:threatfox_enriched", ip)
            if added in (0, False):
                return
            await self._redis.expire("bloom:threatfox_enriched", 86400)
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
                logger.error(f"threatfox | event=worker_error | error={e}")

    async def _process_lookup(self, ip: str):
        if not self._config.api_key:
            return

        url = f"https://threatfox-api.abuse.ch/api/v1/"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Search for IP address IOCs
        payload = {
            "query": "search_ioc",
            "search_term": ip
        }
        
        try:
            async with self._session.post(
                url, 
                headers=headers, 
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    iocs = data.get("data", [])
                    ioc_count = len(iocs)
                    
                    result = {"ioc_count": ioc_count}
                    _LOOKUP_TOTAL.labels(result="success").inc()
                elif resp.status == 404:
                    result = {"ioc_count": 0}
                    _LOOKUP_TOTAL.labels(result="not_found").inc()
                else:
                    logger.warning(f"threatfox | event=api_error | status={resp.status} | ip={ip}")
                    _LOOKUP_TOTAL.labels(result="error").inc()
                    return

                        # Get old cached value for volatility detection
                old_value = None
                try:
                    old_data = await self._redis.get(f"threatfox:data:{ip}")
                    if old_data:
                        old_value = json.loads(old_data)
                except Exception:
                    pass

                # Get adaptive TTL if adaptive cache manager is available
                ttl_seconds = self._config.cache_ttl_seconds
                if hasattr(self, '_adaptive_cache') and self._adaptive_cache:
                    ttl_seconds = self._adaptive_cache.get_adaptive_ttl("threatfox")

                # Cache result
                await self._redis.setex(
                    f"threatfox:data:{ip}",
                    ttl_seconds,
                    json.dumps(result)
                )
                self._local_cache.threatfox_scores.set(ip, result)
                
                # Record cache miss with volatility detection
                if hasattr(self, '_adaptive_cache') and self._adaptive_cache:
                    await self._adaptive_cache.record_cache_miss("threatfox", old_value, result)

        except asyncio.TimeoutError:
            _LOOKUP_TOTAL.labels(result="timeout").inc()
        except Exception as e:
            logger.error(f"threatfox | event=api_exception | ip={ip} | error={e}")
            _LOOKUP_TOTAL.labels(result="error").inc()

    def on_config_reload(self, new_config: dict) -> None:
        self._config = ThreatFoxConfig.from_config(new_config)