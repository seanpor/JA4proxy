"""
Phase 23 — GreyNoise Integration.

Provides background noise and reputation scoring from GreyNoise Community API.
Focuses on "noise" classification (scanners, crawlers) and known malicious IPs.
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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_LOOKUP_TOTAL = Counter(
    "ja4proxy_greynoise_lookup_total",
    "GreyNoise API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_greynoise_enrichment_queue_depth",
    "Current depth of the GreyNoise enrichment queue",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_greynoise_cache_hit_ratio",
    "Rolling 5-minute approximation of the GreyNoise cache hit ratio",
)


@dataclass
class GreyNoiseConfig(TIProviderConfig):
    """Configuration for GreyNoiseProvider."""
    # Specific settings for GreyNoise
    noise_score: int = 25  # Contribution if IP is classified as 'noise'
    riot_score_reduction: int = 15  # Reduction if IP is in 'riot' (known benign)

    @classmethod
    def from_config(cls, config: dict) -> "GreyNoiseConfig":
        cfg = config.get("greynoise", {})
        api_key = cfg.get("api_key", "") or os.environ.get("GREYNOISE_API_KEY", "")
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=api_key,
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 21600)),  # 6h default
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 5)),
            score_cap=int(cfg.get("score_cap", 30)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 2)),
            noise_score=int(cfg.get("noise_score", 25)),
            riot_score_reduction=int(cfg.get("riot_score_reduction", 15))
        )


class GreyNoiseProvider(TIProvider):
    """
    Async GreyNoise reputation provider.
    """

    def __init__(
        self,
        config: GreyNoiseConfig,
        redis_client: redis.asyncio.Redis,
        local_cache: "LocalCache",
        session: "aiohttp.ClientSession",
    ) -> None:
        self._config = config
        self._redis = redis_client
        self._local_cache = local_cache
        self._session = session
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_size)
        self._workers: List[asyncio.Task] = []
        self._hits = 0
        self._total = 0

    async def start(self) -> None:
        if not self._config.enabled:
            return
        self._workers = [
            asyncio.create_task(self._worker_loop(), name=f"greynoise-worker-{i}")
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "greynoise",
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
        cached = self._local_cache.greynoise_scores.get(ip)
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
        """Convert cached GreyNoise data to a RiskSignal."""
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")

        score = 0
        reasons = []

        if noise:
            score += self._config.noise_score
            reasons.append(f"GreyNoise noise ({classification})")
        
        if riot:
            score -= self._config.riot_score_reduction
            reasons.append("GreyNoise RIOT (known benign)")

        if score == 0:
            return None

        # Cap score but allow negative (reductions)
        score = max(-100, min(score, self._config.score_cap))

        return RiskSignal(
            name="greynoise",
            score=score,
            reason=", ".join(reasons)
        )

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis; if miss, enqueue API lookup."""
        try:
            val = await self._redis.get(f"greynoise:data:{ip}")
            if val:
                data = json.loads(val)
                self._local_cache.greynoise_scores.set(ip, data)
                return
        except Exception as e:
            logger.warning(f"greynoise | event=redis_read_error | ip={ip} | error={e}")

        # Bloom dedup (shared with AbuseIPDB logic)
        try:
            added = await self._redis.bf().add("bloom:greynoise_enriched", ip)
            if added in (0, False):
                return
            await self._redis.expire("bloom:greynoise_enriched", 86400)
        except Exception:
            # Fallback to simple set if RedisBloom missing
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
                logger.error(f"greynoise | event=worker_error | error={e}")

    async def _process_lookup(self, ip: str):
        if not self._config.api_key:
            return

        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": self._config.api_key, "Accept": "application/json"}
        
        try:
            async with self._session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Normalize data
                    result = {
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "classification": data.get("classification", "unknown")
                    }
                    _LOOKUP_TOTAL.labels(result="success").inc()
                elif resp.status == 404:
                    result = {"noise": False, "riot": False, "classification": "unknown"}
                    _LOOKUP_TOTAL.labels(result="not_found").inc()
                else:
                    logger.warning(f"greynoise | event=api_error | status={resp.status} | ip={ip}")
                    _LOOKUP_TOTAL.labels(result="error").inc()
                    return

                # Cache result
                await self._redis.setex(
                    f"greynoise:data:{ip}",
                    self._config.cache_ttl_seconds,
                    json.dumps(result)
                )
                self._local_cache.greynoise_scores.set(ip, result)

        except asyncio.TimeoutError:
            _LOOKUP_TOTAL.labels(result="timeout").inc()
        except Exception as e:
            logger.error(f"greynoise | event=api_exception | ip={ip} | error={e}")
            _LOOKUP_TOTAL.labels(result="error").inc()

    def on_config_reload(self, new_config: dict) -> None:
        self._config = GreyNoiseConfig.from_config(new_config)
