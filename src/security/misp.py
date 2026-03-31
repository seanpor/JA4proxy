"""
Phase 46 — MISP Threat Intelligence Integration.

Provides reputation scoring from MISP (Malware Information Sharing Platform) API.
Identifies IPs associated with known malicious indicators (malware, C2, phishing).
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
    "ja4proxy_misp_lookup_total",
    "MISP API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_misp_enrichment_queue_depth",
    "Current depth of the MISP enrichment queue",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_misp_cache_hit_ratio",
    "Rolling 5-minute approximation of the MISP cache hit ratio",
)


@dataclass
class MISPConfig(TIProviderConfig):
    """Configuration for MISPProvider."""
    attribute_score: int = 20  # Score per MISP attribute match
    base_url: str = ""  # MISP instance base URL

    @classmethod
    def from_config(cls, config: dict) -> "MISPConfig":
        cfg = config.get("misp", {})
        api_key = cfg.get("api_key", "") or os.environ.get("MISP_API_KEY", "")
        base_url = cfg.get("base_url", "") or os.environ.get("MISP_BASE_URL", "")
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=api_key,
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 3600)),  # 1h default
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 5)),
            score_cap=int(cfg.get("score_cap", 50)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 2)),
            attribute_score=int(cfg.get("attribute_score", 20)),
            base_url=base_url
        )


class MISPProvider(TIProvider):
    """
    Async MISP reputation provider.
    """

    def __init__(
        self,
        config: MISPConfig,
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
            asyncio.create_task(self._worker_loop(), name=f"misp-worker-{i}")
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "misp",
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
        cached = self._local_cache.misp_scores.get(ip)
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

    def _to_signal(self, ip: str, data: dict, confidence_weight: float = 1.0) -> Optional[RiskSignal]:
        """Convert cached MISP data to a RiskSignal."""
        attribute_count = data.get("attribute_count", 0)
        if attribute_count == 0:
            return None

        # Score scales with attribute count up to cap
        score = min(attribute_count * self._config.attribute_score, self._config.score_cap)

        return RiskSignal(
            name="misp",
            score=score,
            reason=f"MISP associated with {attribute_count} attribute(s)",
            weight=confidence_weight
        )

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis; if miss, enqueue API lookup."""
        try:
            val = await self._redis.get(f"misp:data:{ip}")
            if val:
                data = json.loads(val)
                self._local_cache.misp_scores.set(ip, data)
                return
        except Exception as e:
            logger.warning(f"misp | event=redis_read_error | ip={ip} | error={e}")

        # Bloom dedup
        try:
            added = await self._redis.bf().add("bloom:misp_enriched", ip)
            if added in (0, False):
                return
            await self._redis.expire("bloom:misp_enriched", 86400)
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
                logger.error(f"misp | event=worker_error | error={e}")

    async def _process_lookup(self, ip: str):
        if not self._config.api_key or not self._config.base_url:
            return

        url = f"{self._config.base_url}/attributes/restSearch/json"
        headers = {
            "Authorization": self._config.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Search for IP address attributes
        payload = {
            "returnFormat": "json",
            "limit": 100,
            "value": ip,
            "type": "ip-dst"
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
                    attributes = data.get("response", [])
                    attribute_count = len(attributes)
                    
                    result = {"attribute_count": attribute_count}
                    _LOOKUP_TOTAL.labels(result="success").inc()
                elif resp.status == 404:
                    result = {"attribute_count": 0}
                    _LOOKUP_TOTAL.labels(result="not_found").inc()
                else:
                    logger.warning(f"misp | event=api_error | status={resp.status} | ip={ip}")
                    _LOOKUP_TOTAL.labels(result="error").inc()
                    return

                # Cache result
                await self._redis.setex(
                    f"misp:data:{ip}",
                    self._config.cache_ttl_seconds,
                    json.dumps(result)
                )
                self._local_cache.misp_scores.set(ip, result)

        except asyncio.TimeoutError:
            _LOOKUP_TOTAL.labels(result="timeout").inc()
        except Exception as e:
            logger.error(f"misp | event=api_exception | ip={ip} | error={e}")
            _LOOKUP_TOTAL.labels(result="error").inc()

    def on_config_reload(self, new_config: dict) -> None:
        self._config = MISPConfig.from_config(new_config)