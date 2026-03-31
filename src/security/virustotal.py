"""
Phase 46 — VirusTotal Threat Intelligence Integration.

Provides reputation scoring from VirusTotal API.
Identifies IPs associated with known malicious files, URLs, and domains.
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
    "ja4proxy_virustotal_lookup_total",
    "VirusTotal API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_virustotal_enrichment_queue_depth",
    "Current depth of the VirusTotal enrichment queue",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_virustotal_cache_hit_ratio",
    "Rolling 5-minute approximation of the VirusTotal cache hit ratio",
)

_QUOTA_REMAINING = Gauge(
    "ja4proxy_virustotal_quota_remaining",
    "Remaining VirusTotal API quota for the current period",
)


@dataclass
class VirusTotalConfig(TIProviderConfig):
    """Configuration for VirusTotalProvider."""
    malicious_score: int = 30  # Score for malicious detection
    suspicious_score: int = 15  # Score for suspicious detection
    daily_quota: int = 10000  # Daily API quota limit

    @classmethod
    def from_config(cls, config: dict) -> "VirusTotalConfig":
        cfg = config.get("virustotal", {})
        api_key = cfg.get("api_key", "") or os.environ.get("VIRUSTOTAL_API_KEY", "")
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=api_key,
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 3600)),  # 1h default
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 5)),
            score_cap=int(cfg.get("score_cap", 70)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 2)),
            malicious_score=int(cfg.get("malicious_score", 30)),
            suspicious_score=int(cfg.get("suspicious_score", 15)),
            daily_quota=int(cfg.get("daily_quota", 10000)),
        )


class VirusTotalProvider(TIProvider):
    """
    Async VirusTotal reputation provider.
    """

    def __init__(
        self,
        config: VirusTotalConfig,
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
        self._quota_used_today = 0
        self._last_quota_reset = 0

    async def start(self) -> None:
        if not self._config.enabled:
            return
        
        # Load quota state from Redis
        await self._load_quota_state()
        
        self._workers = [
            asyncio.create_task(self._worker_loop(), name=f"virustotal-worker-{i}")
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "virustotal",
                "event": "started",
                "worker_count": self._config.worker_count,
                "quota_remaining": max(0, self._config.daily_quota - self._quota_used_today)
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
        cached = self._local_cache.virustotal_scores.get(ip)
        if cached is not None:
            self._hits += 1
            self._update_metrics()
            return self._to_signal(ip, cached)

        # Tier 2+: Async lookup (respects quota)
        asyncio.create_task(self._maybe_lookup(ip))
        self._update_metrics()
        return None

    def _update_metrics(self):
        if self._total > 0:
            _CACHE_HIT_RATIO.set(self._hits / self._total)
        _QUEUE_DEPTH.set(self._queue.qsize())
        _QUOTA_REMAINING.set(max(0, self._config.daily_quota - self._quota_used_today))

    def _to_signal(self, ip: str, data: dict, confidence_weight: float = 1.0) -> Optional[RiskSignal]:
        """Convert cached VirusTotal data to a RiskSignal."""
        malicious_count = data.get("malicious_count", 0)
        suspicious_count = data.get("suspicious_count", 0)
        
        if malicious_count == 0 and suspicious_count == 0:
            return None

        # Score based on detection levels
        score = 0
        reason_parts = []
        
        if malicious_count > 0:
            score += min(malicious_count * self._config.malicious_score, self._config.score_cap)
            reason_parts.append(f"{malicious_count} malicious detection(s)")
        
        if suspicious_count > 0:
            score += min(suspicious_count * self._config.suspicious_score, self._config.score_cap)
            reason_parts.append(f"{suspicious_count} suspicious detection(s)")
        
        # Cap total score
        score = min(score, self._config.score_cap)
        reason = "VirusTotal: " + ", ".join(reason_parts)

        return RiskSignal(
            name="virustotal",
            score=score,
            reason=reason,
            weight=confidence_weight
        )

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis; if miss and quota available, enqueue API lookup."""
        # Check quota first
        if self._quota_used_today >= self._config.daily_quota:
            logger.warning(f"virustotal | event=quota_exceeded | ip={ip} | quota_used={self._quota_used_today}")
            return

        try:
            val = await self._redis.get(f"virustotal:data:{ip}")
            if val:
                data = json.loads(val)
                self._local_cache.virustotal_scores.set(ip, data)
                return
        except Exception as e:
            logger.warning(f"virustotal | event=redis_read_error | ip={ip} | error={e}")

        # Bloom dedup
        try:
            added = await self._redis.bf().add("bloom:virustotal_enriched", ip)
            if added in (0, False):
                return
            await self._redis.expire("bloom:virustotal_enriched", 86400)
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
                logger.error(f"virustotal | event=worker_error | error={e}")

    async def _process_lookup(self, ip: str):
        if not self._config.api_key:
            return

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self._config.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with self._session.get(
                url, 
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    suspicious_count = last_analysis_stats.get("suspicious", 0)
                    
                    result = {
                        "malicious_count": malicious_count,
                        "suspicious_count": suspicious_count
                    }
                    
                    # Increment quota and save state
                    self._quota_used_today += 1
                    await self._save_quota_state()
                    
                    _LOOKUP_TOTAL.labels(result="success").inc()
                elif resp.status == 404:
                    result = {
                        "malicious_count": 0,
                        "suspicious_count": 0
                    }
                    _LOOKUP_TOTAL.labels(result="not_found").inc()
                elif resp.status == 403:
                    # Rate limited or quota exceeded
                    logger.warning(f"virustotal | event=api_rate_limited | ip={ip}")
                    _LOOKUP_TOTAL.labels(result="rate_limited").inc()
                    return
                else:
                    logger.warning(f"virustotal | event=api_error | status={resp.status} | ip={ip}")
                    _LOOKUP_TOTAL.labels(result="error").inc()
                    return

                # Cache result
                await self._redis.setex(
                    f"virustotal:data:{ip}",
                    self._config.cache_ttl_seconds,
                    json.dumps(result)
                )
                self._local_cache.virustotal_scores.set(ip, result)

        except asyncio.TimeoutError:
            _LOOKUP_TOTAL.labels(result="timeout").inc()
        except Exception as e:
            logger.error(f"virustotal | event=api_exception | ip={ip} | error={e}")
            _LOOKUP_TOTAL.labels(result="error").inc()

    async def _load_quota_state(self):
        """Load quota usage state from Redis."""
        try:
            quota_data = await self._redis.get("virustotal:quota:state")
            if quota_data:
                data = json.loads(quota_data)
                self._quota_used_today = data.get("quota_used", 0)
                self._last_quota_reset = data.get("last_reset", 0)
        except Exception as e:
            logger.warning(f"virustotal | event=quota_load_error | error={e}")

    async def _save_quota_state(self):
        """Save quota usage state to Redis."""
        try:
            quota_data = {
                "quota_used": self._quota_used_today,
                "last_reset": self._last_quota_reset
            }
            await self._redis.setex(
                "virustotal:quota:state",
                86400,  # 24h TTL
                json.dumps(quota_data)
            )
        except Exception as e:
            logger.warning(f"virustotal | event=quota_save_error | error={e}")

    def on_config_reload(self, new_config: dict) -> None:
        self._config = VirusTotalConfig.from_config(new_config)