"""Phase 10 — AbuseIPDB Integration.

Provides reputation scoring from AbuseIPDB's crowdsourced abuse confidence
database. This is a **score contribution only** — never a hard block. IPs are
shared (CGN, VPN, corporate NAT), so hard-blocking on AbuseIPDB score alone
would create significant false positives.

Three-tier cache hierarchy
--------------------------
Tier 1: LocalCache.abuseipdb_scores (in-process LRU, TTL 4h)
    ↓ miss
Tier 2: Redis "abuseipdb:score:{ip}" (shared across instances, TTL 4h)
    ↓ miss
Tier 3: AbuseIPDB v2 API → write result back to Tier 2, then Tier 1

Fire-and-forget pattern
------------------------
get_signal() / get_score() never await network I/O. Cache misses enqueue a
background lookup via asyncio.Queue. The first connection from an unknown IP
always fails open (returns None). The second connection finds the score cached.

Bloom filter dedup
------------------
Before enqueueing, we check bloom:abuseipdb_enriched. If the IP was recently
enriched (within 24h), we skip re-enqueueing. This limits API usage and bounds
memory. On RedisBloom unavailability we fall back to a plain SET+TTL.

Daily quota management
----------------------
Redis INCR on abuseipdb:quota:{YYYY-MM-DD} tracks API requests atomically.
When the daily limit is reached, WARN is logged once, gauge set to 1, and no
new lookups are enqueued until the next UTC day.

Pipeline integration
--------------------
In _collect_signals():
    signal = self._abuseipdb_checker.get_signal(ip)
    if signal is not None:
        signals.append(signal)

At startup:
    await self._abuseipdb_checker.start()

At shutdown:
    await self._abuseipdb_checker.stop()
"""

import asyncio
import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge

from .models import RiskSignal

try:
    import aiohttp  # type: ignore
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_LOOKUP_TOTAL = Counter(
    "ja4proxy_abuseipdb_lookup_total",
    "AbuseIPDB API lookup outcomes",
    ["result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_abuseipdb_enrichment_queue_depth",
    "Current depth of the AbuseIPDB enrichment queue",
)

_QUOTA_EXHAUSTED = Gauge(
    "ja4proxy_abuseipdb_quota_exhausted",
    "1 if the daily AbuseIPDB quota is exhausted, else 0",
)

_QUOTA_USED_TODAY = Gauge(
    "ja4proxy_abuseipdb_quota_used_today",
    "Number of AbuseIPDB API requests made today",
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_abuseipdb_cache_hit_ratio",
    "Rolling 5-minute approximation of the AbuseIPDB cache hit ratio",
)

_QUEUE_DROPPED = Counter(
    "ja4proxy_abuseipdb_queue_dropped_total",
    "AbuseIPDB enrichment queue items dropped because the queue was full",
)


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass
class AbuseIPDBConfig:
    """Configuration for AbuseIPDBChecker.

    All fields except api_key and worker_count / queue_size are hot-reloadable.
    Changing worker_count or queue_size requires a proxy restart.

    Attributes:
        enabled: Master switch. False = checker is instantiated but does nothing.
        api_key: AbuseIPDB v2 API key. Loaded from ABUSEIPDB_API_KEY env var if empty.
        max_requests_per_day: Daily quota limit (shared across all instances via Redis).
        cache_ttl_seconds: TTL for abuseipdb:score:{ip} Redis keys (default 4h = 14400).
        lookup_timeout_seconds: aiohttp request timeout per API call.
        shared_ip_threshold: Confidence below this → contribution capped at 15.
        queue_size: Max pending IPs in the enrichment queue. Items dropped if full.
        worker_count: Number of background worker coroutines. Requires restart to change.
        score_cap: Maximum contribution to composite score (confidence 100 → score_cap).
        delegate_to_analytics: When true, publish IPs to Redis Set instead of calling API.
    """

    enabled: bool = False
    api_key: str = ""
    max_requests_per_day: int = 1000
    cache_ttl_seconds: int = 14400
    lookup_timeout_seconds: int = 10
    shared_ip_threshold: int = 50
    queue_size: int = 500
    worker_count: int = 3
    score_cap: int = 40
    delegate_to_analytics: bool = False

    @classmethod
    def from_config(cls, config: dict) -> "AbuseIPDBConfig":
        """Build AbuseIPDBConfig from the full proxy.yml config dict.

        Reads the ``abuseipdb`` section. Falls back to defaults for missing keys.
        Loads api_key from ABUSEIPDB_API_KEY env var if the config value is empty.
        """
        cfg = config.get("abuseipdb", {})
        api_key = cfg.get("api_key", "") or ""
        if not api_key:
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        return cls(
            enabled=cfg.get("enabled", False),
            api_key=api_key,
            max_requests_per_day=int(cfg.get("max_requests_per_day", 1000)),
            cache_ttl_seconds=int(cfg.get("cache_ttl_seconds", 14400)),
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 10)),
            shared_ip_threshold=int(cfg.get("shared_ip_threshold", 50)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 3)),
            score_cap=int(cfg.get("score_cap", 40)),
            delegate_to_analytics=bool(cfg.get("delegate_to_analytics", False)),
        )


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class QuotaExhaustedException(Exception):
    """Raised internally when the AbuseIPDB daily quota is reached (HTTP 429)."""


# ---------------------------------------------------------------------------
# Score calculation — pure, module-level, easily unit-tested
# ---------------------------------------------------------------------------


def abuseipdb_to_risk_signal(
    ip: str,
    confidence: int | None,
    shared_ip_threshold: int,
    score_cap: int,
) -> RiskSignal | None:
    """Convert AbuseIPDB confidence to a RiskSignal.

    Args:
        ip: Canonical IP string (for the signal reason text).
        confidence: AbuseIPDB confidence score 0–100, or None (unknown → fail open).
        shared_ip_threshold: Confidence below this → contribution capped at 15.
        score_cap: Maximum contribution (confidence=100 maps to exactly score_cap).

    Returns:
        RiskSignal with name="abuseipdb", or None if confidence is None.

    Score scaling:
        confidence >= shared_ip_threshold:
            contribution = round((confidence / 100) * score_cap)
        confidence < shared_ip_threshold:
            contribution = round((confidence / shared_ip_threshold) * 15)
            (Shared IP protection: below-threshold IPs still flagged but capped at 15.)
    """
    if confidence is None:
        return None

    # Scale: confidence 0–100 → risk contribution 0–score_cap
    contribution = round((confidence / 100) * score_cap)

    # Hard-block protection: if confidence is below threshold (shared IP likely),
    # cap contribution at 15 regardless of the base calculation.
    if confidence < shared_ip_threshold:
        contribution = round((confidence / shared_ip_threshold) * 15)

    return RiskSignal(
        name="abuseipdb",
        score=contribution,
        reason=f"AbuseIPDB confidence {confidence}% → contribution {contribution}",
    )


# ---------------------------------------------------------------------------
# Rolling cache hit ratio tracker
# ---------------------------------------------------------------------------


class _CacheHitTracker:
    """Maintains a rolling hit/miss ratio for the last N observations."""

    def __init__(self, window: int = 200) -> None:
        self._hits = 0
        self._total = 0
        self._window = window

    def record_hit(self) -> None:
        self._hits += 1
        self._total += 1
        if self._total > self._window:
            self._hits = max(0, self._hits - 1)
            self._total -= 1

    def record_miss(self) -> None:
        self._total += 1
        if self._total > self._window:
            self._total -= 1

    def ratio(self) -> float:
        if self._total == 0:
            return 0.0
        return self._hits / self._total


# ---------------------------------------------------------------------------
# AbuseIPDBChecker
# ---------------------------------------------------------------------------


class AbuseIPDBChecker:
    """Async AbuseIPDB reputation checker.

    Maintains a three-tier cache hierarchy and a background worker pool.
    get_signal() is the only hot-path entry point — it returns immediately
    and never makes a network call.

    Args:
        config:      Parsed :class:`AbuseIPDBConfig` instance.
        redis:       Async Redis client (redis.asyncio.Redis).
        local_cache: Process-local :class:`~src.cache.local_cache.LocalCache`.
        session:     Shared aiohttp.ClientSession (injected at startup; never created here).
    """

    def __init__(
        self,
        config: AbuseIPDBConfig,
        redis: object,
        local_cache: "LocalCache",
        session: object,
    ) -> None:
        self._config = config
        self._redis = redis
        self._local_cache = local_cache
        self._session = session
        self._queue: asyncio.Queue | None = None
        self._workers: list[asyncio.Task] = []
        self._quota_exhausted: bool = False
        self._hit_tracker = _CacheHitTracker()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start background worker coroutines. Called once at proxy startup."""
        if not self._config.enabled:
            return
        self._queue = asyncio.Queue(maxsize=self._config.queue_size)
        self._workers = [
            asyncio.create_task(
                self._lookup_worker(), name=f"abuseipdb-worker-{i}"
            )
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps(
                {
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "abuseipdb",
                    "event": "started",
                    "worker_count": self._config.worker_count,
                    "queue_size": self._config.queue_size,
                }
            )
        )

    async def stop(self) -> None:
        """Cancel workers gracefully; log any remaining queue depth."""
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        if self._queue is not None:
            remaining = self._queue.qsize()
            if remaining:
                logger.warning(
                    json.dumps(
                        {
                            "type": "system",
                            "level": "WARN",
                            "subsystem": "abuseipdb",
                            "event": "shutdown_queue_not_empty",
                            "depth": remaining,
                        }
                    )
                )

    # ------------------------------------------------------------------
    # Hot-path entry points (never block)
    # ------------------------------------------------------------------

    def get_signal(self, ip: str) -> RiskSignal | None:
        """Hot-path entry point. Returns cached signal or None. Never blocks.

        Tier 1 (in-process LRU) is checked synchronously. On miss, a background
        coroutine is scheduled to check Tier 2 (Redis) and Tier 3 (API).

        Args:
            ip: Canonical IP address string.

        Returns:
            :class:`~src.security.models.RiskSignal` with name="abuseipdb",
            or None if no cached score is available yet.
        """
        if not self._config.enabled:
            return None

        # Tier 1: in-process LRU cache (synchronous)
        cached = self._local_cache.abuseipdb_scores.get(ip)
        if cached is not None:
            self._hit_tracker.record_hit()
            _CACHE_HIT_RATIO.set(self._hit_tracker.ratio())
            return abuseipdb_to_risk_signal(
                ip,
                cached,
                self._config.shared_ip_threshold,
                self._config.score_cap,
            )

        # Tier 2+: schedule async lookup, return None to fail open
        asyncio.create_task(self._maybe_lookup(ip))
        self._hit_tracker.record_miss()
        _CACHE_HIT_RATIO.set(self._hit_tracker.ratio())
        return None

    async def get_score(self, ip: str) -> int | None:
        """Return cached score, or None if not yet known. Never blocks the hot path.

        Checks Tier 1 (in-process) then Tier 2 (Redis). On miss, enqueues a
        background lookup and returns None immediately.

        Args:
            ip: Canonical IP address string.

        Returns:
            Integer 0–100 confidence score, or None if not cached.
        """
        if not self._config.enabled:
            return None

        # Tier 1: in-process cache
        cached = self._local_cache.abuseipdb_scores.get(ip)
        if cached is not None:
            return cached

        # Tier 2: Redis
        try:
            redis_val = await self._redis.get(f"abuseipdb:score:{ip}")
            if redis_val is not None:
                score = int(redis_val)
                self._local_cache.abuseipdb_scores.set(ip, score)
                return score
        except Exception as exc:
            logger.warning(
                "abuseipdb | event=redis_read_error | ip=%s | error=%s", ip, exc
            )

        # Tier 3: enqueue lookup (fire-and-forget), fail open
        asyncio.create_task(self._enqueue_lookup(ip))
        return None

    # ------------------------------------------------------------------
    # Internal — background pipeline
    # ------------------------------------------------------------------

    async def _maybe_lookup(self, ip: str) -> None:
        """Check Redis cache; if miss, enqueue API lookup."""
        try:
            redis_val = await self._redis.get(f"abuseipdb:score:{ip}")
            if redis_val is not None:
                score = int(redis_val)
                self._local_cache.abuseipdb_scores.set(ip, score)
                self._hit_tracker.record_hit()
                _CACHE_HIT_RATIO.set(self._hit_tracker.ratio())
                return
        except Exception as exc:
            logger.warning(
                "abuseipdb | event=redis_read_error | ip=%s | error=%s", ip, exc
            )

        # Redis miss — enqueue for API lookup
        await self._enqueue_lookup(ip)

    async def _enqueue_lookup(self, ip: str) -> None:
        """Bloom-filter dedup, then enqueue for API lookup.

        BF.ADD returns 1 if newly added, 0 if already present.
        On RedisBloom unavailability, falls back to SET+TTL.
        """
        if not self._config.enabled or self._queue is None:
            return
        if self._quota_exhausted:
            return
        if self._config.delegate_to_analytics:
            try:
                await self._redis.sadd("analytics:enrich:abuseipdb", ip)
            except Exception as exc:
                logger.warning(
                    "abuseipdb | event=delegate_error | ip=%s | error=%s", ip, exc
                )
            return

        # Bloom filter dedup
        try:
            added = await self._redis.bf().add("bloom:abuseipdb_enriched", ip)
            if not added:
                return
            # Set TTL on the bloom filter key (24h)
            try:
                await self._redis.expire("bloom:abuseipdb_enriched", 86400)
            except Exception:
                pass
        except Exception:
            # RedisBloom unavailable — fall back to SET+TTL
            try:
                bloom_key = f"bloom_fallback:abuseipdb_enriched:{ip}"
                already = await self._redis.get(bloom_key)
                if already is not None:
                    return
                await self._redis.setex(bloom_key, 86400, "1")
            except Exception as exc:
                logger.debug(
                    "abuseipdb | event=bloom_fallback_error | ip=%s | error=%s", ip, exc
                )
                # If we can't dedup, still allow enqueueing — worst case duplicates

        # Enqueue
        try:
            self._queue.put_nowait(ip)
            _QUEUE_DEPTH.set(self._queue.qsize())
        except asyncio.QueueFull:
            _QUEUE_DROPPED.inc()

    async def _lookup_worker(self) -> None:
        """Drain the enrichment queue. Runs until cancelled."""
        while True:
            try:
                ip = await self._queue.get()
                _QUEUE_DEPTH.set(self._queue.qsize())
                try:
                    await self._process_lookup(ip)
                except Exception as exc:
                    logger.error(
                        json.dumps(
                            {
                                "type": "system",
                                "level": "ERROR",
                                "subsystem": "abuseipdb",
                                "event": "worker_unhandled_error",
                                "error": str(exc),
                            }
                        )
                    )
                    _LOOKUP_TOTAL.labels(result="error").inc()
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break  # Graceful shutdown

    async def _process_lookup(self, ip: str) -> None:
        """Perform one full lookup: quota check → API call → cache write."""
        # Check and increment daily quota
        quota_ok = await self._check_quota()
        if not quota_ok:
            if not self._quota_exhausted:
                self._quota_exhausted = True
                _QUOTA_EXHAUSTED.set(1)
                logger.warning(
                    json.dumps(
                        {
                            "type": "system",
                            "level": "WARN",
                            "subsystem": "abuseipdb",
                            "event": "quota_exhausted",
                        }
                    )
                )
            _LOOKUP_TOTAL.labels(result="quota_exceeded").inc()
            return

        # Canonical IP for API submission
        try:
            canonical_ip = ipaddress.ip_address(ip).compressed
        except ValueError:
            canonical_ip = ip

        # API call
        try:
            confidence = await self._api_lookup(canonical_ip)
            _LOOKUP_TOTAL.labels(result="miss").inc()
        except QuotaExhaustedException:
            if not self._quota_exhausted:
                self._quota_exhausted = True
                _QUOTA_EXHAUSTED.set(1)
                logger.warning(
                    json.dumps(
                        {
                            "type": "system",
                            "level": "WARN",
                            "subsystem": "abuseipdb",
                            "event": "quota_exhausted",
                        }
                    )
                )
            _LOOKUP_TOTAL.labels(result="quota_exceeded").inc()
            return
        except asyncio.TimeoutError:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "abuseipdb",
                        "event": "api_timeout",
                        "ip": canonical_ip,
                    }
                )
            )
            _LOOKUP_TOTAL.labels(result="timeout").inc()
            confidence = 0  # Fail open
        except Exception as exc:
            http_status = getattr(exc, "status", None)
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "abuseipdb",
                        "event": "api_error",
                        "ip": canonical_ip,
                        "http_status": http_status,
                        "error": str(exc),
                    }
                )
            )
            _LOOKUP_TOTAL.labels(result="error").inc()
            confidence = 0  # Fail open

        # Write-through to cache
        try:
            await self._redis.setex(
                f"abuseipdb:score:{canonical_ip}",
                self._config.cache_ttl_seconds,
                str(confidence),
            )
        except Exception as exc:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "abuseipdb",
                        "event": "redis_write_error",
                        "ip": canonical_ip,
                        "error": str(exc),
                    }
                )
            )
            # Not fatal — use the result for this connection in-memory

        # Tier 1 write-through
        self._local_cache.abuseipdb_scores.set(canonical_ip, confidence)
        # Also cache under the original IP if it differed (e.g. IPv6 normalisation)
        if canonical_ip != ip:
            self._local_cache.abuseipdb_scores.set(ip, confidence)

        # Update quota gauge
        await self._update_quota_gauge()

    async def _api_lookup(self, ip: str) -> int:
        """Call AbuseIPDB v2 /check endpoint. Returns confidence score 0–100.

        Raises:
            QuotaExhaustedException: On HTTP 429.
            aiohttp.ClientError: On network or HTTP errors.
            asyncio.TimeoutError: When the request exceeds lookup_timeout_seconds.
        """
        if aiohttp is None:  # pragma: no cover
            raise RuntimeError("aiohttp is not installed")

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 30, "verbose": False}
        headers = {"Key": self._config.api_key, "Accept": "application/json"}

        async with self._session.get(
            url,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds),
        ) as resp:
            if resp.status == 429:
                raise QuotaExhaustedException()
            resp.raise_for_status()
            data = await resp.json()
            return int(data["data"]["abuseConfidenceScore"])

    async def _check_quota(self) -> bool:
        """Return True if quota is available. Uses Redis INCR for atomic tracking.

        Uses datetime.now(timezone.utc) — never datetime.utcnow() (deprecated).
        """
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"abuseipdb:quota:{today}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                # New key — set TTL: rest of today + 1h buffer
                await self._redis.expire(key, 86400 + 3600)
            if count > self._config.max_requests_per_day:
                await self._redis.decr(key)  # Roll back the increment
                return False
            return True
        except Exception as exc:
            logger.warning(
                "abuseipdb | event=quota_check_error | error=%s | failing open", exc
            )
            return True  # Fail open on quota check failure

    async def _update_quota_gauge(self) -> None:
        """Update the Prometheus quota_used_today gauge."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"abuseipdb:quota:{today}"
        try:
            val = await self._redis.get(key)
            if val is not None:
                _QUOTA_USED_TODAY.set(int(val))
            # Check if a new day started and reset exhausted flag
            if self._quota_exhausted:
                if val is None or int(val) <= self._config.max_requests_per_day:
                    self._quota_exhausted = False
                    _QUOTA_EXHAUSTED.set(0)
        except Exception:
            pass

    def on_config_reload(self, new_config: dict) -> None:
        """Apply hot-reloadable config changes.

        Hot-reloadable: enabled, api_key, max_requests_per_day, cache_ttl_seconds,
                        lookup_timeout_seconds, shared_ip_threshold, score_cap,
                        delegate_to_analytics.
        NOT hot-reloadable: worker_count, queue_size (requires restart).

        Logs WARN if worker_count or queue_size changed (restart required).
        Logs WARN if enabled was toggled false→true (restart required).
        """
        new_cfg = AbuseIPDBConfig.from_config(new_config)

        if new_cfg.worker_count != self._config.worker_count:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "abuseipdb",
                        "event": "restart_required",
                        "key": "worker_count",
                        "old": self._config.worker_count,
                        "new": new_cfg.worker_count,
                    }
                )
            )
        if new_cfg.queue_size != self._config.queue_size:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "abuseipdb",
                        "event": "restart_required",
                        "key": "queue_size",
                        "old": self._config.queue_size,
                        "new": new_cfg.queue_size,
                    }
                )
            )
        if not self._config.enabled and new_cfg.enabled:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "abuseipdb",
                        "event": "enabled_requires_restart",
                        "effect": "workers not started; restart proxy to enable AbuseIPDB lookups",
                    }
                )
            )

        # Apply hot-reloadable fields (keep old worker_count and queue_size)
        self._config = AbuseIPDBConfig(
            enabled=new_cfg.enabled,
            api_key=new_cfg.api_key,
            max_requests_per_day=new_cfg.max_requests_per_day,
            cache_ttl_seconds=new_cfg.cache_ttl_seconds,
            lookup_timeout_seconds=new_cfg.lookup_timeout_seconds,
            shared_ip_threshold=new_cfg.shared_ip_threshold,
            queue_size=self._config.queue_size,  # Keep old — requires restart
            worker_count=self._config.worker_count,  # Keep old — requires restart
            score_cap=new_cfg.score_cap,
            delegate_to_analytics=new_cfg.delegate_to_analytics,
        )
