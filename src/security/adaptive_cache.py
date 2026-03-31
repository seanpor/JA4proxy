"""
Phase 47 — Adaptive Caching System.

Implements volatility-based TTL (Time To Live) for threat intelligence feeds.
Dynamically adjusts cache durations based on how frequently data changes.
"""

import json
import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional

import redis.asyncio
from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_CACHE_TTL_ADJUSTMENTS = Counter(
    "ja4proxy_adaptive_cache_ttl_adjustments_total",
    "Number of TTL adjustments made by adaptive caching system",
    ["feed_name", "direction"],  # direction: up|down|unchanged
)

_CURRENT_TTL = Gauge(
    "ja4proxy_adaptive_cache_current_ttl_seconds",
    "Current TTL for each feed's cache",
    ["feed_name"],
)

_VOLATILITY_SCORE = Gauge(
    "ja4proxy_adaptive_cache_volatility_score",
    "Volatility score for each feed (0.0-1.0, where 1.0 = highly volatile)",
    ["feed_name"],
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_adaptive_cache_hit_ratio",
    "Cache hit ratio for adaptive caching system",
    ["feed_name"],
)


@dataclass
class FeedVolatility:
    """Volatility metrics for a single feed."""
    volatility_score: float = 0.5  # 0.0-1.0, where 1.0 = highly volatile
    change_count: int = 0  # Number of times cached data has changed
    access_count: int = 0  # Number of times cached data has been accessed
    last_change_time: float = 0.0  # Timestamp of last change
    current_ttl: int = 3600  # Current TTL in seconds (default: 1 hour)


class AdaptiveCacheManager:
    """
    Adaptive caching system that adjusts TTL based on data volatility.
    
    Uses a feedback loop to monitor how frequently cached data changes and
    adjusts TTL accordingly to optimize for both freshness and performance.
    """

    def __init__(self, redis_client: redis.asyncio.Redis):
        self._redis = redis_client
        self._feeds: Dict[str, FeedVolatility] = {}
        self._initialized = False
        self._hit_count: Dict[str, int] = {}
        self._miss_count: Dict[str, int] = {}
        
        # Default volatility profiles for known feeds
        self._default_profiles = {
            "misp": {"base_ttl": 3600, "volatility": 0.3},
            "threatfox": {"base_ttl": 21600, "volatility": 0.5},
            "virustotal": {"base_ttl": 7200, "volatility": 0.4},
            "greynoise": {"base_ttl": 21600, "volatility": 0.2},
            "alienvault_otx": {"base_ttl": 3600, "volatility": 0.3},
        }

    async def initialize(self) -> None:
        """Load adaptive cache state from Redis."""
        try:
            data = await self._redis.get("ja4proxy:adaptive_cache:state")
            if data:
                stored = json.loads(data)
                for feed_name, metrics in stored.items():
                    self._feeds[feed_name] = FeedVolatility(
                        volatility_score=metrics.get("volatility_score", 0.5),
                        change_count=metrics.get("change_count", 0),
                        access_count=metrics.get("access_count", 0),
                        last_change_time=metrics.get("last_change_time", 0.0),
                        current_ttl=metrics.get("current_ttl", 3600)
                    )
                    self._update_metrics(feed_name)
            
            # Initialize any feeds not in storage with defaults
            for feed_name in self._default_profiles:
                if feed_name not in self._feeds:
                    profile = self._default_profiles[feed_name]
                    self._feeds[feed_name] = FeedVolatility(
                        volatility_score=profile["volatility"],
                        current_ttl=profile["base_ttl"]
                    )
                    self._update_metrics(feed_name)
            
            # Initialize hit/miss counters
            for feed_name in self._feeds:
                self._hit_count[feed_name] = 0
                self._miss_count[feed_name] = 0
            
            self._initialized = True
            logger.info("adaptive_cache | event=initialized | feed_count=%d", len(self._feeds))
        except Exception as e:
            logger.error("adaptive_cache | event=init_failed | error=%s", e)
            # Fall back to defaults
            for feed_name in self._default_profiles:
                profile = self._default_profiles[feed_name]
                self._feeds[feed_name] = FeedVolatility(
                    volatility_score=profile["volatility"],
                    current_ttl=profile["base_ttl"]
                )
                self._hit_count[feed_name] = 0
                self._miss_count[feed_name] = 0
            self._initialized = True

    async def save_state(self) -> None:
        """Save current adaptive cache state to Redis."""
        if not self._initialized:
            return
        
        try:
            state = {}
            for feed_name, volatility in self._feeds.items():
                state[feed_name] = {
                    "volatility_score": volatility.volatility_score,
                    "change_count": volatility.change_count,
                    "access_count": volatility.access_count,
                    "last_change_time": volatility.last_change_time,
                    "current_ttl": volatility.current_ttl
                }
            
            await self._redis.setex(
                "ja4proxy:adaptive_cache:state",
                86400,  # 24h TTL
                json.dumps(state)
            )
        except Exception as e:
            logger.error("adaptive_cache | event=save_failed | error=%s", e)

    def _update_metrics(self, feed_name: str) -> None:
        """Update Prometheus metrics for a feed."""
        if feed_name not in self._feeds:
            return
        
        volatility = self._feeds[feed_name]
        _VOLATILITY_SCORE.labels(feed_name=feed_name).set(volatility.volatility_score)
        _CURRENT_TTL.labels(feed_name=feed_name).set(volatility.current_ttl)
        
        # Calculate hit ratio
        total = volatility.access_count
        if total > 0:
            hit_ratio = (self._hit_count.get(feed_name, 0) / total) if total > 0 else 0.0
            _CACHE_HIT_RATIO.labels(feed_name=feed_name).set(hit_ratio)

    def get_adaptive_ttl(self, feed_name: str) -> int:
        """
        Get the adaptive TTL for a feed.
        
        Args:
            feed_name: Name of the feed (e.g., "misp", "virustotal")
            
        Returns:
            Adaptive TTL in seconds
        """
        if not self._initialized:
            # Fallback to default if not initialized
            profile = self._default_profiles.get(feed_name, {"base_ttl": 3600})
            return profile.get("base_ttl", 3600)
        
        if feed_name not in self._feeds:
            # Unknown feed - use default TTL
            return 3600
        
        return self._feeds[feed_name].current_ttl

    async def record_cache_hit(self, feed_name: str) -> None:
        """
        Record a cache hit for adaptive TTL calculation.
        
        Args:
            feed_name: Name of the feed
        """
        if not self._initialized or feed_name not in self._feeds:
            return
        
        self._hit_count[feed_name] = self._hit_count.get(feed_name, 0) + 1
        self._feeds[feed_name].access_count += 1
        self._update_metrics(feed_name)
        
        # Save state periodically
        if self._feeds[feed_name].access_count % 50 == 0:
            await self.save_state()

    async def record_cache_miss(self, feed_name: str, old_value: Optional[dict], new_value: dict) -> None:
        """
        Record a cache miss and check if data has changed.
        
        Args:
            feed_name: Name of the feed
            old_value: Previously cached value (None if no previous cache)
            new_value: New value being cached
        """
        if not self._initialized or feed_name not in self._feeds:
            return
        
        self._miss_count[feed_name] = self._miss_count.get(feed_name, 0) + 1
        self._feeds[feed_name].access_count += 1
        
        # Check if data has actually changed (indicating volatility)
        data_changed = False
        if old_value is None:
            # First time caching this item - not a change
            data_changed = False
        else:
            # Compare key fields to detect changes
            old_key = self._get_cache_key(old_value)
            new_key = self._get_cache_key(new_value)
            data_changed = (old_key != new_key)
        
        if data_changed:
            self._feeds[feed_name].change_count += 1
            self._feeds[feed_name].last_change_time = time.time()
            
            # Adjust volatility score based on change frequency
            self._adjust_volatility(feed_name)
            
            logger.debug(
                "adaptive_cache | event=data_changed | feed=%s | "
                "volatility=%.2f | new_ttl=%ds",
                feed_name,
                self._feeds[feed_name].volatility_score,
                self._feeds[feed_name].current_ttl
            )
        
        self._update_metrics(feed_name)
        
        # Save state periodically
        if self._feeds[feed_name].access_count % 50 == 0:
            await self.save_state()

    def _get_cache_key(self, data: dict) -> str:
        """Generate a comparison key for cache data."""
        # For threat intelligence data, we typically care about the core detection counts
        if "attribute_count" in data:
            return f"attr:{data['attribute_count']}"
        elif "ioc_count" in data:
            return f"ioc:{data['ioc_count']}"
        elif "malicious_count" in data and "suspicious_count" in data:
            return f"vt:{data['malicious_count']},{data['suspicious_count']}"
        else:
            # Fallback: use JSON string (not ideal for comparison but works)
            return json.dumps(data, sort_keys=True)

    def _adjust_volatility(self, feed_name: str) -> None:
        """
        Adjust volatility score and TTL based on change frequency.
        
        Uses a simple algorithm:
        - More frequent changes → higher volatility → shorter TTL
        - Less frequent changes → lower volatility → longer TTL
        """
        if feed_name not in self._feeds:
            return
        
        volatility = self._feeds[feed_name]
        access_count = max(1, volatility.access_count)
        change_ratio = volatility.change_count / access_count
        
        # Calculate new volatility score (0.0-1.0)
        # Use exponential moving average to smooth changes
        old_score = volatility.volatility_score
        new_score = change_ratio  # Simple ratio for now
        blended_score = (old_score * 0.7) + (new_score * 0.3)  # 70% old, 30% new
        volatility.volatility_score = max(0.0, min(1.0, blended_score))
        
        # Calculate new TTL based on volatility
        # Formula: TTL = base_ttl × (1.0 - volatility) × multiplier + min_ttl
        base_ttl = self._default_profiles.get(feed_name, {"base_ttl": 3600})["base_ttl"]
        min_ttl = max(300, base_ttl // 10)  # Minimum 5 minutes or 10% of base
        
        # More volatile → shorter TTL
        ttl_reduction = volatility.volatility_score * 0.8  # Reduce by up to 80%
        new_ttl = int(base_ttl * (1.0 - ttl_reduction))
        new_ttl = max(min_ttl, new_ttl)  # Enforce minimum TTL
        
        old_ttl = volatility.current_ttl
        volatility.current_ttl = new_ttl
        
        # Record adjustment direction
        if new_ttl > old_ttl:
            _CACHE_TTL_ADJUSTMENTS.labels(feed_name=feed_name, direction="up").inc()
        elif new_ttl < old_ttl:
            _CACHE_TTL_ADJUSTMENTS.labels(feed_name=feed_name, direction="down").inc()
        else:
            _CACHE_TTL_ADJUSTMENTS.labels(feed_name=feed_name, direction="unchanged").inc()

    def get_cache_stats(self, feed_name: str) -> Dict:
        """Get statistics for a feed's adaptive cache."""
        if feed_name not in self._feeds:
            return {
                "volatility_score": 0.5,
                "change_count": 0,
                "access_count": 0,
                "current_ttl": 3600,
                "hit_count": 0,
                "miss_count": 0,
                "hit_ratio": 0.0
            }
        
        volatility = self._feeds[feed_name]
        access_count = max(1, volatility.access_count)
        hit_ratio = (self._hit_count.get(feed_name, 0) / access_count) if access_count > 0 else 0.0
        
        return {
            "volatility_score": volatility.volatility_score,
            "change_count": volatility.change_count,
            "access_count": volatility.access_count,
            "current_ttl": volatility.current_ttl,
            "hit_count": self._hit_count.get(feed_name, 0),
            "miss_count": self._miss_count.get(feed_name, 0),
            "hit_ratio": hit_ratio
        }