"""In-process LRU cache with per-entry TTL for JA4proxy.

Each cache type has independent size and TTL settings tuned for the
false-positive asymmetry described in CLAUDE.md:

    whitelist_decisions  TTL 1800s  — long; a stale allow is recoverable
    block_decisions      TTL 30s    — short; a stale block hurts real users
    abuseipdb_scores     TTL 14400s — scores change slowly
    asn_class            TTL 3600s  — ASN classification changes rarely
    geoip_country        TTL 3600s  — country data is stable
    rdap_data            TTL 3600s  — RDAP changes rarely

Critical rule: Redis says block + local cache says allow → local cache wins.
This is enforced by the pipeline: it checks local cache before any Redis read.

Rate limit counters are NOT cached locally — they must be accurate across
all proxy instances. Only per-IP decisions are cached here.
"""

import time
from collections import OrderedDict
from typing import Any

from prometheus_client import Counter, Gauge


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_CACHE_OPS = Counter(
    "ja4proxy_cache_operations_total",
    "Cache get/set operations by cache type and result",
    ["type", "result"],
)

_CACHE_HIT_RATIO = Gauge(
    "ja4proxy_cache_hit_ratio",
    "Cache hit ratio per cache type (rolling)",
    ["type"],
)


class LRUCache:
    """LRU cache with per-entry TTL.

    Uses collections.OrderedDict for O(1) LRU tracking.
    TTL is checked on every get — expired entries are lazily evicted.
    No background thread required; safe for single-asyncio-event-loop use.

    Attributes:
        max_size: Maximum number of entries before LRU eviction.
        ttl_seconds: Entry lifetime in seconds after insertion.
        name: Logical name used in Prometheus labels.
    """

    def __init__(self, max_size: int, ttl_seconds: int, name: str = "unknown") -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.name = name
        self._data: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._hits: int = 0
        self._misses: int = 0

    def get(self, key: str) -> Any | None:
        """Return cached value or None if missing or expired.

        Moves the accessed entry to the most-recently-used position.
        Expired entries are deleted on access (lazy eviction).
        """
        entry = self._data.get(key)
        if entry is None:
            self._misses += 1
            _CACHE_OPS.labels(type=self.name, result="miss").inc()
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._data[key]
            self._misses += 1
            _CACHE_OPS.labels(type=self.name, result="miss").inc()
            return None
        self._data.move_to_end(key)
        self._hits += 1
        _CACHE_OPS.labels(type=self.name, result="hit").inc()
        return value

    def set(self, key: str, value: Any) -> None:
        """Insert or update a cache entry with a fresh TTL.

        Evicts the least-recently-used entry if the cache is full.
        """
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = (value, time.monotonic() + self.ttl_seconds)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)  # Remove LRU entry
        _CACHE_OPS.labels(type=self.name, result="set").inc()

    def delete(self, key: str) -> None:
        """Explicitly evict an entry (used by pub/sub invalidation)."""
        self._data.pop(key, None)

    def hit_ratio(self) -> float:
        """Return the lifetime hit ratio for this cache instance."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        ratio = self._hits / total
        _CACHE_HIT_RATIO.labels(type=self.name).set(ratio)
        return ratio

    def __len__(self) -> int:
        return len(self._data)


class LocalCache:
    """In-process cache with one LRUCache per data type.

    Instantiated once per proxy process. Updated by the pub/sub handler
    and read on every connection's hot path.

    The dial value is stored here and updated via pub/sub — no TTL.
    All other caches have type-specific TTLs from config.

    Args:
        config: Full proxy.yml config dict. Reads the ``local_cache`` section.
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get("local_cache", {})

        def _get(section: str, key: str, default: int) -> int:
            return int(cfg.get(section, {}).get(key, default))

        self.whitelist_decisions = LRUCache(
            max_size=_get("whitelist_decisions", "max_size", 50_000),
            ttl_seconds=_get("whitelist_decisions", "ttl_seconds", 1800),
            name="whitelist_decisions",
        )
        self.block_decisions = LRUCache(
            max_size=_get("block_decisions", "max_size", 100_000),
            ttl_seconds=_get("block_decisions", "ttl_seconds", 30),
            name="block_decisions",
        )
        self.abuseipdb_scores = LRUCache(
            max_size=_get("abuseipdb_scores", "max_size", 50_000),
            ttl_seconds=_get("abuseipdb_scores", "ttl_seconds", 14_400),
            name="abuseipdb_scores",
        )
        self.asn_class = LRUCache(
            max_size=_get("asn_class", "max_size", 100_000),
            ttl_seconds=_get("asn_class", "ttl_seconds", 3600),
            name="asn_class",
        )
        self.geoip_country = LRUCache(
            max_size=50_000,
            ttl_seconds=3600,
            name="geoip_country",
        )
        self.rdap_data = LRUCache(
            max_size=50_000,
            ttl_seconds=3600,
            name="rdap_data",
        )
        # Dial has no TTL — updated only by pub/sub or config reload.
        # Default 0 = monitor mode; proxy never blocks on first deploy.
        self._dial: int = 0

    @property
    def dial(self) -> int:
        """Current dial value (0–100). 0 = monitor mode (allow everything)."""
        return self._dial

    @dial.setter
    def dial(self, value: int) -> None:
        """Update dial; clamps to valid range 0–100."""
        self._dial = max(0, min(100, int(value)))
