"""Bloom filter wrapper with graceful fallback to Redis SET.

Redis Stack (redis/redis-stack:latest) provides the RedisBloom module.
If it is unavailable (e.g. plain Redis in tests), this wrapper falls back
to a plain Redis SET with a 24-hour TTL. The fallback is correct — only
less memory-efficient.

Used for enrichment deduplication:
  bloom:rdap_enriched      — IPs whose RDAP data has been fetched
  bloom:abuseipdb_enriched — IPs whose AbuseIPDB score has been fetched

A Bloom filter false positive means: the proxy believes an IP was already
enriched, so it skips the lookup. This is acceptable — the IP will be
enriched on a future connection when the filter resets. False positives
never affect security decisions; they only affect enrichment freshness.

The proxy must never crash because of a Bloom filter error. All errors
are caught, logged, and treated as "not seen" (trigger the enrichment).
"""

import logging

logger = logging.getLogger(__name__)

# Fallback SET key TTL when RedisBloom is unavailable
_FALLBACK_TTL_SECONDS = 86_400  # 24 hours


class BloomFilter:
    """Bloom filter backed by RedisBloom or a plain Redis SET fallback.

    Args:
        redis_client: Async redis.asyncio client.
        name: Bloom filter name, used as the Redis key.
        error_rate: Desired false-positive rate (default 1%).
        capacity: Expected number of unique items (default 1 million).
    """

    def __init__(
        self,
        redis_client: object,
        name: str,
        error_rate: float = 0.01,
        capacity: int = 1_000_000,
    ) -> None:
        self._redis = redis_client
        self._name = name
        self._error_rate = error_rate
        self._capacity = capacity
        self._use_bloom: bool = False
        self._fallback_key = f"bloom_fallback:{name}"

    async def initialize(self) -> None:
        """Create the Bloom filter in Redis, or activate fallback.

        Idempotent — safe to call on every startup (BF.RESERVE returns
        an error if the key already exists, which we treat as success).
        """
        try:
            await self._redis.bf().reserve(self._name, self._error_rate, self._capacity)
            self._use_bloom = True
            logger.info(
                "bloom_filter initialized | name=%s | error_rate=%.3f | capacity=%d",
                self._name,
                self._error_rate,
                self._capacity,
            )
        except Exception as exc:  # noqa: BLE001
            err_str = str(exc).lower()
            if "item exists" in err_str or "already exists" in err_str:
                # Filter already created from a previous run — this is fine
                self._use_bloom = True
                logger.debug("bloom_filter already exists | name=%s", self._name)
            else:
                # RedisBloom unavailable — fall back to plain SET
                self._use_bloom = False
                logger.warning(
                    "bloom_filter unavailable, using SET fallback | "
                    "name=%s | reason=%s",
                    self._name,
                    exc,
                )

    async def add(self, item: str) -> bool:
        """Add item to the filter.

        Returns:
            True if the item was newly added (not previously seen).
            False if the item was already present (or probably present).
            False on error (fail open — treat as already seen to avoid
            hammering a failed external service).
        """
        try:
            if self._use_bloom:
                result = await self._redis.bf().add(self._name, item)
                return bool(result)
            # Fallback: SADD returns 1 for new members, 0 for existing
            result = await self._redis.sadd(self._fallback_key, item)
            if result:
                await self._redis.expire(self._fallback_key, _FALLBACK_TTL_SECONDS)
            return bool(result)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "bloom_filter add error | name=%s | error=%s", self._name, exc
            )
            return False  # Fail open: treat as already seen

    async def contains(self, item: str) -> bool:
        """Check if item is probably in the filter.

        Returns:
            True if the item is probably present (may be a false positive).
            False if the item is definitely not present.
            False on error (fail open — trigger enrichment rather than skip it).
        """
        try:
            if self._use_bloom:
                result = await self._redis.bf().exists(self._name, item)
                return bool(result)
            result = await self._redis.sismember(self._fallback_key, item)
            return bool(result)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "bloom_filter contains error | name=%s | error=%s", self._name, exc
            )
            return False  # Fail open: trigger enrichment
