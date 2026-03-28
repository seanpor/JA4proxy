"""
Fingerprint store — writes ConnectionFingerprints to Redis fp:* keys (Phase 20, Group 7).

All writes are fire-and-forget from the hot path.  Failures are logged and swallowed.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from src.tap.fingerprints.correlation import ConnectionFingerprints

logger = logging.getLogger(__name__)

# TTL constants
_CONN_TTL = 7 * 86400       # 7 days
_IP_TTL = 30 * 86400        # 30 days
_JA4_TTL = 30 * 86400       # 30 days
_OS_COUNT_TTL = 30 * 86400  # 30 days
_OS_IP_TTL = 86400          # 24 hours
_JA4S_MAP_TTL = 7 * 86400   # 7 days

_IP_SORTED_SET_MAX = 1000   # keep last 1000 connections per IP


def _run(redis: Any, fn) -> "asyncio.Future":
    """Run a synchronous redis-py call in the default thread pool."""
    return asyncio.get_event_loop().run_in_executor(None, fn)


class FingerprintStore:
    """Writes and reads ConnectionFingerprints from Redis fp:* keys.

    Uses synchronous redis-py calls dispatched via ``run_in_executor`` to avoid
    blocking the event loop.

    Args:
        redis: A synchronous redis-py ``Redis`` instance.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def write(self, fp: ConnectionFingerprints) -> None:
        """Write all fp:* keys for one connection.

        Writes: fp:conn, fp:ip (ZSET), fp:ja4:hll, fp:ja4:count,
                fp:os:count, fp:os:ip, fp:ja4_to_ja4s.

        Failures are logged and swallowed — the caller must not be affected.
        """
        try:
            await self._write_conn(fp)
            await self._write_ip(fp)
            if fp.ja4:
                await self._write_ja4(fp)
            if fp.os_fingerprint:
                await self._write_os(fp)
            if fp.ja4 and fp.ja4s:
                await self._write_ja4_to_ja4s(fp)
        except Exception:
            logger.exception(
                "fingerprint_store | event=write_error | conn_id=%s", fp.conn_id
            )

    async def _write_conn(self, fp: ConnectionFingerprints) -> None:
        conn_key = f"fp:conn:{fp.conn_id}"
        d = fp.to_redis_dict()
        await _run(self._redis, lambda: self._redis.hset(conn_key, mapping=d))
        await _run(self._redis, lambda: self._redis.expire(conn_key, _CONN_TTL))

    async def _write_ip(self, fp: ConnectionFingerprints) -> None:
        ts = fp.timestamp.timestamp()
        ip_key = f"fp:ip:{fp.client_ip}"
        await _run(self._redis, lambda: self._redis.zadd(ip_key, {fp.conn_id: ts}))
        await _run(
            self._redis,
            lambda: self._redis.zremrangebyrank(ip_key, 0, -(_IP_SORTED_SET_MAX + 1)),
        )
        await _run(self._redis, lambda: self._redis.expire(ip_key, _IP_TTL))

    async def _write_ja4(self, fp: ConnectionFingerprints) -> None:
        hll_key = f"fp:ja4:hll:{fp.ja4}"
        count_key = f"fp:ja4:count:{fp.ja4}"
        await _run(self._redis, lambda: self._redis.pfadd(hll_key, fp.client_ip))
        await _run(self._redis, lambda: self._redis.expire(hll_key, _JA4_TTL))
        await _run(self._redis, lambda: self._redis.incr(count_key))
        await _run(self._redis, lambda: self._redis.expire(count_key, _JA4_TTL))

    async def _write_os(self, fp: ConnectionFingerprints) -> None:
        os_count_key = f"fp:os:count:{fp.os_fingerprint}"
        os_ip_key = f"fp:os:ip:{fp.client_ip}"
        await _run(self._redis, lambda: self._redis.incr(os_count_key))
        await _run(
            self._redis, lambda: self._redis.expire(os_count_key, _OS_COUNT_TTL)
        )
        await _run(
            self._redis,
            lambda: self._redis.set(os_ip_key, fp.os_fingerprint, ex=_OS_IP_TTL),
        )

    async def _write_ja4_to_ja4s(self, fp: ConnectionFingerprints) -> None:
        map_key = f"fp:ja4_to_ja4s:{fp.ja4}"
        await _run(
            self._redis,
            lambda: self._redis.hincrby(map_key, fp.ja4s, 1),  # type: ignore[arg-type]
        )
        await _run(
            self._redis, lambda: self._redis.expire(map_key, _JA4S_MAP_TTL)
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_ip_history(
        self, ip: str, limit: int = 10
    ) -> list[ConnectionFingerprints]:
        """Return the most recent ``limit`` connections from ``ip``.

        Reads ``fp:ip:{ip}`` (sorted set) then hydrates each conn record
        from ``fp:conn:{conn_id}``.
        """
        ip_key = f"fp:ip:{ip}"
        try:
            conn_ids: list[bytes] = await _run(
                self._redis,
                lambda: self._redis.zrevrange(ip_key, 0, limit - 1),
            )
        except Exception:
            logger.exception("fingerprint_store | event=get_ip_history_error | ip=%s", ip)
            return []

        results: list[ConnectionFingerprints] = []
        for raw_id in conn_ids:
            conn_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
            try:
                d: dict = await _run(
                    self._redis,
                    lambda cid=conn_id: self._redis.hgetall(f"fp:conn:{cid}"),
                )
                if d:
                    # Redis may return bytes keys/values
                    decoded = {
                        (k.decode() if isinstance(k, bytes) else k): (
                            v.decode() if isinstance(v, bytes) else v
                        )
                        for k, v in d.items()
                    }
                    results.append(ConnectionFingerprints.from_redis_dict(decoded))
            except Exception:
                logger.exception(
                    "fingerprint_store | event=hydrate_error | conn_id=%s", conn_id
                )
        return results

    async def get_ja4_stats(self, fingerprint: str) -> dict:
        """Return count and unique-IP estimate for a JA4 fingerprint.

        Returns:
            ``{"count": int, "unique_ips": int}`` — zeros on error.
        """
        count_key = f"fp:ja4:count:{fingerprint}"
        hll_key = f"fp:ja4:hll:{fingerprint}"
        try:
            raw_count = await _run(
                self._redis, lambda: self._redis.get(count_key)
            )
            unique_ips = await _run(
                self._redis, lambda: self._redis.pfcount(hll_key)
            )
            count = int(raw_count) if raw_count else 0
            unique_ips = int(unique_ips) if unique_ips else 0
            return {"count": count, "unique_ips": unique_ips}
        except Exception:
            logger.exception(
                "fingerprint_store | event=get_ja4_stats_error | fp=%s", fingerprint
            )
            return {"count": 0, "unique_ips": 0}
