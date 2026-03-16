"""Phase 9 — Beaconing Detection.

Detects C2 beacon patterns by analysing the inter-arrival time (IAT)
coefficient of variation (CV) of connections from the same IP+JA4 pair.

Statistical foundation
----------------------
Low CV (near 0)  → regular timing → likely beacon.
High CV (> 0.5)  → irregular timing → likely human browsing.

Two detection windows operate independently:
  - Short window (default 1 h): fast beacons (C2 every 60 s–30 min).
  - Long window  (default 24 h): slow-burn APT beacons (daily check-in).

Three guards prevent false positives:
  1. Browser ALPN (h2/h1) — never recorded; keep-alive patterns would FP.
  2. Whitelisted IPs (LocalCache.whitelist_decisions) — never recorded.
  3. Blocked/banned connections — excluded so blocked bots don't distort CV.

Pipeline integration
--------------------
In ``_collect_signals()``:
    beacon_signal = await self._beaconing_detector.get_signal(ctx)
    if beacon_signal is not None:
        signals.append(beacon_signal)

At the end of ``_process_inner()``, after action is determined:
    asyncio.create_task(
        self._beaconing_detector.maybe_record(
            ctx.client_ip, ctx.ja4 or "", ctx.alpn or "", result.action
        )
    )

Redis keys
----------
  beacon:{ip}:{ja4}         Sorted Set, score=timestamp, TTL=window+60 s
  beacon:long:{ip}:{ja4}    Sorted Set, score=timestamp, TTL=long_window+60 s
  beacon:suspects           Sorted Set, score=confidence (0–1), no TTL
"""

import logging
import statistics
import time
import uuid
from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge, Histogram

from .models import ConnectionContext, RiskSignal

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_BEACONING_SCORE = Histogram(
    "ja4proxy_beaconing_score",
    "Beacon score distribution (0.0 = random, 0.9 = strong beacon)",
    buckets=[0, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0],
)

_BEACONING_SUSPECTS = Gauge(
    "ja4proxy_beaconing_suspects",
    "Current number of suspected beaconers in beacon:suspects",
)

_BEACONING_RECORDS = Counter(
    "ja4proxy_beaconing_records_total",
    "Connection timestamps recorded for beaconing analysis",
)


# ---------------------------------------------------------------------------
# Statistical functions — pure, module-level, easily unit-tested
# ---------------------------------------------------------------------------


def coefficient_of_variation(values: list[float]) -> float:
    """Compute CV = stdev / mean.

    Returns 0.0 for degenerate inputs: fewer than 2 values, mean of zero,
    or all-equal values (stdev = 0).

    Args:
        values: List of numeric values (e.g. inter-arrival times in seconds).

    Returns:
        Non-negative float. 0.0 for degenerate inputs.
    """
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    stdev = statistics.stdev(values)
    return stdev / mean


def beacon_score(
    iats: list[float],
    strong_beacon: float = 0.15,
    moderate_beacon: float = 0.40,
    weak_signal: float = 0.70,
) -> float:
    """Convert inter-arrival times to a beacon confidence score (0.0–0.9).

    Args:
        iats: Inter-arrival times between consecutive connections (seconds).
              Requires at least 2 values; returns 0.0 for shorter lists.
        strong_beacon:  CV threshold below which timing is "strong beacon".
        moderate_beacon: CV threshold below which timing is "moderate".
        weak_signal:    CV threshold below which timing is "weak signal".

    Returns:
        0.9 (strong beacon) · 0.5 (moderate) · 0.2 (weak) · 0.0 (random).
    """
    if len(iats) < 2:
        return 0.0
    cv = coefficient_of_variation(iats)
    if cv < strong_beacon:
        return 0.9
    elif cv < moderate_beacon:
        return 0.5
    elif cv < weak_signal:
        return 0.2
    return 0.0


def compute_iats(timestamps: list[float]) -> list[float]:
    """Convert sorted timestamp list to inter-arrival times.

    Args:
        timestamps: Sorted list of Unix timestamps (seconds).

    Returns:
        List of time deltas between consecutive timestamps. Empty if < 2 values.
    """
    if len(timestamps) < 2:
        return []
    return [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]


# ---------------------------------------------------------------------------
# BeaconingDetector
# ---------------------------------------------------------------------------


class BeaconingDetector:
    """Detects C2 beacon patterns using inter-arrival time (IAT) analysis.

    Maintains per-IP+JA4 sorted sets of connection timestamps in Redis and
    computes the coefficient of variation of inter-arrival times to identify
    suspiciously regular connection patterns.

    Args:
        config:       Full proxy.yml config dict.
        redis_client: Async Redis client.
        local_cache:  Process-local :class:`~src.cache.local_cache.LocalCache`.
    """

    def __init__(
        self,
        config: dict,
        redis_client: object,
        local_cache: "LocalCache",
    ) -> None:
        cfg = config.get("beaconing_detector", {})
        self._redis = redis_client
        self._cache = local_cache
        self._enabled: bool = cfg.get("enabled", True)
        self._min_obs: int = cfg.get("min_observations", 8)
        self._window_size: int = cfg.get("window_size", 20)
        self._window_seconds: int = cfg.get("observation_window_seconds", 3600)
        self._score_cap: int = cfg.get("score", 35)

        cv_cfg = cfg.get("cv_thresholds", {})
        self._cv_strong: float = cv_cfg.get("strong_beacon", 0.15)
        self._cv_moderate: float = cv_cfg.get("moderate_beacon", 0.40)
        self._cv_weak: float = cv_cfg.get("weak_signal", 0.70)

        long_cfg = cfg.get("long_window", {})
        self._long_enabled: bool = long_cfg.get("enabled", True)
        self._long_seconds: int = long_cfg.get("window_seconds", 86400)
        self._long_min_obs: int = long_cfg.get("min_observations", 5)
        self._long_score_cap: int = long_cfg.get("score", 20)

        # Phase 14d: cap on beacon:suspects leaderboard size to prevent unbounded growth
        self._max_suspects: int = cfg.get("max_suspects", 10000)

    async def maybe_record(
        self,
        ip: str,
        ja4: str,
        alpn: str,
        action: str,
    ) -> None:
        """Record a connection timestamp if it passes all guards.

        Called fire-and-forget after action is determined. Silently absorbs
        all Redis errors — a recording failure must never affect the response.

        Guards:
          1. Browser ALPN (h2/h1) — regular keep-alive patterns cause FP.
          2. IP in LocalCache whitelist_decisions — trusted IPs skipped.
          3. action in {block, ban} — blocked bots inflate frequency, distorting CV.
        """
        if not self._enabled:
            return
        # Guard 1: Never track browser traffic
        if alpn in ("h2", "h1"):
            return
        # Guard 2: Skip IPs in the process-local whitelist cache
        if self._cache.whitelist_decisions.get(ip) is not None:
            return
        # Guard 3: Blocked/banned connections distort the timing distribution
        if action in ("block", "ban"):
            return

        now = time.time()
        # UUID suffix prevents collisions when two connections arrive in the
        # same millisecond (ZADD would overwrite same-score, same-member entry).
        uid = f"{now:.6f}:{uuid.uuid4().hex[:8]}"

        # Short window
        try:
            key = f"beacon:{ip}:{ja4}"
            pipe = self._redis.pipeline(transaction=False)
            pipe.zadd(key, {uid: now})
            pipe.zremrangebyscore(key, 0, now - self._window_seconds)
            # Trim to newest window_size entries to cap memory usage
            pipe.zremrangebyrank(key, 0, -(self._window_size + 2))
            pipe.expire(key, self._window_seconds + 60)
            await pipe.execute()
            _BEACONING_RECORDS.inc()
        except Exception as exc:
            logger.debug(
                "beaconing | event=record_failed | ip=%s | error=%s", ip, exc
            )
            return  # Don't attempt long window if short window failed

        # Long window (independent error boundary — a long-window failure is non-fatal)
        if self._long_enabled:
            try:
                long_key = f"beacon:long:{ip}:{ja4}"
                pipe = self._redis.pipeline(transaction=False)
                pipe.zadd(long_key, {uid: now})
                pipe.zremrangebyscore(long_key, 0, now - self._long_seconds)
                pipe.expire(long_key, self._long_seconds + 60)
                await pipe.execute()
            except Exception as exc:
                logger.debug(
                    "beaconing | event=long_record_failed | ip=%s | error=%s", ip, exc
                )

    async def get_signal(
        self, ctx: ConnectionContext
    ) -> RiskSignal | None:
        """Analyse timing data for this IP+JA4 and return a beacon signal.

        Checks short window first, then long window independently. Returns the
        first (highest-confidence) signal found, or None.

        Args:
            ctx: Connection context with client_ip, ja4, alpn fields.

        Returns:
            :class:`~src.security.models.RiskSignal` with ``name="beaconing"``
            if a beacon pattern is detected, otherwise ``None``.
        """
        if not self._enabled:
            return None

        short_signal = await self._check_window(
            ip=ctx.client_ip,
            ja4=ctx.ja4 or "unknown",
            key_prefix="beacon",
            window_seconds=self._window_seconds,
            min_obs=self._min_obs,
            score_cap=self._score_cap,
        )
        if short_signal is not None:
            return short_signal

        if self._long_enabled:
            return await self._check_window(
                ip=ctx.client_ip,
                ja4=ctx.ja4 or "unknown",
                key_prefix="beacon:long",
                window_seconds=self._long_seconds,
                min_obs=self._long_min_obs,
                score_cap=self._long_score_cap,
            )
        return None

    async def _check_window(
        self,
        ip: str,
        ja4: str,
        key_prefix: str,
        window_seconds: int,
        min_obs: int,
        score_cap: int,
    ) -> RiskSignal | None:
        """Read one detection window and return a signal if beacon detected."""
        key = f"{key_prefix}:{ip}:{ja4}"
        now = time.time()

        try:
            members = await self._redis.zrangebyscore(
                key, now - window_seconds, now, withscores=True
            )
        except Exception as exc:
            logger.debug(
                "beaconing | event=read_failed | ip=%s | error=%s", ip, exc
            )
            return None

        timestamps = sorted(score for _, score in members)

        if len(timestamps) < min_obs:
            return None

        iats = compute_iats(timestamps)
        score_float = beacon_score(
            iats,
            strong_beacon=self._cv_strong,
            moderate_beacon=self._cv_moderate,
            weak_signal=self._cv_weak,
        )

        if score_float == 0.0:
            return None

        risk_score = round(score_float * score_cap)
        n = len(timestamps)
        cv_val = coefficient_of_variation(iats)
        strength = (
            "strong" if score_float >= 0.9
            else ("moderate" if score_float >= 0.5 else "weak")
        )

        _BEACONING_SCORE.observe(score_float)

        # Update suspects sorted set (score = confidence).
        # Phase 14d: trim lowest-scoring entries when the cap is exceeded so
        # sustained attacks with millions of unique IPs cannot grow this set
        # without bound.
        try:
            await self._redis.zadd("beacon:suspects", {f"{ip}:{ja4}": score_float})
            count = await self._redis.zcard("beacon:suspects")
            if count > self._max_suspects:
                # Remove the (count - max_suspects) lowest-scoring entries
                trim = count - self._max_suspects
                await self._redis.zremrangebyrank("beacon:suspects", 0, trim - 1)
                count = self._max_suspects
            _BEACONING_SUSPECTS.set(count)
        except Exception:
            pass  # Non-critical — suspects list is advisory only

        return RiskSignal(
            name="beaconing",
            score=risk_score,
            reason=f"cv={cv_val:.3f} strength={strength} over {n} observations",
        )
