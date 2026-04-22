"""
Phase 54 — Behavioral Attribution.

Detects complex attack patterns (sequential probing, coordinated bursts) 
and performs cross-IP correlation via stable fingerprints.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set

import redis
from prometheus_client import Counter, Gauge

from .models import ConnectionContext, RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_PATTERN_DETECTED = Counter(
    "ja4proxy_behavioral_pattern_total",
    "Coordinated or sequential patterns detected",
    ["pattern_type"] # sequential_probing, coordinated_burst, replay
)

_ACTIVE_CAMPAIGNS = Gauge(
    "ja4proxy_behavioral_active_campaigns_total",
    "Number of currently tracked attack campaigns in Redis",
)


def _sni_key_hash(sni: str) -> str:
    """Return a Redis-key-safe hash of *sni*.

    JA4PROXY-2026-0027 — SNI is attacker-controlled and can legitimately
    contain colons, asterisks, question marks, and other characters that
    collide with the Redis key namespace. Embedding raw SNI in a key
    (``behavioral:burst:{sni}``) lets a crafted SNI like
    ``evil.com:burst:legit.com`` pollute counters for ``legit.com`` or
    fan out keyspace to defeat KEYS/SCAN enumeration.

    Hashing the SNI before interpolation gives a fixed-width, collision-
    resistant identifier that keeps the key space clean without losing
    the ability to group by target hostname. 16 hex chars (64 bits) is
    well beyond what burst-window tracking needs.
    """
    return hashlib.sha256(sni.encode("utf-8", errors="replace")).hexdigest()[:16]


class BehavioralAnalyzer:
    """
    Analyzes multi-connection behavior to identify coordinated campaigns.
    """

    def __init__(self, redis_client: redis.asyncio.Redis, config: dict):
        self._redis = redis_client
        self._config = config.get("behavioral", {})
        self._enabled = self._config.get("enabled", True)
        
        # Thresholds
        self._probing_threshold = self._config.get("probing_unique_sni_threshold", 5)
        self._burst_window_ms = self._config.get("burst_window_ms", 100)
        self._burst_count_threshold = self._config.get("burst_count_threshold", 10)

    async def get_signals(self, ctx: ConnectionContext, afp: str) -> List[RiskSignal]:
        """
        Analyze current connection and return behavioral signals.
        afp: Attacker Fingerprint from AttributionManager
        """
        if not self._enabled:
            return []

        signals = []
        
        # 1. Sequential Probing Detection (Unique SNIs per fingerprint)
        if ctx.sni:
            probing_signal = await self._check_sequential_probing(afp, ctx.sni)
            if probing_signal:
                signals.append(probing_signal)

        # 2. Coordinated Burst Detection (Multiple IPs hitting same target in small window)
        burst_signal = await self._check_coordinated_burst(ctx)
        if burst_signal:
            signals.append(burst_signal)

        # 3. New Fingerprint Drift Alerting
        await self._check_fingerprint_drift(ctx.ja4)

        return signals

    async def _check_sequential_probing(self, afp: str, sni: str) -> Optional[RiskSignal]:
        """Detects if a single fingerprint is probing many different SNIs."""
        key = f"behavioral:probing:{afp}"
        try:
            # Add SNI to set of probed hostnames for this fingerprint
            await self._redis.sadd(key, sni)  # type: ignore[misc]
            await self._redis.expire(key, 3600)  # 1h window  # type: ignore[misc]

            count = await self._redis.scard(key)  # type: ignore[misc]
            if count >= self._probing_threshold:
                _PATTERN_DETECTED.labels(pattern_type="sequential_probing").inc()
                return RiskSignal(
                    name="behavioral_probing",
                    score=30,
                    reason=f"Sequential probing detected ({count} unique SNIs for fingerprint {afp})"
                )
        except Exception as e:
            logger.error(f"behavioral | event=probing_error | fp={afp} | error={e}")
        return None

    async def _check_coordinated_burst(self, ctx: ConnectionContext) -> Optional[RiskSignal]:
        """Detects multiple IPs hitting the same SNI in a very tight window."""
        if not ctx.sni:
            return None
            
        # Use millisecond precision for the window
        now_ms = int(time.time() * 1000)
        window_start = now_ms - self._burst_window_ms
        
        # JA4PROXY-2026-0027 — hash the attacker-controlled SNI before
        # interpolating it into a Redis key. Raw SNI can carry colons,
        # asterisks, etc. that collide with the key namespace.
        key = f"behavioral:burst:{_sni_key_hash(ctx.sni)}"
        try:
            # Add current hit to sorted set
            member = f"{ctx.client_ip}:{now_ms}"
            await self._redis.zadd(key, {member: now_ms})

            # Cleanup old hits
            await self._redis.zremrangebyscore(key, 0, window_start)
            await self._redis.expire(key, 10) # Short TTL for burst tracking

            # Count unique IPs in the window
            members = await self._redis.zrange(key, 0, -1)
            unique_ips = {m.decode("utf-8").split(":")[0] for m in members}

            if len(unique_ips) >= self._burst_count_threshold:
                _PATTERN_DETECTED.labels(pattern_type="coordinated_burst").inc()
                return RiskSignal(
                    name="behavioral_burst",
                    score=25,
                    reason=f"Coordinated burst detected ({len(unique_ips)} IPs in {self._burst_window_ms}ms)"
                )
        except Exception as e:
            # Log the SNI hash (not raw SNI) so attacker-controlled bytes
            # can't smuggle ANSI/control chars into the log stream.
            logger.error(
                f"behavioral | event=burst_error | sni_hash={_sni_key_hash(ctx.sni)} | error={e}"
            )
        return None

    async def _check_fingerprint_drift(self, ja4: str):
        """Track and alert on new JA4 fingerprints appearing in the environment."""
        if not ja4:
            return
            
        key = "behavioral:known_ja4"
        try:
            is_new = await self._redis.sadd(key, ja4)  # type: ignore[misc]
            if is_new:
                logger.warning(
                    json.dumps({
                        "type": "security",
                        "level": "WARN",
                        "subsystem": "behavioral",
                        "event": "new_fingerprint_detected",
                        "ja4": ja4,
                        "message": "First time seeing this JA4 fingerprint in this environment"
                    })
                )
        except Exception as e:
            logger.error(f"behavioral | event=drift_error | ja4={ja4} | error={e}")

    def on_config_reload(self, new_config: dict):
        self._config = new_config.get("behavioral", {})
        self._enabled = self._config.get("enabled", True)
        self._probing_threshold = self._config.get("probing_unique_sni_threshold", 5)
        self._burst_window_ms = self._config.get("burst_window_ms", 100)
        self._burst_count_threshold = self._config.get("burst_count_threshold", 10)
