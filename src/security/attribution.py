"""
Phase 32 — Attacker Attribution.

Transition from individual detection to cross-connection attribution of threat actors.
Correlates JA4, JA4X, JA4T and other signals into unique Attacker Fingerprints.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import redis
from prometheus_client import Counter, Gauge

from .models import ConnectionContext, RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_ATTRIBUTION_HITS = Counter(
    "ja4proxy_attribution_hits_total",
    "Connections attributed to a known threat actor profile",
    ["category"] # category: malicious, suspicious, unknown
)

_KNOWN_ACTORS = Gauge(
    "ja4proxy_attribution_known_actors_total",
    "Total number of unique threat actor fingerprints in Redis",
)

_CORRELATION_EVENTS = Counter(
    "ja4proxy_attribution_correlations_total",
    "Number of times multiple IPs were linked to the same fingerprint",
)


@dataclass
class AttackerProfile:
    """Metadata for an attributed threat actor."""
    fingerprint: str
    category: str = "unknown" # malicious, suspicious, research, unknown
    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    associated_ips: Set[str] = field(default_factory=set)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        data = self.__dict__.copy()
        data["associated_ips"] = list(self.associated_ips)
        return json.dumps(data)

    @classmethod
    def from_json(cls, data_json: str) -> "AttackerProfile":
        data = json.loads(data_json)
        data["associated_ips"] = set(data.get("associated_ips", []))
        return cls(**data)


class AttributionManager:
    """
    Manages threat actor attribution and cross-IP correlation.
    """

    def __init__(self, redis_client: redis.asyncio.Redis, config: dict):
        self._redis = redis_client
        self._config = config.get("attribution", {})
        self._enabled = self._config.get("enabled", True)
        self._escalation_multiplier = self._config.get("escalation_multiplier", 1.5)
        self._malicious_threshold = self._config.get("malicious_threshold", 80)

    def compute_fingerprint(self, ctx: ConnectionContext) -> str:
        """
        Compute a stable, cross-IP Attacker Fingerprint.
        Combines JA4 (TLS), JA4X (Cert), and JA4T (TCP).
        """
        components = [
            ctx.ja4 or "unknown",
            ctx.ja4x or "none",
            ctx.tcp_ja4t or "none"
        ]
        raw = "|".join(components).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16] # 16-char hash is enough

    async def get_signal(self, ctx: ConnectionContext) -> Optional[RiskSignal]:
        """
        Check if the fingerprint is known and return an escalation signal.
        """
        if not self._enabled:
            return None

        afp = self.compute_fingerprint(ctx)
        
        # 1. Update Correlation (Async/Fire-and-forget)
        asyncio.create_task(self._update_correlation(afp, ctx.client_ip))

        # 2. Check for known malicious profile
        profile_json = await self._redis.get(f"attribution:profile:{afp}")
        if not profile_json:
            return None

        profile = AttackerProfile.from_json(profile_json)
        
        if profile.category == "malicious":
            _ATTRIBUTION_HITS.labels(category="malicious").inc()
            return RiskSignal(
                name="attribution_malicious",
                score=40, # High base contribution
                reason=f"Attributed to known malicious actor ({afp}). Tags: {', '.join(profile.tags)}"
            )
        elif profile.category == "suspicious":
            _ATTRIBUTION_HITS.labels(category="suspicious").inc()
            return RiskSignal(
                name="attribution_suspicious",
                score=20,
                reason=f"Attributed to suspicious pattern ({afp})"
            )

        return None

    async def _update_correlation(self, afp: str, ip: str):
        """
        Link IP to fingerprint and update profile metadata.
        """
        try:
            # 1. Add IP to fingerprint set
            added = await self._redis.sadd(f"attribution:ips:{afp}", ip)
            if added:
                _CORRELATION_EVENTS.inc()
                # Optional: expire IP set after 30 days
                await self._redis.expire(f"attribution:ips:{afp}", 2592000)

            # 2. Update or create profile
            profile_key = f"attribution:profile:{afp}"
            profile_json = await self._redis.get(profile_key)
            
            if profile_json:
                profile = AttackerProfile.from_json(profile_json)
                profile.last_seen = time.time()
                profile.associated_ips.add(ip)
            else:
                profile = AttackerProfile(
                    fingerprint=afp,
                    associated_ips={ip}
                )
                _KNOWN_ACTORS.inc()

            # Auto-promote to suspicious if seen from many IPs
            if len(profile.associated_ips) >= self._config.get("min_ips_for_suspicious", 3):
                if profile.category == "unknown":
                    profile.category = "suspicious"
                    profile.tags.append("multi_ip_actor")

            await self._redis.set(profile_key, profile.to_json())
            # Profiles live for 90 days of inactivity
            await self._redis.expire(profile_key, 7776000)

        except Exception as e:
            logger.error(f"attribution | event=correlation_error | fp={afp} | error={e}")

    def on_config_reload(self, new_config: dict):
        self._config = new_config.get("attribution", {})
        self._enabled = self._config.get("enabled", True)
        self._escalation_multiplier = self._config.get("escalation_multiplier", 1.5)
        self._malicious_threshold = self._config.get("malicious_threshold", 80)
