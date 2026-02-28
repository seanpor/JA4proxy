#!/usr/bin/env python3
"""TCP & Connection Behavior Analyzer (Phase 5).

Analyzes TCP-level signals that are independent of TLS content:
- JA4T fingerprinting (OS/stack detection)
- Session resumption rates
- Connection lifespan patterns
- Concurrent connection tracking
- Return visitor trust
- TLS alert monitoring

All modules are designed to fail gracefully and never block legitimate traffic
when Redis is unavailable.
"""

import time
import re
from typing import Any
from dataclasses import dataclass

from prometheus_client import Counter, Gauge

from .risk_scorer import RiskSignal

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_TCP_SIGNAL_TOTAL = Counter(
    "ja4proxy_tcp_signal_total",
    "TCP analysis signals emitted by type",
    ["signal"]
)

_CONCURRENT_CONNECTIONS = Gauge(
    "ja4proxy_concurrent_connections",
    "Current concurrent connections (max observed)"
)

_TLS_ALERT_RATE = Counter(
    "ja4proxy_tls_alert_total",
    "TLS alert messages by type",
    ["alert_type"]
)


@dataclass
class TrustSignal:
    """Represents a score reduction for trusted visitors."""
    reduction_pct: float
    reason: str


class TCPAnalyzer:
    """Analyze TCP-level connection behavior and generate risk signals.
    
    Thread-safe (no mutable state after construction; Redis operations are
    atomic).
    
    Args:
        config: Full proxy.yml config dict. Reads the `tcp_analyzer` section.
        redis_client: Redis client for persistent tracking data.
    """

    def __init__(self, config: dict, redis_client: Any) -> None:
        """Initialize TCP analyzer with configuration and Redis client."""
        self._config = config
        self._redis = redis_client
        
        # Load configuration with sensible defaults
        cfg = config.get("tcp_analyzer", {})
        
        # Module enable/disable flags
        self._enabled = bool(cfg.get("enabled", True))
        
        # 1. JA4T Fingerprinting
        ja4t_cfg = cfg.get("tcp_fingerprinting", {})
        self._ja4t_enabled = bool(ja4t_cfg.get("enabled", True))
        self._ja4t_score = int(ja4t_cfg.get("score", 30))
        
        # 2. Session Resumption
        resumption_cfg = cfg.get("session_resumption", {})
        self._resumption_enabled = bool(resumption_cfg.get("enabled", True))
        self._resumption_min_connections = int(resumption_cfg.get("min_connections", 10))
        self._resumption_score = int(resumption_cfg.get("score", 15))
        
        # 3. Connection Lifespan
        lifespan_cfg = cfg.get("connection_lifespan", {})
        self._lifespan_enabled = bool(lifespan_cfg.get("enabled", True))
        self._lifespan_threshold_ms = int(lifespan_cfg.get("threshold_ms", 500))
        self._lifespan_min_connections = int(lifespan_cfg.get("min_connections", 5))
        self._lifespan_score = int(lifespan_cfg.get("score", 20))
        
        # 4. Concurrent Connections
        concurrent_cfg = cfg.get("concurrent_connections", {})
        self._concurrent_enabled = bool(concurrent_cfg.get("enabled", True))
        self._concurrent_thresholds = concurrent_cfg.get("thresholds", {
            "moderate": 20,
            "high": 50,
            "severe": 100
        })
        self._concurrent_scores = concurrent_cfg.get("risk_scores", {
            "moderate": 10,
            "high": 25,
            "severe": 40
        })
        
        # 5. Return Visitor Trust
        visitor_cfg = cfg.get("return_visitor", {})
        self._return_visitor_enabled = bool(visitor_cfg.get("enabled", True))
        self._trusted_days = int(visitor_cfg.get("trusted_days", 7))
        self._trusted_allow_rate = float(visitor_cfg.get("trusted_allow_rate", 0.90))
        self._score_reduction_pct = int(visitor_cfg.get("score_reduction_pct", 20))
        
        # 6. TLS Alerts
        alerts_cfg = cfg.get("tls_alerts", {})
        self._tls_alerts_enabled = bool(alerts_cfg.get("enabled", True))
        self._alert_rate_threshold = int(alerts_cfg.get("rate_threshold", 5))
        self._alert_score = int(alerts_cfg.get("score", 20))

    def analyze(self, ctx: Any) -> tuple[list[RiskSignal], list[TrustSignal]]:
        """Analyze connection and return risk signals and trust signals.
        
        Args:
            ctx: ConnectionContext with TCP-level data populated.
            
        Returns:
            Tuple of (risk_signals, trust_signals). Risk signals increase score;
            trust signals reduce it.
        """
        if not self._enabled:
            return [], []
        
        risk_signals = []
        trust_signals = []
        
        try:
            # 1. JA4T Fingerprinting
            if self._ja4t_enabled:
                risk_signals.extend(self._check_ja4t_mismatch(ctx))
            
            # 2. Session Resumption
            if self._resumption_enabled:
                risk_signals.extend(self._check_session_resumption(ctx))
            
            # 3. Connection Lifespan
            if self._lifespan_enabled:
                risk_signals.extend(self._check_connection_lifespan(ctx))
            
            # 4. Concurrent Connections
            if self._concurrent_enabled:
                risk_signals.extend(self._check_concurrent_connections(ctx))
            
            # 5. Return Visitor Trust
            if self._return_visitor_enabled:
                trust_signals.extend(self._check_return_visitor(ctx))
            
            # 6. TLS Alerts
            if self._tls_alerts_enabled:
                risk_signals.extend(self._check_tls_alerts(ctx))
                
        except Exception as exc:
            # Fail gracefully - never crash the pipeline
            # Log error but continue processing
            # In production, this would use structured logging
            pass
        
        return risk_signals, trust_signals

    def _check_ja4t_mismatch(self, ctx: Any) -> list[RiskSignal]:
        """Check for JA4T OS mismatch with JA4-implied OS."""
        signals = []
        
        # Extract JA4T and JA4 from context
        ja4t = getattr(ctx, 'tcp_ja4t', '')
        ja4 = getattr(ctx, 'ja4', '')
        
        if not ja4t or not ja4:
            return signals
        
        try:
            # Map JA4T to OS
            ja4t_os = self._map_ja4t_to_os(ja4t)
            
            # Map JA4 to implied OS
            ja4_implied_os = self._map_ja4_to_implied_os(ja4)
            
            # Check for mismatch
            if ja4t_os != ja4_implied_os and ja4t_os != "unknown" and ja4_implied_os != "unknown":
                signals.append(RiskSignal(
                    name="ja4t_mismatch",
                    score=self._ja4t_score,
                    reason=f"JA4T OS mismatch: {ja4t_os} vs {ja4_implied_os}"
                ))
                _TCP_SIGNAL_TOTAL.labels(signal="ja4t_mismatch").inc()
                
        except Exception:
            # Fail gracefully if parsing fails
            pass
        
        return signals

    def _check_session_resumption(self, ctx: Any) -> list[RiskSignal]:
        """Check session resumption rate."""
        signals = []
        
        # TODO: Implement actual Redis tracking
        # Key: session:ip:{ip}:ja4:{ja4} → Hash {total, resumed}
        
        # Example implementation:
        # redis_key = f"session:ip:{ctx.client_ip}:ja4:{ctx.ja4}"
        # try:
        #     data = self._redis.hgetall(redis_key)
        #     total = int(data.get(b"total", 0))
        #     resumed = int(data.get(b"resumed", 0))
        #     
        #     if total >= self._resumption_min_connections and resumed == 0:
        #         signals.append(RiskSignal(
        #             name="no_resumption",
        #             score=self._resumption_score,
        #             reason=f"No session resumption after {total} connections"
        #         ))
        #         _TCP_SIGNAL_TOTAL.labels(signal="no_resumption").inc()
        # except (redis.exceptions.RedisError, TypeError):
        #     # Redis unavailable or data corrupt - fail gracefully
        #     pass
        
        return signals

    def _check_connection_lifespan(self, ctx: Any) -> list[RiskSignal]:
        """Check connection lifespan patterns."""
        signals = []
        
        # TODO: Implement actual Redis tracking
        # Key: lifespan:{ip} → Sorted Set of durations
        
        # Example implementation:
        # redis_key = f"lifespan:{ctx.client_ip}"
        # try:
        #     durations = self._redis.zrange(redis_key, 0, -1, withscores=True)
        #     if len(durations) >= self._lifespan_min_connections:
        #         median = self._calculate_median([d[1] for d in durations])
        #         if median < self._lifespan_threshold_ms:
        #             signals.append(RiskSignal(
        #                 name="short_lived",
        #                 score=self._lifespan_score,
        #                 reason=f"Median lifespan {median:.0f}ms < {self._lifespan_threshold_ms}ms threshold"
        #             ))
        #             _TCP_SIGNAL_TOTAL.labels(signal="short_lived").inc()
        # except (redis.exceptions.RedisError, ValueError):
        #     # Redis unavailable or insufficient data - fail gracefully
        #     pass
        
        return signals

    def _check_concurrent_connections(self, ctx: Any) -> list[RiskSignal]:
        """Check concurrent connection count."""
        signals = []
        
        # TODO: Implement actual Redis tracking
        # Key: concurrent:{ip} → Integer counter
        
        # Example implementation:
        # redis_key = f"concurrent:{ctx.client_ip}"
        # try:
        #     count = self._redis.incr(redis_key)
        #     self._redis.expire(redis_key, 60)  # 60s TTL
        #     
        #     # Update Prometheus gauge
        #     _CONCURRENT_CONNECTIONS.set(count)
        #     
        #     # Check thresholds (highest matching threshold)
        #     if count >= self._concurrent_thresholds["severe"]:
        #         signals.append(RiskSignal(
        #             name="high_concurrency",
        #             score=self._concurrent_scores["severe"],
        #             reason=f"Concurrent connections: {count} (severe)"
        #         ))
        #         _TCP_SIGNAL_TOTAL.labels(signal="high_concurrency_severe").inc()
        #     elif count >= self._concurrent_thresholds["high"]:
        #         signals.append(RiskSignal(
        #             name="high_concurrency",
        #             score=self._concurrent_scores["high"],
        #             reason=f"Concurrent connections: {count} (high)"
        #         ))
        #         _TCP_SIGNAL_TOTAL.labels(signal="high_concurrency_high").inc()
        #     elif count >= self._concurrent_thresholds["moderate"]:
        #         signals.append(RiskSignal(
        #             name="high_concurrency",
        #             score=self._concurrent_scores["moderate"],
        #             reason=f"Concurrent connections: {count} (moderate)"
        #         ))
        #         _TCP_SIGNAL_TOTAL.labels(signal="high_concurrency_moderate").inc()
        # except redis.exceptions.RedisError:
        #     # Redis unavailable - fail gracefully
        #     pass
        
        return signals

    def _check_return_visitor(self, ctx: Any) -> list[TrustSignal]:
        """Check return visitor trust status."""
        trust_signals = []
        
        # TODO: Implement actual Redis tracking
        # Key: visitor:{ip} → Hash {first_seen, last_seen, total, allowed, blocked}
        
        # Example implementation:
        # redis_key = f"visitor:{ctx.client_ip}"
        # try:
        #     visitor_data = self._redis.hgetall(redis_key)
        #     if visitor_data:
        #         first_seen = float(visitor_data.get(b"first_seen", 0))
        #         total = int(visitor_data.get(b"total", 0))
        #         allowed = int(visitor_data.get(b"allowed", 0))
        #         
        #         # Check if visitor meets trust criteria
        #         days_active = (time.time() - first_seen) / 86400
        #         allow_rate = allowed / total if total > 0 else 0
        #         
        #         if (days_active >= self._trusted_days and 
        #             allow_rate >= self._trusted_allow_rate):
        #             trust_signals.append(TrustSignal(
        #                 reduction_pct=self._score_reduction_pct,
        #                 reason=f"Trusted visitor: {days_active:.1f} days, {allow_rate:.1%} allow rate"
        #             ))
        # except (redis.exceptions.RedisError, ValueError):
        #     # Redis unavailable or data corrupt - fail gracefully
        #     pass
        
        return trust_signals

    def _check_tls_alerts(self, ctx: Any) -> list[RiskSignal]:
        """Check TLS alert message patterns."""
        signals = []
        
        # TODO: Implement actual TLS alert monitoring
        # Track alerts in context and check rate
        
        # Example implementation:
        # alert_count = len(ctx.tls_alerts)
        # if alert_count > self._alert_rate_threshold:
        #     for alert in ctx.tls_alerts:
        #         _TLS_ALERT_RATE.labels(alert_type=alert).inc()
        #     signals.append(RiskSignal(
        #         name="tls_alert_rate",
        #         score=self._alert_score,
        #         reason=f"High TLS alert rate: {alert_count} alerts"
        #     ))
        #     _TCP_SIGNAL_TOTAL.labels(signal="tls_alert_rate").inc()
        
        return signals

    def on_config_reload(self, new_config: dict) -> None:
        """Apply new configuration on hot reload."""
        self.__init__(new_config, self._redis)

    def connection_closed(self, ctx: Any) -> None:
        """Called when connection closes to clean up counters."""
        try:
            if self._concurrent_enabled:
                # Decrement concurrent connection counter
                redis_key = f"concurrent:{ctx.client_ip}"
                self._redis.decr(redis_key)
        except Exception:
            # Fail gracefully if Redis unavailable
            pass

    @staticmethod
    def _calculate_median(values: list[float]) -> float:
        """Calculate median of a list of values."""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        n = len(sorted_values)
        if n % 2 == 1:
            return sorted_values[n // 2]
        else:
            return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2

    @staticmethod
    def _map_ja4t_to_os(ja4t: str) -> str:
        """Map JA4T fingerprint to OS based on TCP characteristics.
        
        JA4T format: window_size,ttl,tcp_options
        - Window size: Typical values by OS
        - TTL: Typical values by OS
        - TCP options: Ordering and presence
        """
        if not ja4t:
            return "unknown"
        
        try:
            # Parse JA4T components (simplified parsing)
            parts = ja4t.split(',')
            if len(parts) >= 3:
                window_size = parts[0]
                ttl = parts[1]
                
                # TTL patterns (more reliable than window size)
                if ttl == '64':
                    return "linux"
                elif ttl == '128':
                    return "windows"
                elif ttl == '255':
                    return "macos"
                
                # Window size patterns as fallback
                if window_size == '64240':
                    return "linux"
                elif window_size == '128000':
                    return "windows"
                elif window_size == '256000':
                    return "macos"
                
                # Default based on common patterns
                return "linux" if ttl == '64' else "unknown"
            
        except Exception:
            pass
        
        return "unknown"

    @staticmethod
    def _map_ja4_to_implied_os(ja4: str) -> str:
        """Map JA4 fingerprint to implied OS based on common browser/OS combinations.
        
        This uses heuristic patterns from common JA4 fingerprints.
        """
        if not ja4 or len(ja4) < 5:
            return "unknown"
        
        try:
            # Common patterns (simplified - would use actual fingerprint database in production)
            if 't13d' in ja4:  # TLS 1.3
                if 'h2' in ja4:
                    return "windows"  # Common for Windows browsers
                elif 'h1' in ja4:
                    return "macos"    # Common for macOS browsers
            elif 't12d' in ja4:  # TLS 1.2
                return "linux"     # Common for Linux tools
            
            # Default guess - only if it looks like a valid pattern
            if 'h2' in ja4 and 't13d' in ja4:
                return "windows"
            elif 'h1' in ja4 and 't13d' in ja4:
                return "macos"
            elif 't12d' in ja4:
                return "linux"
            
        except Exception:
            pass
        
        return "unknown"
