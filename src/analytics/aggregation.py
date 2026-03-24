# Aggregation Functions for Analytics Node
# Phase 12a: Foundation

import ipaddress
import time
from collections import defaultdict
from typing import Any, Dict, List


class AggregationManager:
    """Manages cross-instance aggregation of events."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.current_window: int | None = None
        self.aggregation_data: Dict[str, Any] = {}

    def get_subnet(self, ip_str: str, ipv4_mask: int = 24, ipv6_mask: int = 48) -> str:
        """Get subnet for an IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                return f"{ipaddress.IPv4Network(f'{ip}/{ipv4_mask}', strict=False)}"
            else:
                return f"{ipaddress.IPv6Network(f'{ip}/{ipv6_mask}', strict=False)}"
        except ValueError:
            return "invalid"

    def update_aggregation(self, event: Dict[str, Any]):
        """Update aggregation data with a new event."""
        # Get current time window
        current_time = int(time.time())
        window = current_time // self.window_seconds

        if self.current_window is None:
            self.current_window = window

        # Rotate windows if needed
        if window != self.current_window:
            self._rotate_window(window)

        # Get subnet for aggregation
        subnet = self.get_subnet(event["src_ip"])

        # Initialize aggregation data if not exists
        if subnet not in self.aggregation_data:
            self.aggregation_data[subnet] = {
                "total_events": 0,
                "blocked_events": 0,
                "allowed_events": 0,
                "monitored_events": 0,
                "tarpitted_events": 0,
                "total_score": 0.0,
                "unique_ips": set(),
                "ja4_fingerprints": defaultdict(int)
            }

        # Ensure all action counters exist
        for action in ["block", "allow", "monitor", "tarpit"]:
            action_key = f"{action}_events"
            if action_key not in self.aggregation_data[subnet]:
                self.aggregation_data[subnet][action_key] = 0

        # Update aggregation data
        agg = self.aggregation_data[subnet]

        # Count events by action
        agg["total_events"] += 1

        # Safely increment action-specific counter
        action_key = f"{event['action']}_events"
        if action_key not in agg:
            agg[action_key] = 0
        agg[action_key] += 1

        # Track scores
        agg["total_score"] += event["score"]

        # Track unique IPs
        agg["unique_ips"].add(event["src_ip"])

        # Track JA4 fingerprints
        agg["ja4_fingerprints"][event["ja4"]] += 1

    def _rotate_window(self, new_window: int):
        """Rotate to a new time window."""
        # Clear old data (simple approach for Phase 12a)
        self.aggregation_data.clear()
        self.current_window = new_window

    def get_aggregation_results(self) -> Dict[str, Any]:
        """Get current aggregation results."""
        results = {}

        for subnet, data in self.aggregation_data.items():
            results[subnet] = {
                "total_events": data["total_events"],
                "block_events": data.get("block_events", 0),
                "allow_events": data.get("allow_events", 0),
                "monitor_events": data.get("monitor_events", 0),
                "tarpit_events": data.get("tarpit_events", 0),
                "avg_score": data["total_score"] / max(1, data["total_events"]),
                "unique_ip_count": len(data["unique_ips"]),
                "top_ja4": self._get_top_ja4(data["ja4_fingerprints"])
            }

        return results

    def _get_top_ja4(self, ja4_data: Dict[str, int]) -> List[Dict[str, Any]]:
        """Get top JA4 fingerprints by count."""
        if not ja4_data:
            return []

        sorted_ja4 = sorted(ja4_data.items(), key=lambda x: x[1], reverse=True)
        return [{"ja4": k, "count": v} for k, v in sorted_ja4[:5]]  # Top 5


class AdaptiveRateComputer:
    """Computes per-subnet EWMA traffic rates and publishes adaptive rate thresholds.

    The analytics node calls ``record_event()`` for every processed stream event,
    then ``compute_and_publish()`` every 60 seconds.  The proxy reads the published
    ``rate:adaptive:{subnet}`` Redis Hash and uses the threshold when confidence
    exceeds the configured minimum.

    Algorithm:
        rate_ewma = alpha * current_rps + (1 - alpha) * previous_ewma
        confidence = 1 - 1 / (1 + n_windows)   # grows toward 1 as more windows seen

    Alpha = 0.3 provides ~3-window lag (smooth but responsive to DDoS bursts).
    """

    _EWMA_ALPHA: float = 0.3
    _TTL_SECONDS: int = 120  # Two compute cycles; proxy falls back to static if stale.
    _KEY_PREFIX: str = "rate:adaptive:"

    def __init__(
        self,
        min_threshold_rps: int = 5,
        max_threshold_rps: int = 1000,
        window_seconds: int = 60,
    ) -> None:
        self.min_threshold_rps = min_threshold_rps
        self.max_threshold_rps = max_threshold_rps
        self.window_seconds = window_seconds

        # subnet → {"ewma": float, "windows": int, "events_this_window": int}
        self._state: Dict[str, Dict[str, Any]] = {}
        self._window_start: float = time.time()

    def record_event(self, subnet: str) -> None:
        """Record one connection event for a subnet."""
        if subnet not in self._state:
            self._state[subnet] = {"ewma": 0.0, "windows": 0, "events_this_window": 0}
        self._state[subnet]["events_this_window"] += 1

    def _rotate(self) -> None:
        """Called at the start of each compute cycle to finalise the current window."""
        now = time.time()
        elapsed = max(now - self._window_start, 1.0)  # avoid div-by-zero
        for subnet, state in self._state.items():
            current_rps = state["events_this_window"] / elapsed
            state["ewma"] = (
                self._EWMA_ALPHA * current_rps
                + (1.0 - self._EWMA_ALPHA) * state["ewma"]
            )
            state["windows"] += 1
            state["events_this_window"] = 0
        self._window_start = now

    def _confidence(self, windows: int) -> float:
        """Confidence rises toward 1.0 as more windows accumulate."""
        return 1.0 - 1.0 / (1.0 + windows)

    def _clamp(self, value: float) -> int:
        """Clamp threshold to configured bounds."""
        return max(self.min_threshold_rps, min(int(value), self.max_threshold_rps))

    async def compute_and_publish(self, redis: Any) -> int:
        """Rotate the window, compute thresholds, write to Redis.

        Args:
            redis: An async Redis client with ``hset`` and ``expire`` methods.

        Returns:
            Number of subnets published.
        """
        self._rotate()
        published = 0
        for subnet, state in self._state.items():
            if state["windows"] < 1:
                continue  # Not enough data yet
            threshold = self._clamp(state["ewma"] * 2.0)  # 2× observed mean as limit
            confidence = self._confidence(state["windows"])
            key = f"{self._KEY_PREFIX}{subnet}"
            await redis.hset(key, mapping={
                "threshold_rps": str(threshold),
                "confidence": f"{confidence:.4f}",
                "ewma_rps": f"{state['ewma']:.4f}",
                "windows": str(state["windows"]),
            })
            await redis.expire(key, self._TTL_SECONDS)
            published += 1
        return published


class HyperLogLogManager:
    """Manages HyperLogLog for unique IP counting (placeholder for Phase 12a)."""

    def __init__(self):
        # In Phase 12a, we'll use a simple set-based approach
        # Phase 12b will implement actual HyperLogLog
        self.unique_ips = defaultdict(set)

    def add_ip(self, subnet: str, ip: str):
        """Add IP to HyperLogLog structure."""
        self.unique_ips[subnet].add(ip)

    def count_unique_ips(self, subnet: str) -> int:
        """Count unique IPs in subnet."""
        return len(self.unique_ips.get(subnet, set()))

    def get_all_counts(self) -> Dict[str, int]:
        """Get unique IP counts for all subnets."""
        return {subnet: len(ips) for subnet, ips in self.unique_ips.items()}