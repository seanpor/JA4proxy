# Aggregation Functions for Analytics Node
# Phase 12a: Foundation

import time
from typing import Dict, Any, List
from collections import defaultdict
import ipaddress


class AggregationManager:
    """Manages cross-instance aggregation of events."""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.current_window = None
        self.aggregation_data = {}
    
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