# Advanced Detection Modules for Analytics Node
# Phase 12b: Detection Modules

import ipaddress
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


class CampaignDetector:
    """Detects coordinated attack campaigns from multiple IPs in same subnet."""

    def __init__(
        self,
        density_threshold: float = 0.15,
        block_rate_threshold: float = 0.70,
        min_unique_ips: int = 10,
        window_seconds: int = 300,
    ):
        self.density_threshold = density_threshold
        self.block_rate_threshold = block_rate_threshold
        self.min_unique_ips = min_unique_ips
        self.window_seconds = window_seconds
        self.current_window = None
        self.subnet_data = defaultdict(
            lambda: {
                "total_connections": 0,
                "blocked_connections": 0,
                "unique_ips": set(),
                "first_seen": time.time(),
                "last_seen": time.time(),
            }
        )

    def get_subnet(self, ip_str: str, ipv4_mask: int = 24, ipv6_mask: int = 48) -> str:
        """Get subnet for an IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                network = ipaddress.IPv4Network(f"{ip}/{ipv4_mask}", strict=False)
                return str(network)
            else:
                network = ipaddress.IPv6Network(f"{ip}/{ipv6_mask}", strict=False)
                return str(network)
        except ValueError:
            return "invalid"

    def get_subnet_size(self, subnet: str) -> int:
        """Get the size of a subnet."""
        try:
            network = ipaddress.ip_network(subnet)
            return network.num_addresses
        except ValueError:
            return 256  # Default for /24

    def get_subnet_stats(self, subnet: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific subnet."""
        if subnet in self.subnet_data:
            data = self.subnet_data[subnet]
            subnet_size = self.get_subnet_size(subnet)
            density = len(data["unique_ips"]) / subnet_size
            block_rate = data["blocked_connections"] / max(1, data["total_connections"])
            return {
                "subnet": subnet,
                "density": density,
                "block_rate": block_rate,
                "unique_ips": len(data["unique_ips"]),
                "total_connections": data["total_connections"],
                "blocked_connections": data["blocked_connections"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            }
        return None

    def update_with_event(self, event: Dict[str, Any]):
        """Update detection data with a new event."""
        # Get current time window
        current_time = int(time.time())
        window = current_time // self.window_seconds

        if self.current_window is None:
            self.current_window = window

        # Rotate windows if needed
        if window != self.current_window:
            self._rotate_window(window)

        # Get subnet for detection
        subnet = self.get_subnet(event["src_ip"])
        if subnet == "invalid":
            return

        # Update subnet data
        data = self.subnet_data[subnet]
        data["total_connections"] += 1

        if event["action"] == "block":
            data["blocked_connections"] += 1

        data["unique_ips"].add(event["src_ip"])

        if "first_seen" not in data or event["timestamp"] < data["first_seen"]:
            data["first_seen"] = event["timestamp"]

        if event["timestamp"] > data["last_seen"]:
            data["last_seen"] = event["timestamp"]

    def detect_campaigns(self) -> List[Dict[str, Any]]:
        """Detect active campaigns."""
        campaigns = []
        current_time = time.time()

        for subnet, data in self.subnet_data.items():
            # Skip if not enough unique IPs
            if len(data["unique_ips"]) < self.min_unique_ips:
                continue

            # Skip if no recent activity (last 2 windows)
            if current_time - data["last_seen"] > 2 * self.window_seconds:
                continue

            # Calculate density (unique IPs / subnet size)
            subnet_size = self.get_subnet_size(subnet)
            density = len(data["unique_ips"]) / subnet_size

            # Calculate block rate
            if data["total_connections"] > 0:
                block_rate = data["blocked_connections"] / data["total_connections"]
            else:
                block_rate = 0.0

            # Check if campaign criteria met
            if (
                density >= self.density_threshold
                and block_rate >= self.block_rate_threshold
            ):

                campaign = {
                    "subnet": subnet,
                    "density": density,
                    "block_rate": block_rate,
                    "unique_ips": len(data["unique_ips"]),
                    "total_connections": data["total_connections"],
                    "blocked_connections": data["blocked_connections"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "severity": "high" if block_rate >= 0.8 else "medium",
                    "detected_at": time.time(),
                }
                campaigns.append(campaign)

        return campaigns

    def _rotate_window(self, new_window: int):
        """Rotate to a new time window, clearing old data."""
        # Remove subnets with no recent activity
        current_time = time.time()
        active_subnets = set()

        for subnet, data in self.subnet_data.items():
            # Keep subnets with activity in the last window
            if current_time - data["last_seen"] <= self.window_seconds:
                active_subnets.add(subnet)

        # Remove inactive subnets
        inactive_subnets = set(self.subnet_data.keys()) - active_subnets
        for subnet in inactive_subnets:
            del self.subnet_data[subnet]

        self.current_window = new_window


class JA4FingerprintIntelligence:
    """Tracks and analyzes JA4 fingerprints across all instances."""

    def __init__(
        self,
        min_observations: int = 10,
        block_rate_threshold: float = 0.95,
        window_seconds: int = 3600,
    ):  # 1 hour window for JA4 intelligence
        self.min_observations = min_observations
        self.block_rate_threshold = block_rate_threshold
        self.window_seconds = window_seconds
        self.current_window = None
        self.fingerprint_data = defaultdict(
            lambda: {
                "total_seen": 0,
                "blocked_seen": 0,
                "allowed_seen": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "sources": set(),  # Proxy IDs that have seen this fingerprint
            }
        )

    def update_with_event(self, event: Dict[str, Any]):
        """Update fingerprint intelligence with a new event."""
        # Get current time window
        current_time = int(time.time())
        window = current_time // self.window_seconds

        if self.current_window is None:
            self.current_window = window

        # Rotate windows if needed
        if window != self.current_window:
            self._rotate_window(window)

        # Get JA4 fingerprint
        ja4 = event.get("ja4")
        if not ja4:
            return

        # Update fingerprint data
        data = self.fingerprint_data[ja4]
        data["total_seen"] += 1
        data["sources"].add(event["proxy_id"])

        if event["action"] == "block":
            data["blocked_seen"] += 1
        elif event["action"] == "allow":
            data["allowed_seen"] += 1

        if "first_seen" not in data or event["timestamp"] < data["first_seen"]:
            data["first_seen"] = event["timestamp"]

        if event["timestamp"] > data["last_seen"]:
            data["last_seen"] = event["timestamp"]

    def identify_candidates(self) -> List[Dict[str, Any]]:
        """Identify JA4 fingerprints that appear suspicious."""
        candidates = []
        current_time = time.time()

        for ja4, data in self.fingerprint_data.items():
            # Skip if not enough observations
            if data["total_seen"] < self.min_observations:
                continue

            # Skip if no recent activity (last 2 windows)
            if current_time - data["last_seen"] > 2 * self.window_seconds:
                continue

            # Calculate block rate
            if data["total_seen"] > 0:
                block_rate = data["blocked_seen"] / data["total_seen"]
            else:
                block_rate = 0.0

            # Check if fingerprint is suspicious
            if block_rate >= self.block_rate_threshold:
                # Check if fingerprint appears only in blocked connections
                only_in_blocks = data["allowed_seen"] == 0 and data["blocked_seen"] > 0

                candidate = {
                    "ja4": ja4,
                    "total_seen": data["total_seen"],
                    "blocked_seen": data["blocked_seen"],
                    "allowed_seen": data["allowed_seen"],
                    "block_rate": block_rate,
                    "only_in_blocks": only_in_blocks,
                    "source_count": len(data["sources"]),
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "severity": (
                        "high" if (only_in_blocks or block_rate >= 0.9) else "medium"
                    ),
                    "detected_at": time.time(),
                }
                candidates.append(candidate)

        # Sort by block rate (highest first)
        return sorted(candidates, key=lambda x: x["block_rate"], reverse=True)

    def get_fingerprint_stats(self, ja4: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific JA4 fingerprint."""
        if ja4 in self.fingerprint_data:
            data = self.fingerprint_data[ja4]

            if data["total_seen"] > 0:
                block_rate = data["blocked_seen"] / data["total_seen"]
            else:
                block_rate = 0.0

            return {
                "ja4": ja4,
                "total_seen": data["total_seen"],
                "blocked_seen": data["blocked_seen"],
                "allowed_seen": data["allowed_seen"],
                "block_rate": block_rate,
                "source_count": len(data["sources"]),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            }
        return None

    def _rotate_window(self, new_window: int):
        """Rotate to a new time window, clearing old data."""
        # Remove fingerprints with no recent activity
        current_time = time.time()
        active_fingerprints = set()

        for ja4, data in self.fingerprint_data.items():
            # Keep fingerprints with activity in the last window
            if current_time - data["last_seen"] <= self.window_seconds:
                active_fingerprints.add(ja4)

        # Remove inactive fingerprints
        inactive_fingerprints = set(self.fingerprint_data.keys()) - active_fingerprints
        for ja4 in inactive_fingerprints:
            del self.fingerprint_data[ja4]

        self.current_window = new_window


class SlowScanDetector:
    """Detects slow scan activity (many IPs from same subnet, few requests each)."""

    def __init__(
        self,
        max_requests_per_ip: int = 3,
        min_unique_ips: int = 20,
        window_seconds: int = 300,
    ):
        self.max_requests_per_ip = max_requests_per_ip
        self.min_unique_ips = min_unique_ips
        self.window_seconds = window_seconds
        self.current_window = None
        self.subnet_data = defaultdict(
            lambda: {
                "ip_request_counts": defaultdict(int),
                "unique_ips": set(),
                "total_requests": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
            }
        )

    def get_subnet(self, ip_str: str, ipv4_mask: int = 24, ipv6_mask: int = 48) -> str:
        """Get subnet for an IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                network = ipaddress.IPv4Network(f"{ip}/{ipv4_mask}", strict=False)
                return str(network)
            else:
                network = ipaddress.IPv6Network(f"{ip}/{ipv6_mask}", strict=False)
                return str(network)
        except ValueError:
            return "invalid"

    def update_with_event(self, event: Dict[str, Any]):
        """Update detection data with a new event."""
        # Get current time window
        current_time = int(time.time())
        window = current_time // self.window_seconds

        if self.current_window is None:
            self.current_window = window

        # Rotate windows if needed
        if window != self.current_window:
            self._rotate_window(window)

        # Get subnet for detection
        subnet = self.get_subnet(event["src_ip"])
        if subnet == "invalid":
            return

        # Update subnet data
        data = self.subnet_data[subnet]
        ip = event["src_ip"]

        data["ip_request_counts"][ip] += 1
        data["unique_ips"].add(ip)
        data["total_requests"] += 1

        if "first_seen" not in data or event["timestamp"] < data["first_seen"]:
            data["first_seen"] = event["timestamp"]

        if event["timestamp"] > data["last_seen"]:
            data["last_seen"] = event["timestamp"]

    def detect_slow_scans(self) -> List[Dict[str, Any]]:
        """Detect active slow scan activity."""
        slow_scans = []
        current_time = time.time()

        for subnet, data in self.subnet_data.items():
            # Skip if not enough unique IPs
            if len(data["unique_ips"]) < self.min_unique_ips:
                continue

            # Skip if no recent activity (last 2 windows)
            if current_time - data["last_seen"] > 2 * self.window_seconds:
                continue

            # Calculate average requests per IP
            if len(data["unique_ips"]) > 0:
                avg_requests_per_ip = data["total_requests"] / len(data["unique_ips"])
            else:
                avg_requests_per_ip = 0

            # Check if slow scan criteria met
            if avg_requests_per_ip <= self.max_requests_per_ip:
                # Calculate score (0-1 scale)
                score = min(1.0, len(data["unique_ips"]) / 100)

                slow_scan = {
                    "subnet": subnet,
                    "unique_ips": len(data["unique_ips"]),
                    "total_requests": data["total_requests"],
                    "avg_requests_per_ip": avg_requests_per_ip,
                    "score": score,
                    "severity": "high" if score >= 0.8 else "medium",
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "detected_at": time.time(),
                }
                slow_scans.append(slow_scan)

        return slow_scans

    def _rotate_window(self, new_window: int):
        """Rotate to a new time window, clearing old data."""
        # Remove subnets with no recent activity
        current_time = time.time()
        active_subnets = set()

        for subnet, data in self.subnet_data.items():
            # Keep subnets with activity in the last window
            if current_time - data["last_seen"] <= self.window_seconds:
                active_subnets.add(subnet)

        # Remove inactive subnets
        inactive_subnets = set(self.subnet_data.keys()) - active_subnets
        for subnet in inactive_subnets:
            del self.subnet_data[subnet]

        self.current_window = new_window
