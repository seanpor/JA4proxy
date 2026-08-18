# Advanced Detection Modules for Analytics Node
# Phase 12b: Detection Modules

import ipaddress
import time
from collections import defaultdict

from .correlation import CLIENT_IDENTITY_DIMENSIONS, correlate

# Upper bound on retained events per bucket. Large enough that a shared
# characteristic is unambiguous, small enough that a wide scan cannot grow
# in-process memory without limit.
_MAX_SAMPLES = 200


def _retain_sample(bucket: dict, event: dict) -> None:
    """Keep a bounded, representative sample of events for correlation."""
    samples = bucket.setdefault("samples", [])
    if len(samples) < _MAX_SAMPLES:
        samples.append(event)
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
        # Retained only AFTER the invalid-IP guard: touching
        # self.subnet_data[subnet] on a defaultdict CREATES the bucket, so
        # sampling first resurrected an "invalid" bucket for every malformed
        # address — unbounded junk state fed straight into correlation.
        _retain_sample(self.subnet_data[subnet], event)

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

                corr = correlate(data.get("samples") or [])
                campaign = {
                    # phase-827: what the group has in common, so the operator
                    # has a precise lever. Blocking the subnet is the blunt
                    # alternative and a /24 may be a corporate NAT.
                    "shared": corr.summary(),
                    "characteristics": [
                        {"dimension": c.dimension, "value": c.value,
                         "share": round(c.share, 3), "uniform": c.is_uniform}
                        for c in corr.characteristics
                    ],
                    "spread": corr.spread,
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
        min_shared_share: float = 0.80,
    ):
        self.max_requests_per_ip = max_requests_per_ip
        self.min_unique_ips = min_unique_ips
        self.window_seconds = window_seconds
        # Corroboration gate. The shape this detector looks for — many IPs in
        # one subnet, a couple of requests each — is ALSO the shape of a busy
        # five minutes on a CGNAT'd consumer ISP subnet, where 20 unrelated
        # people each load a form once. Shape alone therefore cannot convict,
        # and a finding here is not cosmetic: it writes
        # analytics:slowscan:<subnet>, which the Go proxy reads back as +30 on
        # the risk score of EVERY connection from that /24 for 30 minutes.
        #
        # So we additionally require the group to agree on some client-identity
        # dimension. Set to 0 to disable the gate and detect on shape alone
        # (pre-phase-827 behaviour) — only sensible where the proxy is not
        # populating fingerprints at all.
        self.min_shared_share = min_shared_share
        self.current_window = None
        self.subnet_data = defaultdict(
            lambda: {
                "ip_request_counts": defaultdict(int),
                "unique_ips": set(),
                "total_requests": 0,
                # phase-827: a bounded sample of the events themselves, so a
                # finding can say WHAT the group has in common (one JA4? one
                # ASN?) instead of only how many IPs it had. Bounded because
                # this is per-subnet in-process state on the ingest path —
                # correlation needs a representative sample, not every event.
                "samples": [],
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
        # Retained only AFTER the invalid-IP guard: touching
        # self.subnet_data[subnet] on a defaultdict CREATES the bucket, so
        # sampling first resurrected an "invalid" bucket for every malformed
        # address — unbounded junk state fed straight into correlation.
        _retain_sample(self.subnet_data[subnet], event)

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
                corr = correlate(
                    data.get("samples") or [],
                    min_share=self.min_shared_share or 0.80,
                )

                # Require corroboration: something about the CLIENTS must be
                # common to the group. ASN, country and SNI are excluded on
                # purpose — within one subnet, all visiting one site, those are
                # uniform for legitimate traffic too and would convict it.
                if self.min_shared_share > 0:
                    shared = [
                        c
                        for c in corr.characteristics
                        if c.dimension in CLIENT_IDENTITY_DIMENSIONS
                    ]
                    if not shared:
                        continue

                # Calculate score (0-1 scale)
                score = min(1.0, len(data["unique_ips"]) / 100)

                slow_scan = {
                    "shared": corr.summary(),
                    "characteristics": [
                        {"dimension": c.dimension, "value": c.value,
                         "share": round(c.share, 3), "uniform": c.is_uniform}
                        for c in corr.characteristics
                    ],
                    "spread": corr.spread,
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


class DistributedClientDetector:
    """Detect one client fingerprint operating from many separate networks.

    WHY THIS EXISTS
    ---------------
    CampaignDetector and SlowScanDetector both bucket by /24 before counting.
    That makes them blind to the case that matters most: 45 IPs inside one /24
    is detected, while the same 45 IPs spread across 45 different /24s puts a
    single IP in each bucket and is detected as nothing. Same attacker, same
    tooling, same fingerprint — and spreading across networks costs an attacker
    with a botnet or a few cloud regions essentially nothing.

    No threshold change fixes that, because the evidence is partitioned before
    it is counted. The fix has to invert the grouping: bucket by the client
    FINGERPRINT and treat wide network spread as the signal rather than as
    noise. A single JA4 appearing across many unrelated /24s in a short window
    is a distributed operation almost by definition, since a fingerprint
    identifies client software and legitimate software is not normally
    coordinated that way.

    Deliberately reports "investigate" rather than proposing a block: a widely
    shared fingerprint could equally be a popular library, and this project
    treats a false positive against real users as the expensive error.
    """

    def __init__(
        self,
        min_subnets: int = 10,
        min_observations: int = 20,
        window_seconds: int = 3600,
    ):
        self.min_subnets = min_subnets
        self.min_observations = min_observations
        self.window_seconds = window_seconds
        self.current_window = None
        self.fingerprint_data = defaultdict(
            lambda: {
                "subnets": set(),
                "unique_ips": set(),
                "countries": set(),
                "asns": set(),
                "total_seen": 0,
                "blocked_seen": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "samples": [],
            }
        )

    def get_subnet(self, ip_str: str, ipv4_mask: int = 24, ipv6_mask: int = 48) -> str:
        """Same bucketing as the other detectors, used here only to COUNT spread."""
        try:
            ip = ipaddress.ip_address(ip_str)
            mask = ipv4_mask if ip.version == 4 else ipv6_mask
            return str(ipaddress.ip_network(f"{ip_str}/{mask}", strict=False))
        except ValueError:
            return "invalid"

    def _rotate_window(self, window: int) -> None:
        self.fingerprint_data.clear()
        self.current_window = window

    def update_with_event(self, event: Dict[str, Any]) -> None:
        current_time = int(time.time())
        window = current_time // self.window_seconds
        if self.current_window is None:
            self.current_window = window
        if window != self.current_window:
            self._rotate_window(window)

        ja4 = event.get("ja4") or event.get("ja4proxy.fingerprint.ja4")
        src = event.get("src_ip") or event.get("source.ip")
        if not ja4 or not src:
            return

        d = self.fingerprint_data[ja4]
        d["subnets"].add(self.get_subnet(src))
        d["unique_ips"].add(src)
        for key in ("country", "client.geo.country_iso"):
            if event.get(key):
                d["countries"].add(str(event[key]))
                break
        for key in ("asn", "client.as.number"):
            if event.get(key):
                d["asns"].add(str(event[key]))
                break
        d["total_seen"] += 1
        if event.get("action") in ("block", "ban", "tarpit"):
            d["blocked_seen"] += 1
        d["last_seen"] = time.time()
        _retain_sample(d, event)

    def detect_distributed(self) -> List[Dict[str, Any]]:
        """Fingerprints operating from an unusually wide set of networks."""
        out: List[Dict[str, Any]] = []
        now = time.time()
        for ja4, d in self.fingerprint_data.items():
            if d["total_seen"] < self.min_observations:
                continue
            if len(d["subnets"]) < self.min_subnets:
                continue
            if now - d["last_seen"] > 2 * self.window_seconds:
                continue

            corr = correlate(d.get("samples") or [])
            block_rate = d["blocked_seen"] / d["total_seen"] if d["total_seen"] else 0.0
            out.append(
                {
                    "ja4": ja4,
                    "subnet_count": len(d["subnets"]),
                    "unique_ips": len(d["unique_ips"]),
                    "countries": sorted(d["countries"]),
                    "country_count": len(d["countries"]),
                    "asns": sorted(d["asns"]),
                    "asn_count": len(d["asns"]),
                    "total_seen": d["total_seen"],
                    "blocked_seen": d["blocked_seen"],
                    "block_rate": block_rate,
                    "shared": corr.summary(),
                    "characteristics": [
                        {
                            "dimension": c.dimension,
                            "value": c.value,
                            "share": round(c.share, 3),
                            "uniform": c.is_uniform,
                        }
                        for c in corr.characteristics
                    ],
                    "spread": corr.spread,
                    # Wider spread is stronger evidence of coordination, but a
                    # high block rate is NOT required: the whole point is to
                    # catch a distributed client that is currently getting
                    # through untouched.
                    "severity": "high" if len(d["subnets"]) >= self.min_subnets * 2 else "medium",
                    "first_seen": d["first_seen"],
                    "last_seen": d["last_seen"],
                    "detected_at": now,
                }
            )
        return sorted(out, key=lambda x: x["subnet_count"], reverse=True)
