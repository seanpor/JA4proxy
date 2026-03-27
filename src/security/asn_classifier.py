"""
ASN Classifier - Phase 6

Classifies IP addresses by ASN type (datacenter, VPN, Tor, residential, etc.)
Uses MaxMind GeoLite2-ASN database, local datacenter list, and Tor exit node list.
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Set

import aiohttp
import redis
import yaml

from src.security.models import RiskSignal

try:
    import maxminddb

    MAXMIND_AVAILABLE = True
except ImportError:  # pragma: no cover
    MAXMIND_AVAILABLE = False


@dataclass
class ASNClassification:
    """Classification result for an IP address."""

    asn: int
    asn_str: str
    org_name: str
    category: str  # residential|mobile|datacenter|vpn|tor|unknown


RISK_SCORES = {
    "tor": 40,
    "datacenter": 20,
    "vpn": 10,
    "unknown": 5,
    "residential": 0,
    "mobile": 0,
}

RESIDENTIAL_PATTERNS = [
    ".dsl.",
    ".cable.",
    ".broadband.",
    ".fibonacci",
    "comcast",
    "spectrum",
    "charter",
    "verizon",
    "at&t",
    "t-mobile",
    "orange",
    "vodafone",
    "telecom",
]

VPN_PATTERNS = [
    "nord",
    "expressvpn",
    "cyberghost",
    "purevpn",
    "ipvanish",
    "protonvpn",
    "mullvad",
    "windscribe",
    "tunnelbear",
    "hotspotshield",
]


class ASNClassifier:
    """Classifies IP addresses by ASN type."""

    def __init__(self, config: dict, redis_client=None):
        self._config = config.get("asn_classifier", {})
        self._enabled = self._config.get("enabled", True)
        self._redis_client = redis_client
        self.logger = logging.getLogger(__name__)

        self._datacenter_asns: Dict[int, str] = {}
        self._tor_exit_ips: Set[str] = set()
        self._tor_refresh_task = None
        self._instance_id = f"asn-{os.getpid()}-{time.time()}"

        self._risk_scores = self._config.get(
            "risk_contributions",
            {
                "tor": 40,
                "datacenter": 20,
                "vpn": 10,
                "unknown": 5,
                "residential": 0,
                "mobile": 0,
            },
        )

        self._maxmind_reader = None
        self._load_datacenter_list()
        self._init_maxmind()
        self._tor_list_initialized = False
        self._schedule_tor_list_init()

    def _schedule_tor_list_init(self) -> None:
        """Schedule async Tor list initialization without blocking __init__."""
        # Defer all Tor list initialization to lazy loading in signals() method
        # This prevents unawaited coroutine warnings during module import
        # and ensures proper async context is available
        self._tor_list_initialized = False

    def _load_datacenter_list(self) -> None:
        """Load datacenter ASN list from config file."""
        config_path = self._config.get(
            "datacenter_list_path", "config/asn_datacenter_list.yml"
        )
        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f)
                self._datacenter_asns = {
                    int(k): v for k, v in data.get("asns", {}).items()
                }
                self.logger.info(
                    "asn_classifier | event=datacenter_list_loaded | count=%d",
                    len(self._datacenter_asns),
                )
        except FileNotFoundError:
            self.logger.error(
                "asn_classifier | event=datacenter_list_missing | path=%s", config_path
            )
        except yaml.YAMLError as e:
            self.logger.error(
                "asn_classifier | event=datacenter_list_parse_error | error=%s", str(e)
            )

    def _init_maxmind(self) -> None:
        """Initialize MaxMind GeoLite2-ASN database."""
        if not MAXMIND_AVAILABLE:
            self.logger.warning("asn_classifier | event=maxmind_not_available")
            return

        db_path = self._config.get("maxmind_db_path", "config/GeoLite2-ASN.mmdb")
        if not os.path.exists(db_path):
            self.logger.error(
                "asn_classifier | event=maxmind_db_missing | path=%s", db_path
            )
            return

        try:
            self._maxmind_reader = maxminddb.open_database(db_path)
            self.logger.info("asn_classifier | event=maxmind_loaded | path=%s", db_path)
        except Exception as e:
            self.logger.error(
                "asn_classifier | event=maxmind_load_failed | error=%s", str(e)
            )

    async def _init_tor_list(self) -> None:
        """Initialize Tor exit node list."""
        tor_config = self._config.get("tor_exit_list", {})
        if not tor_config.get("enabled", True):
            return

        refresh_interval = tor_config.get("refresh_interval_seconds", 3600)

        await self._refresh_tor_list()

        # Store the background task so it can be cancelled later
        self._tor_refresh_task = asyncio.create_task(self._tor_refresh_loop(refresh_interval))

    async def cleanup(self) -> None:
        """Cancel any background tasks."""
        if self._tor_refresh_task is not None:
            self._tor_refresh_task.cancel()
            try:
                await self._tor_refresh_task
            except asyncio.CancelledError:
                pass
            self._tor_refresh_task = None

    async def _tor_refresh_loop(self, interval: int) -> None:
        """Background task to refresh Tor exit list periodically."""
        while True:
            try:
                await asyncio.sleep(interval)
                await self._refresh_tor_list()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.warning(
                    "asn_classifier | event=tor_refresh_error | error=%s", str(e)
                )

    async def _refresh_tor_list(self) -> None:
        """Download and parse Tor exit node list."""
        tor_config = self._config.get("tor_exit_list", {})
        url = tor_config.get(
            "download_url", "https://check.torproject.org/tor-exit-consensus"
        )

        leader_key = "leader:tor_exit_download"
        lock_ttl = tor_config.get("refresh_interval_seconds", 3600)

        is_leader = False
        if self._redis_client:
            try:
                is_leader = await self._redis_client.set(
                    leader_key, self._instance_id, nx=True, ex=lock_ttl
                )
            except Exception as e:
                self.logger.warning(
                    "asn_classifier | event=leader_check_error | error=%s", str(e)
                )

        if not is_leader and self._redis_client:
            try:
                cached_ips = await self._redis_client.smembers("tor:exit:ips")
                if cached_ips:
                    self._tor_exit_ips = {
                        ip.decode() if isinstance(ip, bytes) else ip
                        for ip in cached_ips
                    }
                    self.logger.info(
                        "asn_classifier | event=tor_list_loaded_from_redis | count=%d",
                        len(self._tor_exit_ips),
                    )
                    return
            except Exception as e:
                self.logger.warning(
                    "asn_classifier | event=redis_tor_read_error | error=%s", str(e)
                )

        if not is_leader:
            self.logger.debug("asn_classifier | event=not_leader_skip_download")
            return

        try:
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")

                    content = await response.text()
                    exit_ips = self._parse_tor_consensus(content)
                    elapsed_ms = int((time.time() - start_time) * 1000)

                    self._tor_exit_ips = exit_ips

                    if self._redis_client:
                        try:
                            pipe = self._redis_client.pipeline()
                            pipe.delete("tor:exit:ips")
                            if exit_ips:
                                pipe.sadd("tor:exit:ips", *exit_ips)
                            pipe.expire("tor:exit:ips", 3900)
                            await pipe.execute()
                        except Exception as e:
                            self.logger.warning(
                                "asn_classifier | event=redis_tor_write_error | error=%s",
                                str(e),
                            )

                    self.logger.info(
                        "asn_classifier | event=tor_list_refreshed | entries=%d | elapsed_ms=%d",
                        len(exit_ips),
                        elapsed_ms,
                    )

        except Exception as e:
            self.logger.error(
                "asn_classifier | event=tor_list_download_failed | error=%s | entries_retained=%d",
                str(e),
                len(self._tor_exit_ips),
            )

    def _parse_tor_consensus(self, content: str) -> Set[str]:
        """Parse Tor exit consensus document."""
        exit_ips = set()

        for line in content.split("\n"):
            line = line.strip()
            if (
                not line
                or line.startswith("#")
                or line.startswith("network-status-version")
            ):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            if "Exit" in parts:
                for part in parts:
                    if part.count(".") >= 2 or part.count(":") >= 2:
                        ip = part.strip("[]")
                        try:
                            import ipaddress

                            ipaddress.ip_address(ip)
                            exit_ips.add(ip)
                        except ValueError:
                            continue

        return exit_ips

    def classify(self, ip: str) -> ASNClassification:
        """
        Classify an IP address by ASN type.
        Sub-millisecond, in-process only.
        """
        if not self._enabled:
            return ASNClassification(
                asn=0, asn_str="AS0", org_name="", category="unknown"
            )

        canonical_ip = self._normalize_ip(ip)

        if canonical_ip in self._tor_exit_ips:
            return ASNClassification(
                asn=0, asn_str="AS0", org_name="Tor Exit", category="tor"
            )

        asn_info = self._lookup_maxmind(ip)
        if asn_info:
            asn = asn_info.get("asn", 0)
            asn_str = asn_info.get("asn_str", f"AS{asn}")
            org_name = asn_info.get("org_name", "")

            category = self._classify_asn(asn, org_name)
            return ASNClassification(
                asn=asn, asn_str=asn_str, org_name=org_name, category=category
            )

        return ASNClassification(asn=0, asn_str="AS0", org_name="", category="unknown")

        return ASNClassification(asn=0, asn_str="AS0", org_name="", category="unknown")

    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address to canonical form."""
        try:
            import ipaddress

            return ipaddress.ip_address(ip).compressed
        except ValueError:
            return ip

    def _lookup_maxmind(self, ip: str) -> Optional[dict]:
        """Look up IP in MaxMind database."""
        if not self._maxmind_reader:
            return None

        try:
            result = self._maxmind_reader.get(ip)
            if result:
                asn = result.get("autonomous_system_number", 0)
                org = result.get("autonomous_system_organization", "")
                return {"asn": asn, "asn_str": f"AS{asn}", "org_name": org}
        except (AttributeError, KeyError, TypeError):
            pass

        return None

    def _classify_asn(self, asn: int, org_name: str) -> str:
        """Classify ASN based on datacenter list and patterns."""
        if asn in self._datacenter_asns:
            return "datacenter"

        org_lower = org_name.lower()
        for pattern in VPN_PATTERNS:
            if pattern in org_lower:
                return "vpn"

        for pattern in RESIDENTIAL_PATTERNS:
            if pattern in org_lower:
                return "residential"

        if org_lower and any(
            kw in org_lower for kw in ["mobile", "cellular", "wireless"]
        ):
            return "mobile"

        return "unknown"

    def get_signal(self, ip: str) -> Optional[RiskSignal]:
        """Get risk signal for IP classification."""
        classification = self.classify(ip)

        if classification.category in ("unknown", "residential", "mobile"):
            return None

        score = self._risk_scores.get(classification.category, 5)
        reason = f"{classification.asn_str} ({classification.org_name}): {classification.category}"

        return RiskSignal(
            name=f"asn_{classification.category}", score=score, reason=reason
        )

    async def signals(self, ctx) -> list[RiskSignal]:
        """Async method to get risk signals for a connection context."""
        # Lazy initialization of Tor list if not already initialized
        if not self._tor_list_initialized:
            await self._init_tor_list()
            self._tor_list_initialized = True

        signal = self.get_signal(ctx.client_ip)
        return [signal] if signal else []
