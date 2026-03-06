"""
DNS Enrichment - Phase 7

Enrich IP reputation using DNS-derived signals, entirely off the hot path.
The core technique — Forward-Confirmed Reverse DNS — classifies IPs by whether
they have a PTR record, and whether that PTR forward-resolves back.
"""

import asyncio
import ipaddress
import json
import logging
import re
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import yaml
from redis import Redis

from src.security.models import RiskSignal

try:
    import aiodns

    AIODNS_AVAILABLE = True
except ImportError:
    AIODNS_AVAILABLE = False


@dataclass
class FCrDNSResult:
    """Result of FCrDNS check for an IP address."""

    ip: str
    has_ptr: bool
    confirmed: bool
    classification: (
        str  # no_ptr | fcrdns_failed | residential | datacenter_confirmed | confirmed
    )
    hostname: Optional[str] = None
    risk_score: int = 0


RESIDENTIAL_PTR_PATTERNS = [
    re.compile(r"\.dsl\.", re.I),
    re.compile(r"\.cable\.", re.I),
    re.compile(r"\.broadband\.", re.I),
    re.compile(r"\.home\.", re.I),
    re.compile(r"\.residential\.", re.I),
    re.compile(r"-\d+\.dynamic\.", re.I),
    re.compile(r"\.adsl\.", re.I),
    re.compile(r"\.pppoe\.", re.I),
    re.compile(r"cpc\d+\.", re.I),
    re.compile(r"bchsia\.", re.I),
    re.compile(r"\.eircom\.net", re.I),
    re.compile(r"\.bskyb\.com", re.I),
]

DATACENTER_PTR_PATTERNS = [
    re.compile(r"\.amazonaws\.com$", re.I),
    re.compile(r"\.compute\.internal$", re.I),
    re.compile(r"\.googleusercontent\.com$", re.I),
    re.compile(r"\.digitalocean\.com$", re.I),
    re.compile(r"ec2-", re.I),
    re.compile(r"ip-\d+-\d+-\d+-\d+\.", re.I),
]


RISK_SCORES = {
    "no_ptr": 15,
    "fcrdns_failed": 20,
    "ptr_ip_literal": 20,
    "residential": -10,
    "datacenter_confirmed": 0,
    "confirmed": 0,
}


class DNSEnrichment:
    """DNS Enrichment for IP reputation using FCrDNS."""

    def __init__(self, config: dict, redis_client: Optional[Redis] = None):
        self._config = config.get("dns_enrichment", {})
        self._enabled = self._config.get("enabled", True)
        self._redis_client = redis_client
        self.logger = logging.getLogger(__name__)

        self._queue_size = self._config.get("queue_size", 1000)
        self._worker_count = self._config.get("worker_count", 5)
        self._min_enqueue_score = self._config.get("min_enqueue_score", 10)
        self._resolver_timeout = self._config.get("resolver_timeout_seconds", 5)

        fcrdns_config = self._config.get("fcrdns", {})
        self._cache_ttl = fcrdns_config.get("cache_ttl_seconds", 21600)
        self._fcrdns_score = fcrdns_config.get("score", 15)
        self._residential_reduction = fcrdns_config.get(
            "residential_score_reduction", 10
        )

        self._resolver: Optional[Any] = None
        self._queue: Optional[asyncio.Queue] = None
        self._workers: List[asyncio.Task] = []
        self._bloom_key = "bloom:dns_enriched"

        self._metrics: Dict[str, int] = {
            "hit": 0,
            "miss": 0,
            "error": 0,
            "timeout": 0,
            "queue_drops": 0,
        }

        if self._enabled:
            self._init_resolver()

    def _init_resolver(self) -> None:
        """Initialize async DNS resolver."""
        if not AIODNS_AVAILABLE:
            self.logger.error(
                "dns_enrichment | event=aiodns_not_available | error=install aiodns"
            )
            return

        nameservers = self._config.get("resolver_nameservers", [])
        try:
            if nameservers:
                self._resolver = aiodns.DNSResolver(
                    nameservers=nameservers, timeout=self._resolver_timeout
                )
            else:
                self._resolver = aiodns.DNSResolver(timeout=self._resolver_timeout)
            self.logger.info("dns_enrichment | event=resolver_initialized")
        except Exception as e:
            self.logger.error(
                "dns_enrichment | event=resolver_init_failed | error=%s", str(e)
            )

    async def fcrdns_check(self, ip: str) -> FCrDNSResult:
        """
        Perform FCrDNS check: PTR lookup + forward confirmation.
        Returns FCrDNSResult with classification and risk score.
        """
        if not self._enabled or not self._resolver:
            return FCrDNSResult(
                ip=ip,
                has_ptr=False,
                confirmed=False,
                classification="disabled",
                risk_score=0,
            )

        canonical_ip = str(ipaddress.ip_address(ip).compressed)

        hostname = await self._ptr_lookup(canonical_ip)
        if not hostname:
            return FCrDNSResult(
                ip=ip,
                has_ptr=False,
                confirmed=False,
                classification="no_ptr",
                risk_score=RISK_SCORES["no_ptr"],
            )

        confirmed = await self._confirm_fcrdns(hostname, canonical_ip)
        classification = self._classify_hostname(hostname, confirmed)

        risk_score = 0
        if classification == "no_ptr":
            risk_score = RISK_SCORES["no_ptr"]
        elif classification == "fcrdns_failed":
            risk_score = RISK_SCORES["fcrdns_failed"]
        elif classification == "residential":
            risk_score = -RISK_SCORES["residential"]
        elif classification == "ptr_ip_literal":
            risk_score = RISK_SCORES["ptr_ip_literal"]

        return FCrDNSResult(
            ip=ip,
            has_ptr=True,
            confirmed=confirmed,
            classification=classification,
            hostname=hostname,
            risk_score=risk_score,
        )

    async def _ptr_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            result = await asyncio.wait_for(
                self._resolver.gethostbyaddr(ip), timeout=self._resolver_timeout
            )
            return result.name
        except asyncio.TimeoutError:
            self._metrics["timeout"] += 1
            self.logger.warning("dns_enrichment | event=ptr_timeout | ip=%s", ip)
            return None
        except Exception as e:
            self._metrics["error"] += 1
            self.logger.debug(
                "dns_enrichment | event=ptr_error | ip=%s | error=%s", ip, str(e)
            )
            return None

    async def _confirm_fcrdns(self, hostname: str, original_ip: str) -> bool:
        """Confirm that hostname resolves back to original IP."""
        try:
            addr_family = socket.AF_INET6 if ":" in original_ip else socket.AF_INET
            result = await asyncio.wait_for(
                self._resolver.gethostbyname(hostname, addr_family),
                timeout=self._resolver_timeout,
            )
            forward_ips = {
                str(ipaddress.ip_address(a).compressed) for a in result.addresses
            }
            return original_ip in forward_ips
        except asyncio.TimeoutError:
            self._metrics["timeout"] += 1
            return False
        except Exception as e:
            self._metrics["error"] += 1
            self.logger.debug(
                "dns_enrichment | event=fcrdns_error | hostname=%s | error=%s",
                hostname,
                str(e),
            )
            return False

    def _classify_hostname(self, hostname: str, confirmed: bool) -> str:
        """Classify hostname based on PTR patterns."""
        hostname_lower = hostname.lower()

        if not confirmed:
            return "fcrdns_failed"

        if hostname_lower == hostname_lower.split(".")[0]:
            return "ptr_ip_literal"

        for pattern in RESIDENTIAL_PTR_PATTERNS:
            if pattern.search(hostname_lower):
                return "residential"

        for pattern in DATACENTER_PTR_PATTERNS:
            if pattern.search(hostname_lower):
                return "datacenter_confirmed"

        return "confirmed"

    def get_signal(self, ip: str) -> Optional[RiskSignal]:
        """Get risk signal from Redis cache."""
        if not self._enabled or not self._redis_client:
            return None

        cache_key = f"dns:ptr:{ip}"
        try:
            cached = self._redis_client.get(cache_key)
            if cached:
                self._metrics["hit"] += 1
                data = json.loads(cached)
                risk_score = data.get("risk_score", 0)
                if risk_score != 0:
                    return RiskSignal(
                        name=f"dns_{data.get('classification', 'unknown')}",
                        score=risk_score,
                        reason=f"PTR: {data.get('hostname', 'N/A')}",
                    )
                return None

            self._metrics["miss"] += 1
        except Exception as e:
            self.logger.warning(
                "dns_enrichment | event=cache_read_error | error=%s", str(e)
            )

        return None

    async def enqueue(self, ip: str, alpn: Optional[str] = None) -> bool:
        """
        Enqueue IP for async DNS enrichment.
        Returns True if enqueued, False if skipped (already enriched, h2/h1 bypass, queue full).
        """
        if not self._enabled:
            return False

        if alpn in ("h2", "h1"):
            self.logger.debug(
                "dns_enrichment | event=skip_alpn_bypass | ip=%s | alpn=%s", ip, alpn
            )
            return False

        if not self._redis_client:
            return False

        try:
            already_enriched = self._redis_client.bf().exists(self._bloom_key, ip)
            if already_enriched:
                return False

            if not self._queue:
                return False

            if self._queue.full():
                self._metrics["queue_drops"] += 1
                self.logger.warning(
                    "dns_enrichment | event=queue_full | dropped_ip=%s", ip
                )
                return False

            await self._queue.put(ip)
            self._redis_client.bf().add(self._bloom_key, ip)
            return True
        except Exception as e:
            self.logger.warning(
                "dns_enrichment | event=enqueue_error | error=%s", str(e)
            )
            return False

    async def start_workers(self) -> None:
        """Start background workers for async enrichment."""
        if not self._enabled or not self._resolver:
            return

        self._queue = asyncio.Queue(maxsize=self._queue_size)

        for i in range(self._worker_count):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)

        self.logger.info(
            "dns_enrichment | event=workers_started | count=%d", self._worker_count
        )

    async def _worker(self, worker_id: int) -> None:
        """Background worker that processes DNS enrichment queue."""
        self.logger.info(
            "dns_enrichment | event=worker_started | worker_id=%d", worker_id
        )

        while True:
            try:
                ip = await self._queue.get()

                result = await self.fcrdns_check(ip)

                await self._write_to_redis(ip, result)

                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(
                    "dns_enrichment | event=worker_error | worker_id=%d | error=%s",
                    worker_id,
                    str(e),
                )

    async def _write_to_redis(self, ip: str, result: FCrDNSResult) -> None:
        """Write enrichment result to Redis cache."""
        if not self._redis_client:
            return

        cache_key = f"dns:ptr:{ip}"
        try:
            data = {
                "hostname": result.hostname,
                "confirmed": result.confirmed,
                "classification": result.classification,
                "risk_score": result.risk_score,
                "fetched_at": int(time.time()),
            }
            self._redis_client.setex(cache_key, self._cache_ttl, json.dumps(data))
        except Exception as e:
            self.logger.warning(
                "dns_enrichment | event=cache_write_error | error=%s", str(e)
            )

    async def stop_workers(self) -> None:
        """Stop background workers."""
        for task in self._workers:
            task.cancel()

        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        self.logger.info("dns_enrichment | event=workers_stopped")

    def get_metrics(self) -> dict:
        """Get enrichment metrics."""
        return {
            **self._metrics,
            "queue_depth": self._queue.qsize() if self._queue else 0,
        }


class PassiveDNS:
    """Passive DNS enrichment module (optional, off by default)."""

    def __init__(self, config: dict, redis_client: Optional[Redis] = None):
        self._config = config.get("dns_enrichment", {}).get("passive_dns", {})
        self._enabled = self._config.get("enabled", False)
        self._redis_client = redis_client
        self.logger = logging.getLogger(__name__)

        if not self._enabled:
            self.logger.info("dns_enrichment | event=passive_dns_disabled")
            return

        self._api_key = self._config.get("api_key", "")
        self._feed = self._config.get("feed", "")
        self._cache_ttl = self._config.get("cache_ttl_seconds", 3600)
        self._score = self._config.get("score", 20)
        self._new_domain_days = self._config.get("new_domain_days", 7)

    def is_enabled(self) -> bool:
        """Check if passive DNS is enabled."""
        return self._enabled

    async def check_ip(self, ip: str) -> Optional[RiskSignal]:
        """Check IP against passive DNS data."""
        if not self._enabled:
            return None

        self.logger.debug("dns_enrichment | event=passive_dns_check | ip=%s", ip)

        return None
