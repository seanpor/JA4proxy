"""DNS Enrichment - Phase 7

FCrDNS (Forward-Confirmed Reverse DNS) enrichment for IP reputation.
Uses async DNS lookups to classify IPs by PTR record presence and validity.
"""

import asyncio
import json
import logging
import re
import socket
from dataclasses import dataclass
from typing import Optional

import aiodns

from src.security.models import RiskSignal

logger = logging.getLogger(__name__)


@dataclass
class FCrDNSResult:
    """Result of FCrDNS check."""
    ip: str
    has_ptr: bool
    hostname: Optional[str] = None
    confirmed: bool = False
    classification: str = "unknown"


RESIDENTIAL_PATTERNS = [
    r'\.dsl\.', r'\.cable\.', r'\.broadband\.', r'\.home\.',
    r'\.residential\.', r'-\d+\.dynamic\.', r'\.adsl\.',
    r'\.pppoe\.', r'cpc\d+', r'bchsia\.',         # Canadian ISPs
    r'\.eircom\.net', r'\.bskyb\.com',              # Irish/UK ISPs
]

DATACENTER_PATTERNS = [
    r'\.amazonaws\.com$', r'\.compute\.internal$',
    r'\.googleusercontent\.com$', r'\.digitalocean\.com$',
    r'ec2-', r'ip-\d+-\d+-\d+-\d+\.',
]


class DNSEnrichment:
    """DNS enrichment service with FCrDNS checks."""

    def __init__(self, config: dict, redis_client=None):
        self._config = config.get("dns_enrichment", {})
        self._enabled = self._config.get("enabled", True)
        self._redis_client = redis_client
        self._queue = asyncio.Queue(maxsize=self._config.get("queue_size", 1000))
        self._workers = []
        self._resolver = None
        self._bloom_filter_key = "bloom:dns_enriched"
        
        self._fcrdns_config = self._config.get("fcrdns", {})
        self._cache_ttl = self._fcrdns_config.get("cache_ttl_seconds", 21600)
        self._no_ptr_score = self._fcrdns_config.get("no_ptr_score", 15)
        self._fcrdns_failed_score = self._fcrdns_config.get("fcrdns_failed_score", 20)
        self._residential_reduction = self._fcrdns_config.get("residential_score_reduction", 10)
        
        self._init_resolver()
        self._start_workers()

    def _init_resolver(self):
        """Initialize aiodns resolver."""
        try:
            self._resolver = aiodns.DNSResolver(
                timeout=self._config.get("resolver_timeout_seconds", 5)
            )
            nameservers = self._config.get("resolver_nameservers", [])
            if nameservers:
                self._resolver.nameservers = nameservers
        except Exception as e:
            logger.error(f"dns_enrichment | event=resolver_init_failed | error={e}")
            self._enabled = False

    def _start_workers(self):
        """Start worker tasks."""
        worker_count = self._config.get("worker_count", 5)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No event loop - defer worker startup
            return
        
        for i in range(worker_count):
            task = asyncio.create_task(self._worker())
            self._workers.append(task)
            logger.info(f"dns_enrichment | event=worker_started | worker={i}")

    async def _worker(self):
        """Worker that processes DNS enrichment requests."""
        while True:
            try:
                ip = await self._queue.get()
                await self._process_ip(ip)
            except Exception as e:
                logger.error(f"dns_enrichment | event=worker_error | error={e}")
            finally:
                self._queue.task_done()

    async def _process_ip(self, ip: str):
        """Process a single IP through FCrDNS check."""
        # Check cache first
        cached = await self._get_cached_result(ip)
        if cached:
            await self._emit_signal_from_cache(ip, cached)
            return
        
        # Perform FCrDNS check
        result = await self._fcrdns_check(ip)
        
        # Cache the result
        await self._cache_result(ip, result)
        
        # Emit signal
        await self._emit_signal(ip, result)

    async def _fcrdns_check(self, ip: str) -> FCrDNSResult:
        """Perform FCrDNS check on an IP address."""
        if not self._resolver:
            return FCrDNSResult(ip=ip, has_ptr=False, classification="resolver_unavailable")
        
        # Step 1: PTR lookup
        try:
            ptr_result = await self._resolver.gethostbyaddr(ip)
            hostname = ptr_result.name
        except (aiodns.error.DNSError, asyncio.TimeoutError) as e:
            logger.debug(f"dns_enrichment | event=ptr_lookup_failed | ip={ip} | error={e}")
            return FCrDNSResult(ip=ip, has_ptr=False, classification="no_ptr")
        
        # Step 2: Forward lookup
        try:
            addr_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            forward_result = await self._resolver.gethostbyname(hostname, addr_family)
            forward_ips = forward_result.addresses if hasattr(forward_result, 'addresses') else [forward_result.host]
        except (aiodns.error.DNSError, asyncio.TimeoutError) as e:
            logger.debug(f"dns_enrichment | event=forward_lookup_failed | ip={ip} | hostname={hostname} | error={e}")
            return FCrDNSResult(
                ip=ip, 
                has_ptr=True, 
                hostname=hostname,
                confirmed=False,
                classification="fcrdns_failed"
            )
        
        # Step 3: Confirm
        canonical_ip = str(ip)
        confirmed = canonical_ip in [str(a) for a in forward_ips]
        
        classification = self._classify_hostname(hostname, confirmed)
        
        return FCrDNSResult(
            ip=ip,
            has_ptr=True,
            hostname=hostname,
            confirmed=confirmed,
            classification=classification
        )

    def _classify_hostname(self, hostname: str, confirmed: bool) -> str:
        """Classify hostname based on patterns."""
        if not confirmed:
            return "fcrdns_failed"
        
        hostname_lower = hostname.lower()
        
        # Check residential patterns
        for pattern in RESIDENTIAL_PATTERNS:
            if re.search(pattern, hostname_lower):
                return "residential"
        
        # Check datacenter patterns
        for pattern in DATACENTER_PATTERNS:
            if re.search(pattern, hostname_lower):
                return "datacenter_confirmed"
        
        return "confirmed"

    async def _get_cached_result(self, ip: str) -> Optional[dict]:
        """Get cached DNS result from Redis."""
        if not self._redis_client:
            return None
        
        try:
            cached = await self._redis_client.get(f"dns:ptr:{ip}")
            if cached:
                return json.loads(cached)
        except Exception:
            pass
        
        return None

    async def _cache_result(self, ip: str, result: FCrDNSResult):
        """Cache DNS result in Redis."""
        if not self._redis_client:
            return
        
        try:
            cache_data = {
                "ptr": result.hostname,
                "confirmed": result.confirmed,
                "classification": result.classification,
                "fetched_at": int(asyncio.get_event_loop().time())
            }
            await self._redis_client.setex(
                f"dns:ptr:{ip}",
                self._cache_ttl,
                json.dumps(cache_data)
            )
        except Exception as e:
            logger.warning(f"dns_enrichment | event=cache_write_failed | ip={ip} | error={e}")

    async def _emit_signal(self, ip: str, result: FCrDNSResult):
        """Emit risk signal based on FCrDNS result."""
        # This would be called from the pipeline in actual implementation
        # For now, we'll just log the result
        logger.info(f"dns_enrichment | event=fcrdns_result | ip={ip} | classification={result.classification}")

    async def _emit_signal_from_cache(self, ip: str, cached: dict):
        """Emit signal from cached result."""
        # Similar to _emit_signal but from cache
        logger.info(f"dns_enrichment | event=cache_hit | ip={ip} | classification={cached['classification']}")

    async def enqueue(self, ip: str, alpn: Optional[str] = None) -> None:
        """Enqueue IP for DNS enrichment."""
        if not self._enabled:
            return
        
        # Don't enqueue h2/h1 ALPN IPs
        if alpn in ["h2", "h1"]:
            logger.debug(f"dns_enrichment | event=skip_alpn | ip={ip} | alpn={alpn}")
            return
        
        # Check Bloom filter
        try:
            if self._redis_client:
                exists = await self._redis_client.bf().exists(self._bloom_filter_key, ip)
                if exists:
                    logger.debug(f"dns_enrichment | event=bloom_hit | ip={ip}")
                    return
                await self._redis_client.bf().add(self._bloom_filter_key, ip)
        except Exception:
            # If Bloom filter fails, continue anyway
            pass
        
        # Enqueue
        try:
            await self._queue.put(ip)
            logger.debug(f"dns_enrichment | event=enqueued | ip={ip} | queue_size={self._queue.qsize()}")
        except asyncio.QueueFull:
            logger.warning(f"dns_enrichment | event=queue_full | dropped_ip={ip}")

    async def get_signal(self, ip: str) -> Optional[RiskSignal]:
        """Get risk signal for IP (checks cache first)."""
        # Check cache
        cached = await self._get_cached_result(ip)
        if cached:
            return self._signal_from_cache(cached)
        
        # If not in cache and not already queued, enqueue for future
        await self.enqueue(ip)
        return None

    def _signal_from_cache(self, cached: dict) -> Optional[RiskSignal]:
        """Create signal from cached data."""
        classification = cached.get("classification", "unknown")
        
        if classification == "no_ptr":
            return RiskSignal(
                name="no_ptr",
                score=self._no_ptr_score,
                reason=f"No PTR record"
            )
        elif classification == "fcrdns_failed":
            return RiskSignal(
                name="fcrdns_failed",
                score=self._fcrdns_failed_score,
                reason=f"FCrDNS failed for {cached.get('ptr', 'unknown')}"
            )
        elif classification == "residential":
            return RiskSignal(
                name="residential_ptr",
                score=-self._residential_reduction,
                reason=f"Residential PTR: {cached.get('ptr', 'unknown')}"
            )
        elif classification == "datacenter_confirmed":
            return RiskSignal(
                name="datacenter_ptr",
                score=0,  # Already scored by ASN
                reason=f"Datacenter PTR: {cached.get('ptr', 'unknown')}"
            )
        elif classification == "confirmed":
            return RiskSignal(
                name="ptr_confirmed",
                score=0,
                reason=f"PTR confirmed: {cached.get('ptr', 'unknown')}"
            )
        
        return None

    async def close(self):
        """Clean up resources."""
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
