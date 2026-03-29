"""DNS Enrichment - Phase 7

FCrDNS (Forward-Confirmed Reverse DNS) enrichment for IP reputation.
Uses async DNS lookups to classify IPs by PTR record presence and validity.

All DNS lookups are non-blocking (aiodns). The hot path never awaits DNS
results — it checks a Redis cache and returns immediately (fail open on miss),
while background workers perform the actual lookups.
"""

import asyncio
import json
import logging
import re
import socket
from dataclasses import dataclass
from typing import Optional

import redis as redis_lib
from prometheus_client import Counter, Gauge

try:
    import aiodns

    AIODNS_AVAILABLE = True
except ImportError:
    AIODNS_AVAILABLE = False
    aiodns = None  # type: ignore

from src.security.models import RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_DNS_TOTAL = Counter(
    "ja4proxy_dns_enrichment_total",
    "DNS enrichment outcomes",
    ["result"],  # hit, miss, error, timeout
)
_DNS_PTR_CLASS = Counter(
    "ja4proxy_dns_ptr_classification_total",
    "PTR outcomes by classification",
    ["ptr_class"],
)
_DNS_QUEUE_DEPTH = Gauge(
    "ja4proxy_dns_enrichment_queue_depth",
    "Current DNS enrichment queue depth",
)
_DNS_QUEUE_DROPS = Counter(
    "ja4proxy_dns_enrichment_queue_drops_total",
    "Items dropped from full DNS enrichment queue",
)
_DNS_RESOLVER_ERRORS = Counter(
    "ja4proxy_dns_resolver_errors_total",
    "DNS resolver errors",
)

_DNS_PTR_ERRORS = Counter(
    "ja4proxy_dns_ptr_errors_total",
    "DNS PTR lookup failures by error type",
    ["error_type"],  # timeout | nxdomain | servfail | other
)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

RESIDENTIAL_PATTERNS = [
    r"\.dsl\.",
    r"\.cable\.",
    r"\.broadband\.",
    r"\.home\.",
    r"\.residential\.",
    r"-\d+\.dynamic\.",
    r"\.adsl\.",
    r"\.pppoe\.",
    r"cpc\d+",
    r"bchsia\.",
    r"\.eircom\.net",
    r"\.bskyb\.com",
]

DATACENTER_PATTERNS = [
    r"\.amazonaws\.com$",
    r"\.compute\.internal$",
    r"\.googleusercontent\.com$",
    r"\.digitalocean\.com$",
    r"ec2-",
    r"ip-\d+-\d+-\d+-\d+\.",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FCrDNSResult:
    """Result of FCrDNS check."""

    ip: str
    has_ptr: bool
    hostname: Optional[str] = None
    confirmed: bool = False
    classification: str = "unknown"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class DNSEnrichment:
    """DNS enrichment service with FCrDNS checks.

    The hot path calls ``get_signal(ip)`` which returns immediately from
    cache (or None on miss) and enqueues a background lookup. Workers
    write results back to Redis for future calls.
    """

    def __init__(self, config: dict, redis_client=None):
        self._config = config.get("dns_enrichment", {})
        self._enabled = self._config.get("enabled", True)
        self._redis_client = redis_client
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=self._config.get("queue_size", 1000)
        )
        self._workers: list[asyncio.Task] = []
        self._resolver = None
        self._bloom_filter_key = "bloom:dns_enriched"

        fcrdns_cfg = self._config.get("fcrdns", {})
        self._cache_ttl: int = fcrdns_cfg.get("cache_ttl_seconds", 21600)
        self._no_ptr_score: int = fcrdns_cfg.get("no_ptr_score", 15)
        self._fcrdns_failed_score: int = fcrdns_cfg.get("fcrdns_failed_score", 20)
        self._residential_reduction: int = fcrdns_cfg.get(
            "residential_score_reduction", 10
        )

        self._init_resolver()
        self._log_passive_dns_status()
        self._start_workers()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_resolver(self) -> None:
        """Initialise aiodns resolver. Disables enrichment if unavailable."""
        if not AIODNS_AVAILABLE:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "dns",
                        "event": "aiodns_unavailable",
                        "message": "aiodns not installed — DNS enrichment disabled",
                    }
                )
            )
            self._enabled = False
            return

        try:
            self._resolver = aiodns.DNSResolver(
                timeout=self._config.get("resolver_timeout_seconds", 5)
            )
            nameservers = self._config.get("resolver_nameservers", [])
            if nameservers:
                self._resolver.nameservers = nameservers
        except Exception as exc:
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "dns",
                        "event": "resolver_init_failed",
                        "error": str(exc),
                    }
                )
            )
            self._enabled = False

    def _log_passive_dns_status(self) -> None:
        """Log once at startup when passive DNS is disabled (spec requirement)."""
        passive_cfg = self._config.get("passive_dns", {})
        if not passive_cfg.get("enabled", False):
            logger.info(
                json.dumps(
                    {
                        "type": "system",
                        "level": "INFO",
                        "subsystem": "dns",
                        "event": "passive_dns_disabled",
                        "message": "Passive DNS disabled — no feed configured",
                    }
                )
            )

    def _start_workers(self) -> None:
        """Start background worker tasks if an event loop is running."""
        if not self._enabled:
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return  # No event loop — defer; workers started externally

        worker_count = self._config.get("worker_count", 5)
        for i in range(worker_count):
            task = asyncio.create_task(self._worker_with_restart(i))
            self._workers.append(task)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    async def _worker_with_restart(self, worker_id: int) -> None:
        """Outer restart loop — if the inner worker crashes it is restarted."""
        while True:
            try:
                await self._worker(worker_id)
            except asyncio.CancelledError:
                raise  # Propagate cancellation on shutdown
            except Exception as exc:
                logger.error(
                    json.dumps(
                        {
                            "type": "system",
                            "level": "ERROR",
                            "subsystem": "dns",
                            "event": "worker_crashed",
                            "worker": worker_id,
                            "error": str(exc),
                        }
                    )
                )
                await asyncio.sleep(1)  # Brief pause before restart

    async def _worker(self, worker_id: int) -> None:
        """Inner worker loop — processes IPs from the queue indefinitely."""
        logger.debug("dns_enrichment | event=worker_started | worker=%d", worker_id)
        while True:
            ip = await self._queue.get()
            try:
                await self._process_ip(ip)
            except Exception as exc:
                logger.error(
                    json.dumps(
                        {
                            "type": "system",
                            "level": "ERROR",
                            "subsystem": "dns",
                            "event": "worker_error",
                            "ip": ip,
                            "error": str(exc),
                        }
                    )
                )
            finally:
                self._queue.task_done()
                _DNS_QUEUE_DEPTH.set(self._queue.qsize())

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    async def _process_ip(self, ip: str) -> None:
        """Perform FCrDNS for one IP and write result to Redis cache."""
        cached = await self._get_cached_result(ip)
        if cached:
            _DNS_TOTAL.labels(result="hit").inc()
            return

        result = await self._fcrdns_check(ip)
        _DNS_PTR_CLASS.labels(ptr_class=result.classification).inc()
        await self._cache_result(ip, result)

    async def _fcrdns_check(self, ip: str) -> FCrDNSResult:
        """Perform the three-step FCrDNS check. Always returns (never raises)."""
        if not self._resolver:
            _DNS_TOTAL.labels(result="error").inc()
            return FCrDNSResult(
                ip=ip, has_ptr=False, classification="resolver_unavailable"
            )

        # Step 1: PTR lookup
        try:
            ptr_result = await self._resolver.gethostbyaddr(ip)
            hostname = ptr_result.name
        except asyncio.TimeoutError:
            _DNS_TOTAL.labels(result="timeout").inc()
            _DNS_RESOLVER_ERRORS.inc()
            _DNS_PTR_ERRORS.labels(error_type="timeout").inc()
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "dns",
                        "event": "resolver_error",
                        "ip": ip,
                        "error": "timeout on PTR lookup",
                    }
                )
            )
            return FCrDNSResult(ip=ip, has_ptr=False, classification="no_ptr")
        except Exception as exc:
            _DNS_TOTAL.labels(result="error").inc()
            _DNS_RESOLVER_ERRORS.inc()
            exc_name = type(exc).__name__
            error_type = (
                "nxdomain"
                if "nxdomain" in exc_name.lower()
                else "servfail" if "servfail" in exc_name.lower() else "other"
            )
            _DNS_PTR_ERRORS.labels(error_type=error_type).inc()
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "dns",
                        "event": "resolver_error",
                        "ip": ip,
                        "error": str(exc),
                    }
                )
            )
            return FCrDNSResult(ip=ip, has_ptr=False, classification="no_ptr")

        # Step 2: Forward lookup (A/AAAA)
        try:
            addr_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            forward_result = await self._resolver.gethostbyname(hostname, addr_family)
            forward_ips = (
                forward_result.addresses
                if hasattr(forward_result, "addresses")
                else [forward_result.host]
            )
        except asyncio.TimeoutError:
            _DNS_TOTAL.labels(result="timeout").inc()
            _DNS_RESOLVER_ERRORS.inc()
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "dns",
                        "event": "resolver_error",
                        "ip": ip,
                        "error": "timeout on forward lookup",
                    }
                )
            )
            return FCrDNSResult(
                ip=ip,
                has_ptr=True,
                hostname=hostname,
                confirmed=False,
                classification="fcrdns_failed",
            )
        except Exception as exc:
            _DNS_TOTAL.labels(result="error").inc()
            _DNS_RESOLVER_ERRORS.inc()
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "dns",
                        "event": "resolver_error",
                        "ip": ip,
                        "error": str(exc),
                    }
                )
            )
            return FCrDNSResult(
                ip=ip,
                has_ptr=True,
                hostname=hostname,
                confirmed=False,
                classification="fcrdns_failed",
            )

        # Step 3: Confirm
        confirmed = str(ip) in [str(a) for a in forward_ips]
        classification = self._classify_hostname(hostname, confirmed)
        _DNS_TOTAL.labels(result="miss").inc()
        return FCrDNSResult(
            ip=ip,
            has_ptr=True,
            hostname=hostname,
            confirmed=confirmed,
            classification=classification,
        )

    def _classify_hostname(self, hostname: str, confirmed: bool) -> str:
        """Classify PTR hostname. Returns classification string."""
        if not confirmed:
            return "fcrdns_failed"
        hostname_lower = hostname.lower()
        for pattern in RESIDENTIAL_PATTERNS:
            if re.search(pattern, hostname_lower):
                return "residential"
        for pattern in DATACENTER_PATTERNS:
            if re.search(pattern, hostname_lower):
                return "datacenter_confirmed"
        return "confirmed"

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    async def _get_cached_result(self, ip: str) -> Optional[dict]:
        """Return cached DNS result from Redis, or None on miss/error."""
        if not self._redis_client:
            return None
        try:
            raw = await self._redis_client.get(f"dns:ptr:{ip}")
            if raw:
                return json.loads(raw)
        except (redis_lib.RedisError, json.JSONDecodeError, ValueError):
            pass  # cache unavailable or malformed — fall through to DNS lookup
        return None

    async def _cache_result(self, ip: str, result: FCrDNSResult) -> None:
        """Write FCrDNS result to Redis with TTL."""
        if not self._redis_client:
            return
        try:
            loop = asyncio.get_running_loop()
            data = {
                "ptr": result.hostname,
                "confirmed": result.confirmed,
                "classification": result.classification,
                "fetched_at": int(loop.time()),
            }
            await self._redis_client.setex(
                f"dns:ptr:{ip}", self._cache_ttl, json.dumps(data)
            )
        except Exception as exc:
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "dns",
                        "event": "cache_write_failed",
                        "ip": ip,
                        "error": str(exc),
                    }
                )
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(self, ip: str, alpn: Optional[str] = None) -> None:
        """Enqueue IP for background DNS enrichment. Non-blocking."""
        if not self._enabled:
            return
        if alpn in ("h2", "h1"):
            return

        # Bloom filter dedup
        try:
            if self._redis_client:
                # Phase 30b: Explicit check for 1/True to handle truthy mocks
                exists = await self._redis_client.bf().exists(
                    self._bloom_filter_key, ip
                )
                if exists in (1, True):
                    return
                await self._redis_client.bf().add(self._bloom_filter_key, ip)
        except (redis_lib.RedisError, AttributeError, TypeError):
            pass  # Bloom filter unavailable or non-awaitable — not fatal, continue to enqueue

        try:
            self._queue.put_nowait(ip)
            _DNS_QUEUE_DEPTH.set(self._queue.qsize())
        except asyncio.QueueFull:
            _DNS_QUEUE_DROPS.inc()
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "dns",
                        "event": "queue_full",
                        "dropped_ip": ip,
                    }
                )
            )

    async def get_signal(self, ip: str) -> Optional[RiskSignal]:
        """Return cached RiskSignal for ip, or None (and enqueue) on miss.

        The hot path calls this method. It never blocks waiting for DNS.
        """
        cached = await self._get_cached_result(ip)
        if cached:
            return self._signal_from_cache(cached)
        # Cache miss — enqueue for background enrichment, fail open
        await self.enqueue(ip)
        return None

    def _signal_from_cache(self, cached: dict) -> Optional[RiskSignal]:
        """Derive a RiskSignal from a cached DNS result dict."""
        classification = cached.get("classification", "unknown")
        ptr = cached.get("ptr", "unknown")

        if classification == "no_ptr":
            return RiskSignal(
                name="no_ptr", score=self._no_ptr_score, reason="No PTR record"
            )
        if classification == "fcrdns_failed":
            return RiskSignal(
                name="fcrdns_failed",
                score=self._fcrdns_failed_score,
                reason=f"FCrDNS failed for {ptr}",
            )
        if classification == "residential":
            return RiskSignal(
                name="residential_ptr",
                score=-self._residential_reduction,
                reason=f"Residential PTR: {ptr}",
            )
        if classification == "datacenter_confirmed":
            return RiskSignal(
                name="datacenter_ptr", score=0, reason=f"Datacenter PTR: {ptr}"
            )
        if classification == "confirmed":
            return RiskSignal(
                name="ptr_confirmed", score=0, reason=f"PTR confirmed: {ptr}"
            )
        return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Cancel worker tasks on shutdown."""
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
