"""Phase 11 — RDAP Enrichment & Block Expansion.

Provides netblock/org reputation scoring from RDAP (Registration Data Access
Protocol — the modern successor to WHOIS). Enrichment is entirely offline —
the hot path never awaits RDAP results.

Architecture
------------
Hot path:  get_signal(ip, trigger_score)
             ↓ in-process LRU hit      → return cached signals immediately
             ↓ LRU miss + score ≥ min  → enqueue; return [] (fail open)

Background: worker pool drains asyncio.Queue
              ↓ Bloom filter dedup
              ↓ IANA bootstrap → correct RIR URL
              ↓ RDAP API call (aiohttp, rate-limited)
              ↓ parse org/netblock/date
              ↓ write to Redis + LocalCache.rdap_results
              ↓ maybe_expand_block() (4 guards + hourly cap)

Block expansion propagation
---------------------------
When all 4 guards pass:
  1. Write ban_cidr:{cidr} to Redis with TTL
  2. Call BlocklistManager.load_cidrs([cidr], "rdap_expansion")
  3. Publish {"type":"cidr_ban_add","value":cidr} to ja4proxy:invalidate
All other proxy instances receive the pub/sub message and update their tries.
"""

import asyncio
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import yaml
from prometheus_client import Counter, Gauge

from .models import RiskSignal

try:
    import aiohttp  # type: ignore
    AIOHTTP_AVAILABLE = True
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore
    AIOHTTP_AVAILABLE = False

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache
    from .blocklists import BlocklistManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_LOOKUP_TOTAL = Counter(
    "ja4proxy_rdap_lookup_total",
    "RDAP lookup outcomes by registry and result",
    ["registry", "result"],
)

_QUEUE_DEPTH = Gauge(
    "ja4proxy_rdap_enrichment_queue_depth",
    "Current depth of the RDAP enrichment queue",
)

_BLOCK_EXPANSIONS = Counter(
    "ja4proxy_rdap_block_expansions_total",
    "Automatic CIDR block expansions applied by RDAP enrichment",
)

_PARSE_ERRORS = Counter(
    "ja4proxy_rdap_parse_errors_total",
    "RDAP response parse failures",
)

_QUEUE_DROPPED = Counter(
    "ja4proxy_rdap_queue_dropped_total",
    "RDAP enrichment queue items dropped because the queue was full",
)

_EXPANSIONS_THIS_HOUR = Gauge(
    "ja4proxy_rdap_expansions_this_hour",
    "Current hourly expansion count vs cap",
)

# IANA bootstrap URLs
BOOTSTRAP_URL_V4 = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP_URL_V6 = "https://data.iana.org/rdap/ipv6.json"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RDAPResult:
    """Parsed RDAP enrichment result for one IP address.

    Attributes:
        netblock:          CIDR of the owning netblock, e.g. "185.220.0.0/15".
        org_name:          Organization name from vCard, e.g. "Frantech Solutions".
        org_handle:        Registry org handle, e.g. "FRANK-1".
        asn:               Autonomous system number, e.g. "AS53667", or None.
        country:           ISO 3166-1 alpha-2 country code, or None.
        registration_date: ISO date of netblock registration, or None.
        fetched_at:        Unix timestamp when the result was fetched.
        is_unknown:        True when RDAP returned 404 (IP not in any RIR database).
    """

    netblock: str
    org_name: str
    org_handle: str
    asn: str | None
    country: str | None
    registration_date: str | None
    fetched_at: float
    is_unknown: bool = False


@dataclass
class _BlockExpansionConfig:
    enabled: bool = False
    min_trigger_score: int = 75
    max_prefix_length_v4: int = 24
    max_prefix_length_v6: int = 48
    require_no_browser_traffic: bool = True
    require_known_bad_org: bool = True
    expansion_ban_duration: int = 3600
    max_expansions_per_hour: int = 10


@dataclass
class _OrgReputationConfig:
    enabled: bool = True
    score: int = 45


@dataclass
class _NewNetblockConfig:
    enabled: bool = True
    max_age_days: int = 90
    score: int = 20


@dataclass
class RDAPConfig:
    """Configuration for RDAPEnricher.

    All fields except worker_count and queue_size are hot-reloadable.
    Changing worker_count or queue_size requires a proxy restart.

    Attributes:
        enabled:               Master switch.
        queue_size:            Max pending IPs in the enrichment queue.
        worker_count:          Number of background worker coroutines.
        min_enqueue_score:     Only enqueue when trigger score ≥ this value.
        lookup_timeout_seconds: aiohttp request timeout per RDAP call.
        delegate_to_analytics: When true, publish IPs to Redis Set instead of calling API.
        org_reputation:        Config for known-bad org signal.
        new_netblock_flagging: Config for new netblock age signal.
        block_expansion:       Config for automatic CIDR block expansion.
    """

    enabled: bool = True
    queue_size: int = 500
    worker_count: int = 3
    min_enqueue_score: int = 20
    lookup_timeout_seconds: int = 15
    delegate_to_analytics: bool = False
    org_reputation: _OrgReputationConfig = field(default_factory=_OrgReputationConfig)
    new_netblock_flagging: _NewNetblockConfig = field(default_factory=_NewNetblockConfig)
    block_expansion: _BlockExpansionConfig = field(default_factory=_BlockExpansionConfig)

    @classmethod
    def from_config(cls, config: dict) -> "RDAPConfig":
        """Build RDAPConfig from the full proxy.yml config dict.

        Reads the ``rdap_enrichment`` section. Falls back to defaults for missing keys.
        """
        cfg = config.get("rdap_enrichment", {})
        or_cfg = cfg.get("org_reputation", {})
        nn_cfg = cfg.get("new_netblock_flagging", {})
        be_cfg = cfg.get("block_expansion", {})

        return cls(
            enabled=bool(cfg.get("enabled", True)),
            queue_size=int(cfg.get("queue_size", 500)),
            worker_count=int(cfg.get("worker_count", 3)),
            min_enqueue_score=int(cfg.get("min_enqueue_score", 20)),
            lookup_timeout_seconds=int(cfg.get("lookup_timeout_seconds", 15)),
            delegate_to_analytics=bool(cfg.get("delegate_to_analytics", False)),
            org_reputation=_OrgReputationConfig(
                enabled=bool(or_cfg.get("enabled", True)),
                score=int(or_cfg.get("score", 45)),
            ),
            new_netblock_flagging=_NewNetblockConfig(
                enabled=bool(nn_cfg.get("enabled", True)),
                max_age_days=int(nn_cfg.get("max_age_days", 90)),
                score=int(nn_cfg.get("score", 20)),
            ),
            block_expansion=_BlockExpansionConfig(
                enabled=bool(be_cfg.get("enabled", False)),
                min_trigger_score=int(be_cfg.get("min_trigger_score", 75)),
                max_prefix_length_v4=int(be_cfg.get("max_prefix_length_v4", 24)),
                max_prefix_length_v6=int(be_cfg.get("max_prefix_length_v6", 48)),
                require_no_browser_traffic=bool(be_cfg.get("require_no_browser_traffic", True)),
                require_known_bad_org=bool(be_cfg.get("require_known_bad_org", True)),
                expansion_ban_duration=int(be_cfg.get("expansion_ban_duration", 3600)),
                max_expansions_per_hour=int(be_cfg.get("max_expansions_per_hour", 10)),
            ),
        )


# ---------------------------------------------------------------------------
# Per-registry rate limiter
# ---------------------------------------------------------------------------


class RegistryRateLimiter:
    """In-process token bucket rate limiter per RDAP registry.

    Uses asyncio.Semaphore as a token pool. On acquire, one token is consumed
    and a task is scheduled to release it after the window expires.

    Registry limits (requests per window_seconds):
        ARIN:    60 / 60s
        RIPE:    60 / 60s
        APNIC:   30 / 60s
        LACNIC:  20 / 60s
        AFRINIC: 20 / 60s
        default: 10 / 60s
    """

    LIMITS: dict[str, tuple[int, int]] = {
        "rdap.arin.net": (60, 60),
        "rdap.ripe.net": (60, 60),
        "rdap.apnic.net": (30, 60),
        "rdap.lacnic.net": (20, 60),
        "rdap.afrinic.net": (20, 60),
    }

    def __init__(self) -> None:
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def _get_semaphore(self, host: str) -> tuple[asyncio.Semaphore, int, int]:
        limit, window = self.LIMITS.get(host, (10, 60))
        if host not in self._semaphores:
            self._semaphores[host] = asyncio.Semaphore(limit)
        return self._semaphores[host], limit, window

    async def acquire(self, registry_host: str) -> None:
        """Block until a rate-limit token is available for this registry."""
        sem, _limit, window = self._get_semaphore(registry_host)
        await sem.acquire()
        # Schedule token release after the window expires
        asyncio.create_task(self._release_after(sem, window))

    @staticmethod
    async def _release_after(sem: asyncio.Semaphore, delay: float) -> None:
        await asyncio.sleep(delay)
        sem.release()


# ---------------------------------------------------------------------------
# Signal helper functions (module-level, easily unit-tested)
# ---------------------------------------------------------------------------


def new_netblock_signal(
    registration_date: str | None,
    max_age_days: int,
    score: int,
) -> RiskSignal | None:
    """Return a RiskSignal if the netblock was registered within max_age_days.

    Args:
        registration_date: ISO date string (e.g. "2024-01-15") or None.
        max_age_days:       Flag netblocks younger than this many days.
        score:              Risk contribution to assign.

    Returns:
        RiskSignal or None (when date missing or age ≥ max_age_days).
    """
    if not registration_date:
        return None
    try:
        reg_dt = datetime.fromisoformat(registration_date)
        # Ensure timezone-aware for comparison
        if reg_dt.tzinfo is None:
            reg_dt = reg_dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - reg_dt).days
        if age < max_age_days:
            return RiskSignal(
                name="rdap_new_netblock",
                score=score,
                reason=f"Netblock registered {age} days ago (< {max_age_days} day threshold)",
            )
    except (ValueError, TypeError):
        return None
    return None


def _compute_expansion_cidr(ip: str, config: _BlockExpansionConfig) -> str:
    """Compute the expansion CIDR containing the trigger IP.

    Always expands to the configured prefix length (/24 IPv4, /48 IPv6),
    not necessarily the full RDAP netblock.

    Args:
        ip:     Trigger IP address string.
        config: Block expansion config containing prefix lengths.

    Returns:
        CIDR string, e.g. "185.220.101.0/24".
    """
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return str(ipaddress.ip_network(
            f"{ip}/{config.max_prefix_length_v4}", strict=False
        ))
    return str(ipaddress.ip_network(
        f"{ip}/{config.max_prefix_length_v6}", strict=False
    ))


# ---------------------------------------------------------------------------
# RDAPEnricher
# ---------------------------------------------------------------------------


class RDAPEnricher:
    """Async RDAP enrichment module.

    Maintains a background worker pool that enriches IPs with RDAP org/netblock
    data. get_signal() is the only hot-path entry point — it returns immediately
    from cache and never makes a network call.

    Args:
        config:           Parsed :class:`RDAPConfig` instance.
        redis:            Async Redis client (redis.asyncio.Redis).
        local_cache:      Process-local :class:`~src.cache.local_cache.LocalCache`.
        session:          Shared aiohttp.ClientSession (injected at startup; never created here).
        blocklist_manager: :class:`~src.security.blocklists.BlocklistManager` for CIDR expansion.
        instance_id:      Unique instance identifier for leader election.
        known_bad_orgs_path: Path to config/known_bad_orgs.yml.
    """

    def __init__(
        self,
        config: RDAPConfig,
        redis: object,
        local_cache: "LocalCache",
        session: object,
        blocklist_manager: "BlocklistManager | None" = None,
        instance_id: str = "default",
        known_bad_orgs_path: str = "config/known_bad_orgs.yml",
    ) -> None:
        self._config = config
        self._redis = redis
        self._local_cache = local_cache
        self._session = session
        self._blocklist_manager = blocklist_manager
        self._instance_id = instance_id
        self._known_bad_orgs_path = known_bad_orgs_path
        self._queue: asyncio.Queue | None = None
        self._workers: list[asyncio.Task] = []
        self._bootstrap_v4: list[dict] = []   # list of {prefix, urls}
        self._bootstrap_v6: list[dict] = []
        self._rate_limiter = RegistryRateLimiter()
        self._known_bad: list[dict] = []  # loaded from known_bad_orgs.yml

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Download/load IANA bootstrap, scan existing ban_cidr keys, start workers.

        Called once at proxy startup.

        Raises:
            FileNotFoundError: If known_bad_orgs.yml is missing.
            RuntimeError: If known_bad_orgs.yml cannot be parsed.
        """
        if not self._config.enabled:
            return

        # Load known-bad org list — fatal on missing file
        self._load_known_bad_orgs()

        # Load IANA bootstrap (leader election)
        await self._load_bootstrap()

        # Scan Redis for existing ban_cidr:* keys and load into blocklist trie
        await self._scan_existing_ban_cidrs()

        self._queue = asyncio.Queue(maxsize=self._config.queue_size)
        self._workers = [
            asyncio.create_task(
                self._lookup_worker(), name=f"rdap-worker-{i}"
            )
            for i in range(self._config.worker_count)
        ]
        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "rdap",
                "event": "started",
                "worker_count": self._config.worker_count,
                "queue_size": self._config.queue_size,
            })
        )

    async def stop(self) -> None:
        """Cancel workers gracefully and log any remaining queue depth."""
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        if self._queue is not None:
            remaining = self._queue.qsize()
            if remaining:
                logger.warning(
                    json.dumps({
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "rdap",
                        "event": "shutdown_queue_not_empty",
                        "depth": remaining,
                    })
                )

    # ------------------------------------------------------------------
    # Hot-path entry points (never block)
    # ------------------------------------------------------------------

    def get_signal(self, ip: str, trigger_score: int) -> list[RiskSignal]:
        """Hot-path entry point. Returns cached signals (possibly empty). Never blocks.

        Checks LocalCache.rdap_results (in-process LRU) only — no Redis on hot path.
        Enqueues background lookup on cache miss if trigger_score >= min_enqueue_score.

        Args:
            ip:            Canonical IP address string.
            trigger_score: Running composite score from all preceding signal modules.
                           Used to gate whether this IP is worth enriching.

        Returns:
            list[RiskSignal] — empty if no cached data available yet.
        """
        if not self._config.enabled:
            return []

        # In-process LRU hit — return immediately
        cached: RDAPResult | None = self._local_cache.rdap_results.get(ip)
        if cached is not None:
            return self._rdap_to_signals(cached)

        # Cache miss — enqueue background lookup if score warrants it
        if trigger_score >= self._config.min_enqueue_score and self._queue is not None:
            asyncio.create_task(self._enqueue_lookup(ip))

        return []

    async def record_browser_subnet(self, ip: str) -> None:
        """Set browser:seen:subnet:{subnet} in Redis with 24h TTL.

        Called fire-and-forget from the pipeline hot path for every h2/h1 ALPN
        connection. Prevents block expansion for subnets with known browser traffic.

        Args:
            ip: Canonical IP address string.
        """
        from ..utils.ip import get_analysis_subnet
        try:
            subnet = get_analysis_subnet(ip)
            await self._redis.setex(f"browser:seen:subnet:{subnet}", 86400, "1")
        except Exception as exc:
            logger.debug(
                "rdap | event=browser_subnet_write_error | ip=%s | error=%s", ip, exc
            )

    def on_config_reload(self, new_config: dict) -> None:
        """Apply hot-reloadable config changes.

        Hot-reloadable: enabled, min_enqueue_score, lookup_timeout_seconds,
                        delegate_to_analytics, org_reputation.*, new_netblock_flagging.*,
                        block_expansion.* (except worker_count / queue_size).
        NOT hot-reloadable: worker_count, queue_size (require restart).
        """
        new_cfg = RDAPConfig.from_config(new_config)

        if new_cfg.worker_count != self._config.worker_count:
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "restart_required",
                    "key": "worker_count",
                    "old": self._config.worker_count,
                    "new": new_cfg.worker_count,
                })
            )
        if new_cfg.queue_size != self._config.queue_size:
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "restart_required",
                    "key": "queue_size",
                    "old": self._config.queue_size,
                    "new": new_cfg.queue_size,
                })
            )

        # Apply hot-reloadable fields; keep old worker_count and queue_size
        self._config = RDAPConfig(
            enabled=new_cfg.enabled,
            queue_size=self._config.queue_size,      # Keep old — requires restart
            worker_count=self._config.worker_count,  # Keep old — requires restart
            min_enqueue_score=new_cfg.min_enqueue_score,
            lookup_timeout_seconds=new_cfg.lookup_timeout_seconds,
            delegate_to_analytics=new_cfg.delegate_to_analytics,
            org_reputation=new_cfg.org_reputation,
            new_netblock_flagging=new_cfg.new_netblock_flagging,
            block_expansion=new_cfg.block_expansion,
        )

    # ------------------------------------------------------------------
    # Internal — background pipeline
    # ------------------------------------------------------------------

    async def _enqueue_lookup(self, ip: str) -> None:
        """Bloom-filter dedup, then enqueue for RDAP lookup."""
        if not self._config.enabled or self._queue is None:
            return

        if self._config.delegate_to_analytics:
            try:
                await self._redis.sadd("analytics:enrich:rdap", ip)
            except Exception as exc:
                logger.warning(
                    "rdap | event=delegate_error | ip=%s | error=%s", ip, exc
                )
            return

        # Bloom filter dedup
        try:
            added = await self._redis.bf().add("bloom:rdap_enriched", ip)
            if not added:
                return
            try:
                await self._redis.expire("bloom:rdap_enriched", 86400)
            except Exception:
                pass
        except Exception:
            # RedisBloom unavailable — fallback SET+TTL
            try:
                bloom_key = f"bloom_fallback:rdap_enriched:{ip}"
                already = await self._redis.get(bloom_key)
                if already is not None:
                    return
                await self._redis.setex(bloom_key, 86400, "1")
            except Exception as exc:
                logger.debug(
                    "rdap | event=bloom_fallback_error | ip=%s | error=%s", ip, exc
                )

        # Enqueue
        try:
            self._queue.put_nowait(ip)
            _QUEUE_DEPTH.set(self._queue.qsize())
        except asyncio.QueueFull:
            _QUEUE_DROPPED.inc()

    async def _lookup_worker(self) -> None:
        """Drain the enrichment queue. Runs until cancelled."""
        while True:
            try:
                ip = await self._queue.get()
                _QUEUE_DEPTH.set(self._queue.qsize())
                try:
                    await self._process_lookup(ip)
                except Exception as exc:
                    logger.error(
                        json.dumps({
                            "type": "system",
                            "level": "ERROR",
                            "subsystem": "rdap",
                            "event": "worker_unhandled_error",
                            "error": str(exc),
                        })
                    )
                    _LOOKUP_TOTAL.labels(registry="unknown", result="error").inc()
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break  # Graceful shutdown

    async def _process_lookup(self, ip: str) -> None:
        """Perform one full RDAP lookup: bootstrap → rate limit → API → cache write."""
        try:
            base_url = await self.get_rdap_base_url(ip)
        except Exception as exc:
            logger.error(
                json.dumps({
                    "type": "system",
                    "level": "ERROR",
                    "subsystem": "rdap",
                    "event": "bootstrap_routing_error",
                    "ip": ip,
                    "error": str(exc),
                })
            )
            _LOOKUP_TOTAL.labels(registry="unknown", result="error").inc()
            return

        # Extract registry hostname for rate limiting and metrics
        try:
            from urllib.parse import urlparse
            registry_host = urlparse(base_url).netloc
        except Exception:
            registry_host = "unknown"

        # Apply per-registry rate limit
        try:
            await self._rate_limiter.acquire(registry_host)
        except Exception:
            pass  # Rate limiter failure is non-fatal

        # Perform RDAP lookup
        try:
            rdap = await self._api_lookup(ip, base_url)
        except asyncio.TimeoutError:
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "registry_timeout",
                    "registry": registry_host,
                    "ip": ip,
                })
            )
            _LOOKUP_TOTAL.labels(registry=registry_host, result="timeout").inc()
            return
        except _RedirectLimitError:
            _LOOKUP_TOTAL.labels(registry=registry_host, result="redirect_limit").inc()
            return
        except _NotFoundError:
            # 404 is not an error — store as is_unknown=True; never retried
            rdap = RDAPResult(
                netblock="0.0.0.0/0",
                org_name="",
                org_handle="",
                asn=None,
                country=None,
                registration_date=None,
                fetched_at=datetime.now(timezone.utc).timestamp(),
                is_unknown=True,
            )
            _LOOKUP_TOTAL.labels(registry=registry_host, result="not_found").inc()
        except Exception as exc:
            logger.error(
                json.dumps({
                    "type": "system",
                    "level": "ERROR",
                    "subsystem": "rdap",
                    "event": "registry_error",
                    "registry": registry_host,
                    "error": str(exc),
                })
            )
            _LOOKUP_TOTAL.labels(registry=registry_host, result="error").inc()
            return
        else:
            _LOOKUP_TOTAL.labels(registry=registry_host, result="ok").inc()

        # Write result to Redis and LocalCache
        await self._cache_result(ip, rdap)

        # Maybe trigger block expansion (if not unknown)
        if not rdap.is_unknown:
            trigger_score = 0  # We don't have the original score here; expansion
            # is only triggered by the background worker after explicit request.
            # The block expansion check is triggered explicitly via maybe_expand_block.
            is_known_bad, _ = self._check_known_bad(rdap.org_handle, rdap.org_name)
            await self.maybe_expand_block(ip, rdap, trigger_score=0, is_known_bad=is_known_bad)

    async def _cache_result(self, ip: str, rdap: RDAPResult) -> None:
        """Write RDAPResult to Redis and LocalCache."""
        # Write to Redis
        try:
            result_dict = {
                "netblock": rdap.netblock,
                "org_name": rdap.org_name,
                "org_handle": rdap.org_handle,
                "asn": rdap.asn,
                "country": rdap.country,
                "registration_date": rdap.registration_date,
                "fetched_at": rdap.fetched_at,
                "is_unknown": rdap.is_unknown,
            }
            await self._redis.setex(
                f"rdap:ip:{ip}",
                86400,
                json.dumps(result_dict),
            )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "redis_write_error",
                    "ip": ip,
                    "error": str(exc),
                })
            )

        # Write to in-process LRU (hot path reads from here)
        self._local_cache.rdap_results.set(ip, rdap)

    def _rdap_to_signals(self, rdap: RDAPResult) -> list[RiskSignal]:
        """Convert a cached RDAPResult to a list of RiskSignals."""
        if rdap.is_unknown:
            return []

        signals: list[RiskSignal] = []

        # Org reputation check
        if self._config.org_reputation.enabled:
            is_known_bad, org_entry = self._check_known_bad(rdap.org_handle, rdap.org_name)
            if is_known_bad and org_entry:
                signals.append(RiskSignal(
                    name="rdap_known_bad_org",
                    score=org_entry.get("score", self._config.org_reputation.score),
                    reason=(
                        f"Known bad org: {rdap.org_name or rdap.org_handle} "
                        f"({org_entry.get('reason', '')})"
                    ),
                ))

        # New netblock check
        if self._config.new_netblock_flagging.enabled:
            sig = new_netblock_signal(
                rdap.registration_date,
                self._config.new_netblock_flagging.max_age_days,
                self._config.new_netblock_flagging.score,
            )
            if sig is not None:
                signals.append(sig)

        return signals

    # ------------------------------------------------------------------
    # IANA Bootstrap
    # ------------------------------------------------------------------

    async def _load_bootstrap(self) -> None:
        """Load IANA bootstrap data (leader election + Redis caching)."""
        # Try loading from Redis first
        try:
            v4_raw = await self._redis.get("rdap:bootstrap:v4")
            v6_raw = await self._redis.get("rdap:bootstrap:v6")
            if v4_raw and v6_raw:
                self._bootstrap_v4 = json.loads(v4_raw)
                self._bootstrap_v6 = json.loads(v6_raw)
                logger.info(
                    json.dumps({
                        "type": "system",
                        "level": "INFO",
                        "subsystem": "rdap",
                        "event": "bootstrap_loaded_from_redis",
                    })
                )
                return
        except Exception as exc:
            logger.warning(
                "rdap | event=bootstrap_redis_read_error | error=%s", exc
            )

        # Leader election — download bootstrap
        try:
            won = await self._try_become_bootstrap_leader()
        except Exception:
            won = True  # Fail open — act as leader

        if won:
            await self._download_bootstrap()
        else:
            # Wait for leader to populate Redis (up to 30s)
            for _ in range(30):
                await asyncio.sleep(1)
                try:
                    v4_raw = await self._redis.get("rdap:bootstrap:v4")
                    v6_raw = await self._redis.get("rdap:bootstrap:v6")
                    if v4_raw and v6_raw:
                        self._bootstrap_v4 = json.loads(v4_raw)
                        self._bootstrap_v6 = json.loads(v6_raw)
                        return
                except Exception:
                    pass
            # Timed out — warn and continue without bootstrap
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "bootstrap_load_timeout",
                    "effect": "RDAP lookups may fail until bootstrap is available",
                })
            )

    async def _try_become_bootstrap_leader(self) -> bool:
        """Acquire leader:rdap_bootstrap_download lock. Returns True if winner."""
        try:
            result = await self._redis.set(
                "leader:rdap_bootstrap_download",
                self._instance_id,
                nx=True,
                ex=300,  # 5-minute lock
            )
            return result is not None
        except Exception:
            return True  # Fail open — act as leader

    async def _download_bootstrap(self) -> None:
        """Download IANA bootstrap JSON and write to Redis."""
        if not AIOHTTP_AVAILABLE or self._session is None:
            logger.warning(
                json.dumps({
                    "type": "system",
                    "level": "WARN",
                    "subsystem": "rdap",
                    "event": "bootstrap_download_skipped",
                    "reason": "aiohttp or session unavailable",
                })
            )
            return

        for url, redis_key, attr in [
            (BOOTSTRAP_URL_V4, "rdap:bootstrap:v4", "_bootstrap_v4"),
            (BOOTSTRAP_URL_V6, "rdap:bootstrap:v6", "_bootstrap_v6"),
        ]:
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    services = data.get("services", [])
                    # Each service: [[prefixes...], [urls...]]
                    parsed = [
                        {"prefixes": svc[0], "urls": svc[1]}
                        for svc in services
                        if len(svc) >= 2
                    ]
                    setattr(self, attr, parsed)
                    # Write to Redis
                    try:
                        await self._redis.setex(redis_key, 86400, json.dumps(parsed))
                    except Exception as exc:
                        logger.warning(
                            "rdap | event=bootstrap_redis_write_error | key=%s | error=%s",
                            redis_key, exc,
                        )
            except Exception as exc:
                logger.warning(
                    json.dumps({
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "rdap",
                        "event": "bootstrap_download_failed",
                        "url": url,
                        "error": str(exc),
                    })
                )

    async def get_rdap_base_url(self, ip: str) -> str:
        """Find the correct RIR for this IP using IANA bootstrap.

        Walks bootstrap entries to find the longest matching prefix.

        Args:
            ip: IP address string.

        Returns:
            RDAP base URL, e.g. "https://rdap.arin.net/registry/".
        """
        addr = ipaddress.ip_address(ip)
        bootstrap = self._bootstrap_v6 if addr.version == 6 else self._bootstrap_v4

        best_prefixlen = -1
        best_url = "https://rdap.arin.net/registry/"  # Default fallback

        for entry in bootstrap:
            for prefix_str in entry.get("prefixes", []):
                try:
                    net = ipaddress.ip_network(prefix_str, strict=False)
                    if addr in net and net.prefixlen > best_prefixlen:
                        best_prefixlen = net.prefixlen
                        urls = entry.get("urls", [])
                        if urls:
                            best_url = urls[0]
                except (ValueError, TypeError):
                    continue

        return best_url

    # ------------------------------------------------------------------
    # RDAP API
    # ------------------------------------------------------------------

    async def _api_lookup(self, ip: str, base_url: str) -> RDAPResult:
        """Perform RDAP IP lookup. Follows up to 3 redirects.

        Args:
            ip:       Canonical IP address string.
            base_url: RDAP base URL for the relevant RIR.

        Returns:
            Parsed :class:`RDAPResult`.

        Raises:
            _NotFoundError:     On HTTP 404.
            _RedirectLimitError: After 3 redirect hops.
            asyncio.TimeoutError: On timeout.
            Exception:          On other HTTP/network errors.
        """
        if not AIOHTTP_AVAILABLE:  # pragma: no cover
            raise RuntimeError("aiohttp is not installed")

        url = f"{base_url.rstrip('/')}/ip/{ip}"
        redirect_count = 0
        max_redirects = 3

        while redirect_count <= max_redirects:
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(
                        total=self._config.lookup_timeout_seconds
                    ),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 404:
                        raise _NotFoundError(ip)
                    if resp.status in (301, 302, 303, 307, 308):
                        if redirect_count >= max_redirects:
                            raise _RedirectLimitError(
                                f"Exceeded {max_redirects} redirects for {ip}"
                            )
                        location = resp.headers.get("Location", "")
                        if not location:
                            raise Exception(f"Redirect with no Location header for {ip}")
                        url = location
                        redirect_count += 1
                        continue
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
                    try:
                        return self._parse_rdap_response(data, ip)
                    except Exception as exc:
                        _PARSE_ERRORS.inc()
                        logger.error(
                            json.dumps({
                                "type": "system",
                                "level": "ERROR",
                                "subsystem": "rdap",
                                "event": "parse_error",
                                "ip": ip,
                                "error": str(exc),
                            })
                        )
                        raise
            except (_NotFoundError, _RedirectLimitError, asyncio.TimeoutError):
                raise
            except Exception:
                raise

        raise _RedirectLimitError(f"Exceeded {max_redirects} redirects for {ip}")

    def _parse_rdap_response(self, data: dict, ip: str) -> RDAPResult:
        """Parse RDAP JSON response into a RDAPResult.

        Handles RFC 7483 format with:
        - vCard format for org entity data
        - ARIN handle vs RIPE nic-hdl variations
        - events array for registration date
        - startAddress + cidrLength or network.cidr for netblock
        """
        # Extract netblock
        netblock = _extract_netblock(data, ip)

        # Extract org info from entities
        org_name, org_handle = _extract_org(data)

        # Extract ASN
        asn: str | None = None
        if "autnums" in data:
            for autnum in data.get("autnums", []):
                handle = autnum.get("handle", "")
                if handle:
                    asn = f"AS{handle.lstrip('AS')}"
                    break
        # Some registries put ASN in parentName or name field
        if asn is None:
            parent_name = data.get("parentHandle", "")
            if parent_name and parent_name.startswith("AS"):
                asn = parent_name

        # Extract country
        country: str | None = None
        country = data.get("country")

        # Extract registration date from events
        registration_date: str | None = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                raw_date = event.get("eventDate", "")
                if raw_date:
                    # Normalise: strip time part if present
                    registration_date = raw_date[:10] if len(raw_date) >= 10 else raw_date
                break

        return RDAPResult(
            netblock=netblock,
            org_name=org_name,
            org_handle=org_handle,
            asn=asn,
            country=country,
            registration_date=registration_date,
            fetched_at=datetime.now(timezone.utc).timestamp(),
            is_unknown=False,
        )

    # ------------------------------------------------------------------
    # Known-bad org detection
    # ------------------------------------------------------------------

    def _load_known_bad_orgs(self) -> None:
        """Load config/known_bad_orgs.yml. Fatal if missing or unparseable."""
        path = self._known_bad_orgs_path
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"known_bad_orgs.yml not found at {path!r}. "
                "This file is required for RDAP enrichment. "
                "Create it or disable rdap_enrichment in proxy.yml."
            )
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            self._known_bad = raw.get("orgs", [])
        except Exception as exc:
            raise RuntimeError(
                f"Failed to parse {path!r}: {exc}. "
                "Fix the YAML syntax or disable rdap_enrichment in proxy.yml."
            ) from exc

    def _check_known_bad(
        self, org_handle: str, org_name: str
    ) -> tuple[bool, dict | None]:
        """Check if an org matches the known-bad list.

        Matching order (first match wins):
        1. Exact org_handle match (case-insensitive)
        2. Case-insensitive substring match on org_name

        Args:
            org_handle: Registry org handle string.
            org_name:   Organization name string.

        Returns:
            (is_match, matched_entry_dict) — entry is None when no match.
        """
        if not self._known_bad:
            return False, None

        # 1. Exact handle match
        if org_handle:
            for entry in self._known_bad:
                if entry.get("handle", "").lower() == org_handle.lower():
                    return True, entry

        # 2. Substring name match (case-insensitive)
        if org_name:
            org_name_lower = org_name.lower()
            for entry in self._known_bad:
                entry_name = entry.get("name", "")
                if entry_name and entry_name.lower() in org_name_lower:
                    return True, entry

        return False, None

    # ------------------------------------------------------------------
    # Block expansion
    # ------------------------------------------------------------------

    async def maybe_expand_block(
        self,
        ip: str,
        rdap: RDAPResult,
        trigger_score: int,
        is_known_bad: bool,
    ) -> bool:
        """Attempt CIDR block expansion. Returns True if expansion was applied.

        All four guards must pass:
        1. trigger_score >= min_trigger_score
        2. discovered netblock prefix >= max_prefix_length (not too broad)
        3. No browser traffic seen from this subnet
        4. Org confirmed as known-bad

        Plus cross-instance hourly rate limit cap.

        Args:
            ip:            Trigger IP address string.
            rdap:          RDAP enrichment result for the IP.
            trigger_score: Composite score that triggered enrichment.
            is_known_bad:  True when org matched the known-bad list.

        Returns:
            True if expansion was applied; False otherwise.
        """
        if not self._config.block_expansion.enabled:
            return False

        # Guard 1: Score threshold
        if trigger_score < self._config.block_expansion.min_trigger_score:
            return False

        # Guard 2: Network prefix size — reject if broader than configured max
        try:
            net = ipaddress.ip_network(rdap.netblock, strict=False)
            if net.version == 4:
                if net.prefixlen < self._config.block_expansion.max_prefix_length_v4:
                    return False  # Netblock broader than /24 — too risky
            else:
                if net.prefixlen < self._config.block_expansion.max_prefix_length_v6:
                    return False  # Netblock broader than /48 — too risky
        except (ValueError, TypeError):
            return False

        # Guard 3: No browser traffic from this subnet
        try:
            from ..utils.ip import get_analysis_subnet
            subnet = get_analysis_subnet(ip)
            browser_key_exists = await self._redis.exists(f"browser:seen:subnet:{subnet}")
            if browser_key_exists:
                return False  # Browser traffic observed here — do NOT expand
        except Exception as exc:
            logger.warning(
                "rdap | event=browser_subnet_check_error | ip=%s | error=%s", ip, exc
            )
            return False  # Fail safe on error

        # Guard 4: Confirmed known-bad org required
        if not is_known_bad:
            return False

        # Cross-instance hourly cap
        if not await self._check_expansion_rate_limit():
            return False

        expansion_cidr = _compute_expansion_cidr(ip, self._config.block_expansion)
        await self._apply_expansion(expansion_cidr, rdap, trigger_score)
        await self._log_expansion_audit(ip, expansion_cidr, rdap, trigger_score)

        logger.info(
            json.dumps({
                "type": "system",
                "level": "INFO",
                "subsystem": "rdap",
                "event": "block_expansion_applied",
                "ip": ip,
                "cidr": expansion_cidr,
                "org_handle": rdap.org_handle,
                "org_name": rdap.org_name,
                "trigger_score": trigger_score,
            })
        )

        _BLOCK_EXPANSIONS.inc()
        return True

    async def _check_expansion_rate_limit(self) -> bool:
        """Redis atomic counter for hourly expansion cap.

        Returns True if expansion is allowed; False if cap is reached.
        Rolls back the counter increment on rejection.
        """
        hour_key = (
            f"rdap:expansions:count:"
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
        )
        try:
            count = await self._redis.incr(hour_key)
            if count == 1:
                await self._redis.expire(hour_key, 3600)
            if count > self._config.block_expansion.max_expansions_per_hour:
                await self._redis.decr(hour_key)
                logger.warning(
                    json.dumps({
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "rdap",
                        "event": "expansion_rate_limit_reached",
                        "hour_count": count,
                        "max_per_hour": self._config.block_expansion.max_expansions_per_hour,
                    })
                )
                return False
            # Update Prometheus gauge
            _EXPANSIONS_THIS_HOUR.set(count)
            return True
        except Exception as exc:
            logger.warning(
                "rdap | event=expansion_rate_limit_error | error=%s | failing open", exc
            )
            return True  # Fail open on rate limit check failure

    async def _apply_expansion(
        self, cidr: str, rdap: RDAPResult, trigger_score: int
    ) -> None:
        """Apply a CIDR block expansion:
        1. Write ban_cidr:{cidr} to Redis with TTL
        2. Update local BlocklistManager trie
        3. Publish cidr_ban_add to ja4proxy:invalidate
        """
        # 1. Write to Redis with TTL
        try:
            await self._redis.setex(
                f"ban_cidr:{cidr}",
                self._config.block_expansion.expansion_ban_duration,
                "1",
            )
        except Exception as exc:
            logger.warning(
                "rdap | event=ban_cidr_write_error | cidr=%s | error=%s", cidr, exc
            )

        # 2. Load into local trie
        if self._blocklist_manager is not None:
            try:
                self._blocklist_manager.load_cidrs([cidr], "rdap_expansion")
            except Exception as exc:
                logger.warning(
                    "rdap | event=trie_load_error | cidr=%s | error=%s", cidr, exc
                )

        # 3. Publish to other instances
        try:
            msg = json.dumps({"type": "cidr_ban_add", "value": cidr})
            await self._redis.publish("ja4proxy:invalidate", msg)
        except Exception as exc:
            logger.warning(
                "rdap | event=pubsub_publish_error | cidr=%s | error=%s", cidr, exc
            )

    async def _log_expansion_audit(
        self, ip: str, cidr: str, rdap: RDAPResult, trigger_score: int
    ) -> None:
        """Write expansion audit entry to Redis LIST (capped at 1000)."""
        entry = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trigger_ip": ip,
            "trigger_score": trigger_score,
            "expansion_cidr": cidr,
            "org_name": rdap.org_name,
            "org_handle": rdap.org_handle,
            "netblock": rdap.netblock,
            "guards_checked": {
                "min_trigger_score": self._config.block_expansion.min_trigger_score,
                "max_prefix_v4": self._config.block_expansion.max_prefix_length_v4,
                "max_prefix_v6": self._config.block_expansion.max_prefix_length_v6,
            },
            "instance_id": self._instance_id,
        })
        try:
            await self._redis.lpush("rdap:expansions", entry)
            await self._redis.ltrim("rdap:expansions", 0, 999)  # Cap at 1000
        except Exception as exc:
            logger.warning(
                "rdap | event=audit_write_error | cidr=%s | error=%s", cidr, exc
            )

    async def _scan_existing_ban_cidrs(self) -> None:
        """Scan Redis for ban_cidr:* keys and load into BlocklistManager trie."""
        if self._blocklist_manager is None:
            return
        try:
            cidrs: list[str] = []
            cursor = 0
            while True:
                cursor, keys = await self._redis.scan(cursor, match="ban_cidr:*", count=100)
                for key in keys:
                    key_str = key.decode("utf-8") if isinstance(key, bytes) else key
                    cidr = key_str[len("ban_cidr:"):]
                    if cidr:
                        cidrs.append(cidr)
                if cursor == 0:
                    break
            if cidrs:
                self._blocklist_manager.load_cidrs(cidrs, "rdap_expansion")
                logger.info(
                    json.dumps({
                        "type": "system",
                        "level": "INFO",
                        "subsystem": "rdap",
                        "event": "ban_cidrs_loaded_from_redis",
                        "count": len(cidrs),
                    })
                )
        except Exception as exc:
            logger.warning(
                "rdap | event=ban_cidr_scan_error | error=%s", exc
            )


# ---------------------------------------------------------------------------
# Private exception types
# ---------------------------------------------------------------------------


class _NotFoundError(Exception):
    """RDAP API returned 404 for this IP."""


class _RedirectLimitError(Exception):
    """Exceeded the maximum number of redirect hops."""


# ---------------------------------------------------------------------------
# RDAP response parsing helpers
# ---------------------------------------------------------------------------


def _extract_netblock(data: dict, ip: str) -> str:
    """Extract netblock CIDR from RDAP response."""
    # Method 1: startAddress + cidrLength
    start = data.get("startAddress", "")
    cidr_len = data.get("cidrLength")
    if start and cidr_len is not None:
        try:
            return str(ipaddress.ip_network(f"{start}/{cidr_len}", strict=False))
        except (ValueError, TypeError):
            pass

    # Method 2: network.cidr field (some registries)
    network = data.get("network", {})
    if network:
        start = network.get("startAddress", "")
        cidr_len = network.get("cidrLength")
        if start and cidr_len is not None:
            try:
                return str(ipaddress.ip_network(f"{start}/{cidr_len}", strict=False))
            except (ValueError, TypeError):
                pass
        # Some use endAddress instead
        end = network.get("endAddress", "")
        if start and end:
            try:
                start_addr = ipaddress.ip_address(start)
                if start_addr.version == 4:
                    return str(ipaddress.ip_network(f"{start}/24", strict=False))
                return str(ipaddress.ip_network(f"{start}/48", strict=False))
            except (ValueError, TypeError):
                pass

    # Fallback: compute /24 or /48 from the trigger IP
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/48", strict=False))
    except (ValueError, TypeError):
        return "0.0.0.0/0"


def _extract_org(data: dict) -> tuple[str, str]:
    """Extract org_name and org_handle from RDAP entities."""
    org_name = ""
    org_handle = ""

    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrant" not in roles and "administrative" not in roles:
            continue

        # Handle (ARIN uses 'handle'; RIPE uses 'nic-hdl')
        handle = entity.get("handle", "") or entity.get("nic-hdl", "")
        if handle:
            org_handle = handle

        # vCard format: [[version...], [fn, {}, text, "Name"], ...]
        vcard = entity.get("vcardArray", [])
        if vcard and len(vcard) >= 2:
            vcard_data = vcard[1]
            for entry in vcard_data:
                if not isinstance(entry, list) or len(entry) < 4:
                    continue
                if entry[0] in ("fn", "org"):
                    name_val = entry[3]
                    if isinstance(name_val, list):
                        name_val = " ".join(str(v) for v in name_val if v)
                    if name_val and not org_name:
                        org_name = str(name_val)

        if org_name:
            break

    # Fallback: try top-level name
    if not org_name:
        org_name = data.get("name", "")

    return org_name, org_handle
