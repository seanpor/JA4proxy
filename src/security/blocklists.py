"""Blocklists - Phase 8

Spamhaus DROP/EDROP and extensible threat-intel feed framework.

Architecture:
- In-process pytricia CIDR tries (IPv4 + IPv6) for O(log n) lookup.
- Redis stores raw CIDR lists for cross-instance sharing (never for lookup).
- Leader election ensures only one instance downloads per feed.
- ETag-based conditional HTTP download avoids redundant processing.
- is_bypass=true  → hard-block bypass (no scorer involved).
- is_bypass=false → RiskSignal contribution to scorer.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from prometheus_client import Counter, Gauge

try:
    import pytricia
    PYTRICIA_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYTRICIA_AVAILABLE = False
    pytricia = None  # type: ignore

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:  # pragma: no cover
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore

from src.security.models import RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_BLOCKLIST_ENTRIES = Gauge(
    "ja4proxy_blocklist_entries",
    "Current loaded CIDR count per feed",
    ["feed"],
)
_BLOCKLIST_LAST_REFRESH = Gauge(
    "ja4proxy_blocklist_last_refresh_success_seconds",
    "Unix timestamp of last successful feed refresh",
    ["feed"],
)
_BLOCKLIST_DOWNLOAD_ERRORS = Counter(
    "ja4proxy_blocklist_download_errors_total",
    "Failed download attempts per feed",
    ["feed"],
)
_BLOCKLIST_MATCHES = Counter(
    "ja4proxy_blocklist_matches_total",
    "Connections matched per feed",
    ["feed"],
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FeedConfig:
    """Configuration for one blocklist feed."""
    name: str
    url: str
    format: str                     # spamhaus | cidr | ipset
    is_bypass: bool                 # True → hard-block; False → RiskSignal
    action: str                     # block | tarpit | flag
    score: int                      # Risk score when is_bypass=False
    refresh_interval_seconds: int
    enabled: bool = True


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def parse_feed(text: str, fmt: str) -> list[str]:
    """Parse a blocklist feed text into a list of valid CIDR strings.

    Skips comment lines, strips suffixes (SBL refs, inline comments),
    and silently drops malformed CIDRs.

    Args:
        text: Raw feed content.
        fmt: Format variant — "spamhaus", "cidr", or "ipset".

    Returns:
        List of CIDR strings (e.g. "1.10.16.0/20").
    """
    import ipaddress

    cidrs: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if fmt == "spamhaus":
            if line.startswith(";"):
                continue
            # Split on space/semicolon — CIDR is always first field
            cidr = line.split()[0].split(";")[0].strip()
        elif fmt == "cidr":
            if line.startswith("#") or line.startswith(";"):
                continue
            cidr = line.split()[0]
        elif fmt == "ipset":
            # Format: "add <setname> <cidr>"
            if not line.startswith("add "):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            cidr = parts[2]
        else:
            cidr = line.split()[0]

        # Validate
        try:
            ipaddress.ip_network(cidr, strict=False)
            cidrs.append(cidr)
        except ValueError:
            logger.warning(
                json.dumps({
                    "type": "system", "level": "WARN",
                    "subsystem": "blocklist", "event": "malformed_cidr",
                    "cidr": cidr,
                })
            )

    return cidrs


# ---------------------------------------------------------------------------
# BlocklistManager
# ---------------------------------------------------------------------------

class BlocklistManager:
    """In-process CIDR trie for O(log n) blocklist lookups.

    Maintains separate pytricia tries for IPv4 and IPv6.
    Stores the feed name as trie value so callers know which list matched.
    Also stores per-feed FeedConfig for non-bypass signal generation.
    """

    def __init__(self) -> None:
        if PYTRICIA_AVAILABLE:
            self._trie_v4 = pytricia.PyTricia(32)
            self._trie_v6 = pytricia.PyTricia(128)
        else:  # pragma: no cover
            raise RuntimeError("pytricia is required — install it: pip install pytricia")

        # Maps feed_name → FeedConfig (for is_bypass=false signal generation)
        self._feed_configs: dict[str, FeedConfig] = {}
        # Maps feed_name → set of CIDRs currently loaded (for reload)
        self._feed_cidrs: dict[str, set[str]] = {}

    def load_cidrs(
        self,
        cidrs: list[str],
        list_name: str,
        feed_config: Optional[FeedConfig] = None,
    ) -> int:
        """Load (or replace) CIDRs for one feed. Returns count loaded.

        Atomically replaces all previous entries for ``list_name`` with the
        new set. CIDRs from other feeds are unaffected.
        """
        import ipaddress

        # Remove old entries for this feed
        old_cidrs = self._feed_cidrs.get(list_name, set())
        for cidr in old_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                trie = self._trie_v6 if net.version == 6 else self._trie_v4
                if trie.has_key(cidr):
                    del trie[cidr]
            except Exception:
                pass

        # Insert new entries
        loaded: list[str] = []
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                trie = self._trie_v6 if net.version == 6 else self._trie_v4
                trie[cidr] = list_name
                loaded.append(cidr)
            except Exception:
                logger.warning(
                    json.dumps({
                        "type": "system", "level": "WARN",
                        "subsystem": "blocklist", "event": "cidr_load_failed",
                        "list": list_name, "cidr": cidr,
                    })
                )

        self._feed_cidrs[list_name] = set(loaded)
        if feed_config is not None:
            self._feed_configs[list_name] = feed_config

        _BLOCKLIST_ENTRIES.labels(feed=list_name).set(len(loaded))
        return len(loaded)

    def is_blocked(self, ip: str) -> tuple[bool, str]:
        """Check ip against all loaded CIDR tries. O(log n).

        Returns:
            (True, feed_name) on match; (False, "") otherwise.
        """
        try:
            trie = self._trie_v6 if ":" in ip else self._trie_v4
            match = trie.get(ip)
            if match:
                # Only count as bypass-block when feed is a bypass feed
                feed_name = match
                _BLOCKLIST_MATCHES.labels(feed=feed_name).inc()
                return True, feed_name
        except Exception as exc:
            logger.error(
                json.dumps({
                    "type": "system", "level": "ERROR",
                    "subsystem": "blocklist", "event": "lookup_error",
                    "ip": ip, "error": str(exc),
                })
            )
        return False, ""

    def get_signals(self, ip: str) -> list[RiskSignal]:
        """Return RiskSignals for non-bypass feeds that match ip.

        Bypass feeds (is_bypass=True) are intentionally excluded here —
        they are handled as hard-block bypasses in the pipeline, not as
        scored signals.
        """
        signals: list[RiskSignal] = []
        try:
            trie = self._trie_v6 if ":" in ip else self._trie_v4
            match = trie.get(ip)
            if not match:
                return signals
            feed_name = match
            cfg = self._feed_configs.get(feed_name)
            if cfg is None or cfg.is_bypass:
                return signals
            _BLOCKLIST_MATCHES.labels(feed=feed_name).inc()
            signals.append(RiskSignal(
                name=f"blocklist_{feed_name}",
                score=cfg.score,
                reason=f"IP matched {feed_name} blocklist",
            ))
        except Exception as exc:
            logger.error(
                json.dumps({
                    "type": "system", "level": "ERROR",
                    "subsystem": "blocklist", "event": "signal_error",
                    "ip": ip, "error": str(exc),
                })
            )
        return signals

    def entry_count(self, feed_name: str) -> int:
        """Return the number of CIDRs currently loaded for feed_name."""
        return len(self._feed_cidrs.get(feed_name, set()))


# ---------------------------------------------------------------------------
# FeedManager — download, parse, distribute
# ---------------------------------------------------------------------------

class FeedManager:
    """Manages periodic download and distribution of blocklist feeds.

    Leader election ensures only one proxy instance downloads per feed.
    Non-leaders load from Redis. ETag-based conditional HTTP avoids
    redundant parse+load cycles.
    """

    def __init__(
        self,
        config: dict,
        blocklist_manager: BlocklistManager,
        redis_client=None,
        instance_id: str = "default",
    ) -> None:
        self._bl_cfg = config.get("blocklists", {})
        self._feeds: list[FeedConfig] = self._parse_feed_configs()
        self._mgr = blocklist_manager
        self._redis = redis_client
        self._instance_id = instance_id
        self._refresh_tasks: list[asyncio.Task] = []

    def _parse_feed_configs(self) -> list[FeedConfig]:
        raw_feeds = self._bl_cfg.get("feeds", [])
        configs = []
        for f in raw_feeds:
            if not f.get("enabled", True):
                continue
            configs.append(FeedConfig(
                name=f["name"],
                url=f.get("url", ""),
                format=f.get("format", "spamhaus"),
                is_bypass=f.get("is_bypass", True),
                action=f.get("action", "block"),
                score=f.get("score", 60),
                refresh_interval_seconds=f.get("refresh_interval_seconds", 43200),
                enabled=True,
            ))
        return configs

    async def start(self) -> None:
        """Load all feeds and start background refresh tasks."""
        for feed_cfg in self._feeds:
            await self._load_feed(feed_cfg)
            task = asyncio.create_task(self._refresh_loop(feed_cfg))
            self._refresh_tasks.append(task)

    async def stop(self) -> None:
        """Cancel refresh tasks."""
        for task in self._refresh_tasks:
            task.cancel()
        await asyncio.gather(*self._refresh_tasks, return_exceptions=True)
        self._refresh_tasks.clear()

    async def _refresh_loop(self, feed_cfg: FeedConfig) -> None:
        """Periodically refresh one feed."""
        while True:
            await asyncio.sleep(feed_cfg.refresh_interval_seconds)
            await self._load_feed(feed_cfg)

    async def _load_feed(self, feed_cfg: FeedConfig) -> None:
        """Load feed from Redis (fast path) or download (slow path)."""
        # Fast path: load from Redis if available
        cidrs = await self._load_from_redis(feed_cfg.name)
        if cidrs is not None:
            count = self._mgr.load_cidrs(cidrs, feed_cfg.name, feed_cfg)
            logger.info(
                json.dumps({
                    "type": "system", "level": "INFO",
                    "subsystem": "blocklist", "event": "feed_loaded_from_redis",
                    "feed": feed_cfg.name, "entries": count,
                })
            )
            return

        # Slow path: try leader election, download if winner
        won = await self._try_become_leader(feed_cfg)
        if won:
            await self._download_and_store(feed_cfg)
        else:
            # Wait for leader to populate Redis (up to 30s)
            for _ in range(30):
                await asyncio.sleep(1)
                cidrs = await self._load_from_redis(feed_cfg.name)
                if cidrs is not None:
                    self._mgr.load_cidrs(cidrs, feed_cfg.name, feed_cfg)
                    return
            # Give up — fail open, trie remains empty/stale
            logger.warning(
                json.dumps({
                    "type": "system", "level": "WARN",
                    "subsystem": "blocklist", "event": "feed_load_timeout",
                    "feed": feed_cfg.name,
                })
            )

    async def _load_from_redis(self, feed_name: str) -> Optional[list[str]]:
        """Return CIDR list from Redis, or None if absent."""
        if not self._redis:
            return None
        try:
            raw = await self._redis.get(f"blocklist:cidrs:{feed_name}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    async def _try_become_leader(self, feed_cfg: FeedConfig) -> bool:
        """SET NX leader key. Returns True if this instance is the leader."""
        if not self._redis:
            return True  # No Redis → always download
        try:
            key = f"leader:blocklist_download:{feed_cfg.name}"
            ttl = max(1, feed_cfg.refresh_interval_seconds // 2)
            result = await self._redis.set(
                key, self._instance_id, nx=True, ex=ttl
            )
            return result is not None
        except Exception:
            return True  # Redis failure → act as leader (fail open)

    async def _download_and_store(self, feed_cfg: FeedConfig) -> None:
        """Download feed, parse, load trie, and write to Redis."""
        if not AIOHTTP_AVAILABLE:
            logger.error(
                json.dumps({
                    "type": "system", "level": "ERROR",
                    "subsystem": "blocklist", "event": "feed_download_failed",
                    "feed": feed_cfg.name, "error": "aiohttp not installed",
                    "entries_retained": self._mgr.entry_count(feed_cfg.name),
                })
            )
            return

        t0 = time.monotonic()
        last_etag = await self._get_etag(feed_cfg.name)
        headers = {}
        if last_etag:
            headers["If-None-Match"] = last_etag

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    feed_cfg.url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 304:
                        logger.debug(
                            "blocklist | event=etag_hit | feed=%s", feed_cfg.name
                        )
                        return

                    if resp.status != 200:
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history, status=resp.status
                        )

                    text = await resp.text()
                    new_etag = resp.headers.get("ETag")

            cidrs = parse_feed(text, feed_cfg.format)
            count = self._mgr.load_cidrs(cidrs, feed_cfg.name, feed_cfg)
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            # Write to Redis for non-leader instances
            await self._store_to_redis(feed_cfg, cidrs, new_etag)

            _BLOCKLIST_LAST_REFRESH.labels(feed=feed_cfg.name).set(time.time())
            logger.info(
                json.dumps({
                    "type": "system", "level": "INFO",
                    "subsystem": "blocklist", "event": "feed_refreshed",
                    "feed": feed_cfg.name, "entries": count,
                    "elapsed_ms": elapsed_ms,
                })
            )

        except Exception as exc:
            _BLOCKLIST_DOWNLOAD_ERRORS.labels(feed=feed_cfg.name).inc()
            logger.error(
                json.dumps({
                    "type": "system", "level": "ERROR",
                    "subsystem": "blocklist", "event": "feed_download_failed",
                    "feed": feed_cfg.name,
                    "http_status": getattr(exc, "status", None),
                    "error": str(exc),
                    "entries_retained": self._mgr.entry_count(feed_cfg.name),
                })
            )

    async def _get_etag(self, feed_name: str) -> Optional[str]:
        """Retrieve stored ETag from Redis."""
        if not self._redis:
            return None
        try:
            raw = await self._redis.get(f"blocklist:etag:{feed_name}")
            return raw.decode() if isinstance(raw, bytes) else raw
        except Exception:
            return None

    async def _store_to_redis(
        self,
        feed_cfg: FeedConfig,
        cidrs: list[str],
        etag: Optional[str],
    ) -> None:
        """Persist CIDR list and ETag to Redis for non-leader instances."""
        if not self._redis:
            return
        ttl = feed_cfg.refresh_interval_seconds + 1800
        try:
            await self._redis.setex(
                f"blocklist:cidrs:{feed_cfg.name}", ttl, json.dumps(cidrs)
            )
            if etag:
                await self._redis.setex(
                    f"blocklist:etag:{feed_cfg.name}", ttl, etag
                )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "type": "system", "level": "WARN",
                    "subsystem": "blocklist", "event": "redis_write_failed",
                    "feed": feed_cfg.name, "error": str(exc),
                })
            )
