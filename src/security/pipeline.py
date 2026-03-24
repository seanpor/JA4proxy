"""Connection pipeline: bypass checks → signal collection → scoring → action.

This module is the central integration point for all phases. Every
connection passes through :meth:`Pipeline.process` exactly once.

Pipeline stages
---------------
1. **Bypass checks** — checked in order; first match short-circuits the
   pipeline and returns immediately without scoring.
2. **Signal collection** — all enabled signal modules run and produce
   :class:`~src.security.risk_scorer.RiskSignal` objects. (Populated by
   Phases 3–12; stub in Phase 0.)
3. **Composite scoring** — :class:`~src.security.risk_scorer.RiskScorer`
   aggregates signals into a 0–100 score. (Added in Phase 1.)
4. **Action decision** — :class:`~src.security.action_decider.ActionDecider`
   maps score + dial → final action string. (Added in Phase 1.)

Bypass check order (per ``security_policy`` config)
----------------------------------------------------
  1. ``static_ip_allowlist``   — IP or CIDR match → ALLOW
  2. ``alpn_browser_bypass``   — ALPN is h2 or h1 → ALLOW
  3. ``ja4_whitelist_bypass``  — JA4 in whitelist set → ALLOW
  4. ``mtls_bypass``           — Valid client cert present → ALLOW
  5. ``ja4_blacklist_bypass``  — JA4 in blacklist set → BLOCK
  6. ``country_blacklist_bypass`` — GeoIP country in blocklist → BLOCK
                                   (stub until Phase 6)

If a bypass is disabled in ``security_policy`` config, the corresponding
check is skipped and the connection falls through to the scorer.

Log format (§2a of docs/STYLE_GUIDE.md)
----------------------------------------
Every connection produces exactly one decision line::

    ALLOW    | 142.250.80.1  | score=12  | dial=75 | signals=[dga(+7)]
    BYPASS   | 142.250.80.1  | score=N/A | dial=75 | bypass=alpn_browser
    MONITOR  | 91.108.4.1    | score=61  | dial=0  | signals=[...] | would=flag@25,tarpit@50

JSON machine-readable log (one per connection)::

    {"type":"connection","verb":"ALLOW","ip":"...","score":12,"dial":75,
     "action":"allow","signals":[{"name":"dga","score":7}]}
    {"type":"connection","verb":"BYPASS","ip":"...","score":null,
     "bypass":"alpn_browser","signals":[]}
    {"type":"connection","verb":"MONITOR","ip":"...","score":61,"dial":0,
     "counterfactual":{"action_at_25":"flag","action_at_50":"tarpit",...}}
"""

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from prometheus_client import Counter, Gauge

from .abuseipdb import AbuseIPDBChecker, AbuseIPDBConfig
from .asn_classifier import ASNClassifier
from .beaconing_detector import BeaconingDetector
from .blocklists import BlocklistManager, FeedConfig
from .dns_enrichment import DNSEnrichment
from .mtls import MTLSHandler
from .rate_strategy import RateLimitStrategy, StrategyConfig
from .rate_tracker import MultiStrategyRateTracker
from .rdap_enrichment import RDAPEnricher
from .sni_analyzer import SNIAnalyzer
from .tcp_analyzer import TCPAnalyzer
from .tls_enforcer import TLSEnforcer

if TYPE_CHECKING:
    from ..cache.local_cache import LocalCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_ALLOWLIST_HITS = Counter(
    "ja4proxy_static_allowlist_hits_total",
    "Connections matched by the static IP allowlist bypass",
)

_CONNECTIONS = Counter(
    "ja4proxy_connections_total",
    "Connections by final action",
    ["action"],
)

_DIAL_CURRENT = Gauge("ja4proxy_dial_current", "Current dial value 0–100")

_COUNTERFACTUAL = Counter(
    "ja4proxy_monitor_counterfactual_total",
    "Would-have-taken actions per counterfactual dial value",
    ["action", "dial"],
)

_DIAL_CHANGE_REJECTED = Counter(
    "ja4proxy_dial_change_rejected_total",
    "Dial changes rejected by the increment limit",
)

_DIAL_CHANGES = Counter("ja4proxy_dial_changes_total", "Successful dial value changes")

_RATE_LIMIT_SIGNALS = Counter(
    "ja4proxy_rate_limit_signals_total",
    "Rate limit threshold crossings by strategy and level",
    ["strategy", "level"],
)

_RATE_LIMIT_BANS = Counter(
    "ja4proxy_rate_limit_bans_total",
    "Connections immediately blocked due to active rate-limit ban",
    ["strategy"],
)

_ANALYTICS_SIGNALS = Counter(
    "ja4proxy_analytics_signals_total",
    "Analytics cross-instance signals by type",
    ["signal_type"],
)

_SIGNAL_SKIPPED = Counter(
    "ja4proxy_signal_skipped_total",
    "Signals skipped due to expected dependency failures",
    ["module", "reason"],
)

_SIGNAL_ERROR = Counter(
    "ja4proxy_signal_error_total",
    "Signals failed due to unexpected internal errors",
    ["module"],
)

_PIPELINE_UNEXPECTED_ERRORS = Counter(
    "ja4proxy_pipeline_unexpected_errors_total",
    "Unexpected errors reaching the top-level pipeline handler (should always be 0)",
    ["phase"],
)

_EXCEPTION_HANDLED = Counter(
    "ja4proxy_exception_handled_total",
    "All caught exceptions by module and exception type",
    ["module", "exception_type"],
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

# Verb tokens — 8 chars, uppercase, right-padded (§2a of STYLE_GUIDE)
_VERBS: dict[str, str] = {
    "allow": "ALLOW   ",
    "flag": "FLAG    ",
    "rate_limit": "RATELMT ",
    "tarpit": "TARPIT  ",
    "block": "BLOCK   ",
    "ban": "BAN     ",
    "bypass": "BYPASS  ",
    "monitor": "MONITOR ",
}


from .models import ConnectionContext, PipelineResult

# ---------------------------------------------------------------------------
# Static allowlist
# ---------------------------------------------------------------------------


class StaticAllowlist:
    """In-process static IP allowlist backed by ipaddress CIDR matching.

    Loaded from ``static_allowlist.ips`` in proxy.yml and from the
    ``static:allowlist`` Redis SET (for UI-added entries). Config-file
    entries are authoritative. Redis-only entries are honoured but logged
    with a warning.

    Both individual IPs and CIDR ranges are supported. IPv4 and IPv6
    are supported natively via the ipaddress stdlib module.
    """

    def __init__(self, config: dict) -> None:
        self._entries: list[
            tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict]
        ] = []
        self.reload(config)

    def reload(self, config: dict) -> None:
        """Reload allowlist entries from config. Call on hot reload."""
        entries = []
        allowlist_cfg = config.get("static_allowlist", {})
        if not allowlist_cfg.get("enabled", True):
            self._entries = []
            return

        for entry in allowlist_cfg.get("ips", []):
            raw_ip = entry.get("ip", "")
            if not raw_ip:
                continue
            try:
                # ip_network handles both IPs and CIDR prefixes
                network = ipaddress.ip_network(raw_ip, strict=False)
                entries.append((network, entry))
            except ValueError:
                logger.warning(
                    "static_allowlist | event=invalid_entry | ip=%r | skipping",
                    raw_ip,
                )

        self._entries = entries

    def match(self, ip: str) -> dict | None:
        """Return the matching allowlist entry dict, or None if no match.

        Args:
            ip: Canonical IP address string.

        Returns:
            The entry dict from config (contains ``ip``, ``comment``, etc.)
            or None if the IP is not allowlisted.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for network, entry in self._entries:
            if addr in network:
                return entry
        return None

    def add_from_redis(self, raw_ip: str) -> None:
        """Add a UI-sourced entry from Redis (logged as potentially stale)."""
        try:
            network = ipaddress.ip_network(raw_ip, strict=False)
            entry = {"ip": raw_ip, "comment": "Redis-sourced (UI-added)"}
            self._entries.append((network, entry))
            logger.warning(
                "static_allowlist | event=redis_only_entry | ip=%s | "
                "entry not found in config — may be stale",
                raw_ip,
            )
        except ValueError:
            logger.warning(
                "static_allowlist | event=invalid_redis_entry | ip=%r", raw_ip
            )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Main connection processing pipeline.

    Instantiated once per proxy process. Thread-safe for asyncio use.

    Args:
        config: Full proxy.yml config dict (the ``security_policy`` section
                is read here; other sections are read by individual modules).
        local_cache: The process-local :class:`~src.cache.local_cache.LocalCache`.
        redis_client: Sync Redis client for stream events (Phase 12 upgrades to async).
        tracing: Optional OpenTelemetry tracer wrapper (Phase 16).
        collectors: Optional list of :class:`~src.security.protocols.SignalCollector`
            instances.  When supplied (typically in tests) ``_collect_signals``
            routes through these instead of the built-in modules.  When ``None``
            (production default) the pipeline builds and owns all modules itself.

    The pipeline is intentionally additive: new phases plug in by adding
    signal modules to ``_collect_signals()`` and the scorer/decider are
    wired into ``_score_connection()``.
    """

    def __init__(
        self,
        config: dict,
        local_cache: "LocalCache",
        redis_client: object,
        tracing: Any = None,
        collectors: list | None = None,
    ) -> None:
        self._config = config
        self._cache = local_cache
        self._redis = redis_client
        self._policy = config.get("security_policy", {})
        # Phase 16j: optional OpenTelemetry tracer (noop when None / disabled)
        self._tracer = tracing
        # Optional injected collectors (used in tests for isolation).
        # When set, _collect_signals routes through these instead of built-ins.
        self._injected_collectors: list | None = collectors
        self._allowlist = StaticAllowlist(config)
        # In-process sets for O(1) JA4 lookup on hot path
        # Populated from Redis on startup and updated via pub/sub
        self._whitelist: set[str] = set()
        self._blacklist: set[str] = set()
        # Phase 1 components — set by update_scorer() after Phase 1 init
        self._scorer: Any = None
        self._decider: Any = None
        # Phase 2: counterfactual reporting config
        monitor_cfg = config.get("monitor_mode", {})
        self._cf_dials: list[int] = monitor_cfg.get(
            "counterfactual_thresholds", [25, 50, 75, 100]
        )
        self._log_counterfactuals: bool = monitor_cfg.get("log_counterfactuals", True)
        # Phase 3: TLS version and cipher suite enforcement
        self._tls_enforcer = TLSEnforcer(config)
        # Phase 4: SNI analysis
        self._sni_analyzer = SNIAnalyzer(config)
        # Phase 5a: TCP & mTLS
        self._tcp_analyzer = TCPAnalyzer(config, redis_client)
        self._mtls_handler = MTLSHandler(config)
        # Phase 6: ASN & Datacenter Classification
        self._asn_classifier = ASNClassifier(config, redis_client)
        # Phase 7: DNS/FCrDNS enrichment (fire-and-forget queue)
        self._dns_enrichment = DNSEnrichment(config, redis_client)
        # Phase 8: Spamhaus DROP/EDROP blocklist trie
        self._blocklist_manager = BlocklistManager()
        self._load_blocklist_feeds(config)
        # Rate limiting: multi-strategy sliding window tracker (by_ip, by_ja4, by_ip+ja4)
        # Runs in _collect_signals(); results feed into the risk scorer.
        try:
            self._rate_tracker: MultiStrategyRateTracker | None = MultiStrategyRateTracker(
                redis_client, config
            )
        except Exception as exc:
            logger.warning("rate_tracker | event=init_failed | error=%s — rate limiting disabled", exc)
            self._rate_tracker = None
        # Phase 9: Beaconing detector (IAT coefficient of variation)
        self._beaconing_detector = BeaconingDetector(config, redis_client, local_cache)
        # Phase 10: AbuseIPDB checker (three-tier cache; fire-and-forget background workers)
        # The aiohttp session and full startup are handled by ProxyServer.
        # Pipeline holds a reference; start()/stop() called by ProxyServer.
        self._abuseipdb_checker: AbuseIPDBChecker | None = None
        # Phase 11: RDAP enrichment (offline enrichment; background workers).
        # start()/stop() called by ProxyServer.
        self._rdap_enricher: RDAPEnricher | None = None
        # Phase 16: JA4X fingerprint lists (parallel structure to JA4 lists)
        self._ja4x_whitelist: set[str] = set()
        self._ja4x_blacklist: set[str] = set()

    def _load_blocklist_feeds(self, config: dict) -> None:
        """Load any static/pre-populated blocklist feeds from config."""
        bl_cfg = config.get("blocklists", {})
        for feed in bl_cfg.get("feeds", []):
            if not feed.get("enabled", True):
                continue
            feed_cfg = FeedConfig(
                name=feed["name"],
                url=feed.get("url", ""),
                format=feed.get("format", "spamhaus"),
                is_bypass=feed.get("is_bypass", True),
                action=feed.get("action", "block"),
                score=feed.get("score", 60),
                refresh_interval_seconds=feed.get("refresh_interval_seconds", 43200),
                enabled=True,
            )
            # Static CIDRs (for testing / offline use)
            static_cidrs = feed.get("static_cidrs", [])
            if static_cidrs:
                self._blocklist_manager.load_cidrs(static_cidrs, feed["name"], feed_cfg)

    def update_scorer(self, scorer: Any, decider: Any) -> None:
        """Wire in Phase 1 scorer and decider. Called after Phase 1 init."""
        self._scorer = scorer
        self._decider = decider

    def set_abuseipdb_checker(self, checker: AbuseIPDBChecker | None) -> None:
        """Wire in the Phase 10 AbuseIPDB checker. Called after start()."""
        self._abuseipdb_checker = checker

    def set_rdap_enricher(self, enricher: RDAPEnricher | None) -> None:
        """Wire in the Phase 11 RDAP enricher. Called after start()."""
        self._rdap_enricher = enricher

    def _get_analytics_signals(self, ip: str) -> list:
        """Read analytics cross-instance signals from Redis (Phase 12).

        Checks for campaign (+35) and slow-scan (+30) findings written by the
        Analytics Node for the /24 (IPv4) or /48 (IPv6) subnet of *ip*.

        Results are cached locally for 60 s to avoid Redis round-trips on every
        connection.  Always fails open — any exception returns an empty list.
        """
        from .models import RiskSignal

        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
            else:
                subnet = str(ipaddress.IPv6Network(f"{ip}/48", strict=False))
        except ValueError:
            return []

        cached = self._cache.analytics_signals.get(subnet)
        if cached is not None:
            return cached

        signals: list = []
        try:
            if self._redis is None:
                self._cache.analytics_signals.set(subnet, signals)
                return signals

            campaign_val = self._redis.get(f"analytics:campaign:{subnet}")
            if campaign_val is not None and isinstance(campaign_val, (bytes, str)):
                signals.append(
                    RiskSignal(
                        name="analytics_campaign",
                        score=35,
                        reason=f"Analytics: campaign activity from subnet {subnet}",
                    )
                )
                _ANALYTICS_SIGNALS.labels(signal_type="campaign").inc()

            slowscan_val = self._redis.get(f"analytics:slowscan:{subnet}")
            if slowscan_val is not None and isinstance(slowscan_val, (bytes, str)):
                signals.append(
                    RiskSignal(
                        name="analytics_slowscan",
                        score=30,
                        reason=f"Analytics: slow-scan activity from subnet {subnet}",
                    )
                )
                _ANALYTICS_SIGNALS.labels(signal_type="slowscan").inc()
        except (asyncio.TimeoutError, ConnectionError) as exc:
            # Fail open — analytics signals are enrichment only; any failure returns []
            logger.error(
                "analytics | event=internal_error | subnet=%s | error=%s",
                subnet,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="analytics", reason="timeout_or_conn_error").inc()
            return []
        except Exception as exc:
            # Fail open — analytics signals are enrichment only; any failure returns []
            logger.error(
                "analytics | event=internal_error | subnet=%s | error=%s",
                subnet,
                exc,
            )
            return []

        self._cache.analytics_signals.set(subnet, signals)
        return signals

    def update_sets(self, whitelist: set[str], blacklist: set[str]) -> None:
        """Replace in-process JA4 sets. Called on startup and pub/sub update."""
        self._whitelist = whitelist
        self._blacklist = blacklist

    def update_ja4x_sets(self, whitelist: set[str], blacklist: set[str]) -> None:
        """Replace in-process JA4X sets. Called on startup and pub/sub update."""
        self._ja4x_whitelist = whitelist
        self._ja4x_blacklist = blacklist

    def on_config_reload(self, new_config: dict) -> None:
        """Apply new config on hot reload. Registered with ConfigLoader."""
        self._config = new_config
        self._policy = new_config.get("security_policy", {})
        self._allowlist.reload(new_config)
        self._tls_enforcer.on_config_reload(new_config)
        self._sni_analyzer.on_config_reload(new_config)

    async def process(self, ctx: ConnectionContext) -> PipelineResult:
        """Process one connection through the full pipeline.

        Returns a :class:`PipelineResult` describing the action to take.
        Never raises — all errors result in an allow decision (fail open).
        When tracing is enabled, emits a ``pipeline.process`` span with
        connection attributes and the final action/score.
        """
        if self._tracer is not None:
            tracer = self._tracer.get_tracer("ja4proxy.pipeline")
            with tracer.start_as_current_span("pipeline.process") as span:
                span.set_attribute("client.ip", ctx.client_ip)
                span.set_attribute("ja4", ctx.ja4 or "")
                if ctx.ja4x:
                    span.set_attribute("ja4x", ctx.ja4x)
                if ctx.sni:
                    span.set_attribute("sni", ctx.sni)
                try:
                    result = await self._process_inner(ctx)
                except Exception as exc:  # noqa: BLE001
                    span.record_exception(exc)
                    result = PipelineResult(
                        action="allow", score=0, signals=[], dial=self._cache.dial
                    )
                    self._emit_log(ctx, result)
                span.set_attribute("action", result.action)
                if result.score is not None:
                    span.set_attribute("risk.score", result.score)
                return result

        try:
            return await self._process_inner(ctx)
        except Exception as exc:  # noqa: BLE001
            _PIPELINE_UNEXPECTED_ERRORS.labels(phase="process").inc()
            _EXCEPTION_HANDLED.labels(
                module="pipeline", exception_type=type(exc).__name__
            ).inc()
            logger.error(
                "pipeline | event=unexpected_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            # Fail open: an error in the pipeline must not block real users
            result = PipelineResult(
                action="allow", score=0, signals=[], dial=self._cache.dial
            )
            self._emit_log(ctx, result)
            return result

    # ------------------------------------------------------------------
    # Internal pipeline stages
    # ------------------------------------------------------------------

    async def _process_inner(self, ctx: ConnectionContext) -> PipelineResult:
        # ── 1. ALLOW bypasses ──────────────────────────────────────────
        bypass = self._check_allow_bypasses(ctx)
        if bypass is not None:
            _CONNECTIONS.labels(action="bypass_allow").inc()
            self._emit_log(ctx, bypass)
            return bypass

        # ── 2. BLOCK bypasses ──────────────────────────────────────────
        block = self._check_block_bypasses(ctx)
        if block is not None:
            _CONNECTIONS.labels(action="bypass_block").inc()
            self._emit_log(ctx, block)
            return block

        # ── 3. TLS enforcement (Phase 3) ───────────────────────────────
        # check() returns None → hard block; list → signals (may be empty)
        tls_signals = self._tls_enforcer.check(ctx.tls_version, ctx.cipher_list)
        if tls_signals is None:
            block = PipelineResult(
                action="block", bypassed=True, bypass_reason="tls_version"
            )
            _CONNECTIONS.labels(action="bypass_block").inc()
            self._emit_log(ctx, block)
            return block

        # ── 4. Signal collection (Phases 4–12 add signals here) ────────
        signals: list = list(tls_signals)  # start with Phase 3 TLS signals
        signals.extend(await self._collect_signals(ctx))

        # ── 5. Score + decide ──────────────────────────────────────────
        score, action, scored_signals, cf = self._score_connection(signals)
        dial = self._cache.dial
        _DIAL_CURRENT.set(dial)

        if dial == 0:
            # Monitor mode: always allow, log what would happen at higher dials
            result = PipelineResult(
                action="allow",
                score=score,
                signals=scored_signals,
                dial=dial,
                counterfactuals=cf,
            )
            self._emit_log(ctx, result)
            # Increment counterfactual Prometheus counters
            if self._log_counterfactuals and isinstance(cf, dict):
                for d, act in cf.items():
                    _COUNTERFACTUAL.labels(action=act, dial=str(d)).inc()
        else:
            result = PipelineResult(
                action=action,
                score=score,
                signals=scored_signals,
                dial=dial,
                counterfactuals=cf,
            )
            self._emit_log(ctx, result)

        _CONNECTIONS.labels(action=result.action).inc()
        # Fire-and-forget stream event (Phase 12 analytics consumes this)
        asyncio.create_task(self._emit_stream_event(ctx, result))
        # Phase 9: Record connection timing for beaconing analysis (after action decided)
        asyncio.create_task(
            self._beaconing_detector.maybe_record(
                ctx.client_ip, ctx.ja4 or "", ctx.alpn or "", result.action
            )
        )
        return result

    def _check_allow_bypasses(self, ctx: ConnectionContext) -> PipelineResult | None:
        """Return an ALLOW PipelineResult if any active ALLOW bypass matches."""
        # 1. Static IP allowlist
        if self._policy.get("static_ip_allowlist", {}).get("enabled", True):
            entry = self._allowlist.match(ctx.client_ip)
            if entry is not None:
                _ALLOWLIST_HITS.inc()
                return PipelineResult(
                    action="allow",
                    bypassed=True,
                    bypass_reason="static_allowlist",
                )

        # 2. ALPN browser bypass (h2 / h1 = modern browser traffic)
        if self._policy.get("alpn_browser_bypass", {}).get("enabled", True):
            if ctx.alpn in ("h2", "h1"):
                return PipelineResult(
                    action="allow",
                    bypassed=True,
                    bypass_reason="alpn_browser",
                )

        # 3. JA4 whitelist bypass
        if self._policy.get("ja4_whitelist_bypass", {}).get("enabled", True):
            if ctx.ja4 and ctx.ja4 in self._whitelist:
                return PipelineResult(
                    action="allow",
                    bypassed=True,
                    bypass_reason="ja4_whitelist",
                )

        # 3b. JA4X whitelist bypass (Phase 16)
        ja4x_cfg = self._config.get("fingerprinting", {}).get("ja4x", {})
        if ja4x_cfg.get("enabled", True):
            if ctx.ja4x and ctx.ja4x in self._ja4x_whitelist:
                return PipelineResult(
                    action="allow",
                    bypassed=True,
                    bypass_reason="ja4x_whitelist",
                )

        # 4. mTLS bypass
        if self._policy.get("mtls_bypass", {}).get("enabled", True):
            if self._mtls_handler.verify_client_cert(ctx):
                return PipelineResult(
                    action="allow",
                    bypassed=True,
                    bypass_reason="mtls",
                )
        return None

    def _check_block_bypasses(self, ctx: ConnectionContext) -> PipelineResult | None:
        """Return a BLOCK PipelineResult if any active BLOCK bypass matches."""
        # 5. JA4 blacklist bypass
        if self._policy.get("ja4_blacklist_bypass", {}).get("enabled", True):
            if ctx.ja4 and ctx.ja4 in self._blacklist:
                return PipelineResult(
                    action="block",
                    bypassed=True,
                    bypass_reason="ja4_blacklist",
                )

        # 6. Country blacklist bypass (stub — GeoIP added in Phase 6)
        if self._policy.get("country_blacklist_bypass", {}).get("enabled", True):
            if ctx.country is not None:
                blocked_countries: list[str] = self._config.get("geoip", {}).get(
                    "country_blacklist", []
                )
                if ctx.country in blocked_countries:
                    return PipelineResult(
                        action="block",
                        bypassed=True,
                        bypass_reason="country_blacklist",
                    )

        # 7. Spamhaus / blocklist bypass (Phase 8)
        if self._policy.get("spamhaus_bypass", {}).get("enabled", True):
            blocked, feed_name = self._blocklist_manager.is_blocked(ctx.client_ip)
            if blocked:
                # Only bypass if the matched feed is a bypass feed
                cfg = self._blocklist_manager._feed_configs.get(feed_name)
                if cfg is None or cfg.is_bypass:
                    return PipelineResult(
                        action="block",
                        bypassed=True,
                        bypass_reason=f"spamhaus_{feed_name}",
                    )

        return None

    async def _collect_signals(self, ctx: ConnectionContext) -> list:
        """Collect risk signals from enabled signal modules (Phases 4–12).

        Phase 3 (TLS enforcement) is handled before this method is called.
        Each subsequent phase adds its module call here. Modules run
        concurrently where possible.

        Expected dependency failures (Redis down, DNS timeout) result in a
        fail-open (signal skipped) to prevent blocking legitimate users due
        to infrastructure issues. Unexpected logic errors are logged as
        errors and also result in a skip.

        When ``self._injected_collectors`` is set (test injection), this
        method iterates those instead of calling built-in modules.  This
        allows unit-testing the pipeline in complete isolation without
        mocking all 14 signal collectors.
        """
        # Injection path — used in tests for pipeline isolation
        if self._injected_collectors is not None:
            signals = []
            for collector in self._injected_collectors:
                try:
                    signal = await collector.get_signal(ctx)
                    if signal is not None:
                        signals.append(signal)
                except Exception as exc:  # noqa: BLE001
                    _SIGNAL_ERROR.labels(module=type(collector).__name__).inc()
                    logger.error(
                        "pipeline | event=collector_error | collector=%s | error=%s",
                        type(collector).__name__,
                        exc,
                        exc_info=True,
                    )
            return signals

        signals = []

        # Phase 16: JA4X cert extraction from mTLS client cert (if not already set)
        if ctx.ja4x is None and ctx.client_certificate is not None:
            ctx.ja4x = self._extract_ja4x_from_cert(ctx.client_certificate)

        # Phase 16: JA4X blacklist signal (score contribution, not hard block)
        ja4x_cfg = self._config.get("fingerprinting", {}).get("ja4x", {})
        if ja4x_cfg.get("enabled", True) and ctx.ja4x and ctx.ja4x in self._ja4x_blacklist:
            from .models import RiskSignal
            blacklist_score = ja4x_cfg.get("blacklist_score", 80)
            signals.append(RiskSignal(
                name="ja4x_blacklist",
                score=blacklist_score,
                reason=f"JA4X {ctx.ja4x} in blacklist",
            ))

        # Phase 11: Record browser subnet for block expansion guard 3.
        # Fire-and-forget: never awaited on the hot path.
        if ctx.alpn in ("h2", "h1") and self._rdap_enricher is not None:
            asyncio.create_task(
                self._rdap_enricher.record_browser_subnet(ctx.client_ip)
            )

        # Phase 4: SNI analysis
        try:
            sni_signals = self._sni_analyzer.analyze(ctx.sni)
            signals.extend(sni_signals)
        except Exception as exc:
            logger.error(
                "sni_analyzer | event=analysis_error | ip=%s | sni=%s | error=%s",
                ctx.client_ip,
                getattr(ctx, "sni", "unknown"),
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="sni_analyzer").inc()

        # Phase 5a: TCP analysis
        try:
            tcp_signals = await self._tcp_analyzer.analyze(ctx)
            signals.extend(tcp_signals)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.warning(
                "tcp_analyzer | event=dependency_failure | ip=%s | error=%s",
                ctx.client_ip,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="tcp_analyzer", reason="timeout_or_conn_error").inc()
        except Exception as exc:
            logger.error(
                "tcp_analyzer | event=analysis_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="tcp_analyzer").inc()

        # Phase 6: ASN classification
        try:
            asn_signals = await self._asn_classifier.signals(ctx)
            signals.extend(asn_signals)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.warning(
                "asn_classifier | event=dependency_failure | ip=%s | error=%s",
                ctx.client_ip,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="asn_classifier", reason="timeout_or_conn_error").inc()
        except Exception as exc:
            logger.error(
                "asn_classifier | event=analysis_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="asn_classifier").inc()

        # Phase 7: DNS/FCrDNS enrichment
        try:
            dns_signal = await self._dns_enrichment.get_signal(ctx.client_ip)
            if dns_signal is not None:
                signals.append(dns_signal)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.warning(
                "dns_enrichment | event=dependency_failure | ip=%s | error=%s",
                ctx.client_ip,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="dns_enrichment", reason="timeout_or_conn_error").inc()
        except Exception as exc:
            logger.error(
                "dns_enrichment | event=analysis_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="dns_enrichment").inc()

        # Phase 8: Non-bypass blocklist signals (is_bypass=false feeds)
        try:
            bl_signals = self._blocklist_manager.get_signals(ctx.client_ip)
            signals.extend(bl_signals)
        except Exception as exc:
            logger.error(
                "blocklist | event=signal_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="blocklist").inc()

        # Rate limiting: multi-strategy sliding window (by_ip, by_ja4, by_ip+ja4 pair)
        if self._rate_tracker is not None:
            try:
                metrics = await self._rate_tracker.track_connection(
                    ja4=ctx.ja4 or "unknown",
                    ip=ctx.client_ip,
                    window="short",
                )
                _level_scores = {
                    "suspicious": 20,
                    "block": 60,
                    "ban": 90,
                }
                # Determine per-strategy threshold crossings
                strategy_levels: dict[str, str] = {}
                for strategy, m in metrics.items():
                    cfg = self._rate_tracker.get_strategy_config(strategy)
                    cps = m.connections_per_second
                    if cps >= cfg.ban_threshold:
                        strategy_levels[strategy.value] = "ban"
                    elif cps >= cfg.block_threshold:
                        strategy_levels[strategy.value] = "block"
                    elif cps >= cfg.suspicious_threshold:
                        strategy_levels[strategy.value] = "suspicious"

                if strategy_levels:
                    # Majority policy: pick the level that ≥2 strategies agree on
                    from collections import Counter as _Counter
                    level_counts = _Counter(strategy_levels.values())
                    majority_level = None
                    for lvl in ("ban", "block", "suspicious"):
                        if level_counts.get(lvl, 0) >= 2:
                            majority_level = lvl
                            break
                    if majority_level is None and "ban" in strategy_levels.values():
                        majority_level = "ban"

                    if majority_level:
                        score = _level_scores[majority_level]
                        from .models import RiskSignal
                        signals.append(RiskSignal(
                            name=f"rate_limit_{majority_level}",
                            score=score,
                            reason=f"Rate limit: {majority_level} — {len(strategy_levels)} strategies",
                        ))
                        _RATE_LIMIT_SIGNALS.labels(
                            strategy="majority", level=majority_level
                        ).inc()
                        for strat, lvl in strategy_levels.items():
                            _RATE_LIMIT_SIGNALS.labels(strategy=strat, level=lvl).inc()
            except (asyncio.TimeoutError, ConnectionError) as exc:
                logger.warning(
                    "rate_limiter | event=dependency_failure | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                )
                _SIGNAL_SKIPPED.labels(module="rate_limiter", reason="timeout_or_conn_error").inc()
            except Exception as exc:
                logger.error(
                    "rate_limiter | event=signal_error | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                    exc_info=True,
                )
                _SIGNAL_ERROR.labels(module="rate_limiter").inc()

        # Phase 9: Beaconing detection (IAT coefficient of variation)
        try:
            beacon_signal = await self._beaconing_detector.get_signal(ctx)
            if beacon_signal is not None:
                signals.append(beacon_signal)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.warning(
                "beaconing_detector | event=dependency_failure | ip=%s | error=%s",
                ctx.client_ip,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="beaconing_detector", reason="timeout_or_conn_error").inc()
        except Exception as exc:
            logger.error(
                "beaconing_detector | event=analysis_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="beaconing_detector").inc()

        # Phase 10: AbuseIPDB reputation (three-tier cache; hot path never blocks)
        if self._abuseipdb_checker is not None:
            try:
                abuseipdb_signal = self._abuseipdb_checker.get_signal(ctx.client_ip)
                if abuseipdb_signal is not None:
                    signals.append(abuseipdb_signal)
            except (asyncio.TimeoutError, ConnectionError) as exc:
                logger.warning(
                    "abuseipdb | event=dependency_failure | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                )
                _SIGNAL_SKIPPED.labels(module="abuseipdb", reason="timeout_or_conn_error").inc()
            except Exception as exc:
                logger.error(
                    "abuseipdb | event=get_signal_error | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                    exc_info=True,
                )
                _SIGNAL_ERROR.labels(module="abuseipdb").inc()

        # Phase 11: RDAP enrichment (called LAST; trigger_score is running subtotal)
        if self._rdap_enricher is not None:
            try:
                running_score = sum(
                    s.score for s in signals if hasattr(s, "score")
                )
                rdap_signals = self._rdap_enricher.get_signal(
                    ctx.client_ip, running_score
                )
                signals.extend(rdap_signals)
            except (asyncio.TimeoutError, ConnectionError) as exc:
                logger.warning(
                    "rdap_enricher | event=dependency_failure | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                )
                _SIGNAL_SKIPPED.labels(module="rdap_enricher", reason="timeout_or_conn_error").inc()
            except Exception as exc:
                logger.error(
                    "rdap_enricher | event=get_signal_error | ip=%s | error=%s",
                    ctx.client_ip,
                    exc,
                    exc_info=True,
                )
                _SIGNAL_ERROR.labels(module="rdap_enricher").inc()

        # Phase 12: Analytics cross-instance signals (campaign detection, slow-scan)
        try:
            analytics_signals = self._get_analytics_signals(ctx.client_ip)
            signals.extend(analytics_signals)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.warning(
                "analytics | event=dependency_failure | ip=%s | error=%s",
                ctx.client_ip,
                exc,
            )
            _SIGNAL_SKIPPED.labels(module="analytics", reason="timeout_or_conn_error").inc()
        except Exception as exc:
            logger.error(
                "analytics | event=signal_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            _SIGNAL_ERROR.labels(module="analytics").inc()

        return signals

    def _extract_ja4x_from_cert(self, cert_der: bytes) -> str | None:
        """Extract JA4X fingerprint from DER-encoded X.509 certificate.

        Format: {issuer_hash}_{subject_hash}_{san_hash} where each hash is
        SHA-256 truncated to 12 hex chars of sorted, comma-joined field values.
        Returns None on any parse error (fail open).
        """
        try:
            import hashlib

            from cryptography import x509

            cert = x509.load_der_x509_certificate(cert_der)

            def _sorted_attrs(name: object) -> str:
                return ",".join(
                    sorted(f"{attr.oid.dotted_string}={attr.value}" for attr in name)  # type: ignore[union-attr]
                )

            issuer = _sorted_attrs(cert.issuer)
            subject = _sorted_attrs(cert.subject)

            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                san = ",".join(sorted(str(n) for n in san_ext.value))
            except x509.ExtensionNotFound:
                san = ""

            def _hash(s: str) -> str:
                if not s:
                    return "000000000000"
                return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]

            return f"{_hash(issuer)}_{_hash(subject)}_{_hash(san)}"
        except Exception as exc:
            logger.warning("pipeline | event=ja4x_extract_failed | error=%s", exc)
            return None

    def _score_connection(self, signals: list) -> tuple[int, str, list, dict]:
        """Map signals → (score, action, scored_signals, counterfactuals).

        Phase 0: no scorer wired in — returns (0, "allow", [], {}).
        Phase 1+: scorer + decider are wired in via update_scorer().

        Returns the scorer's processed signals (clamped, weighted) rather than
        the raw input so callers can populate PipelineResult with the final list.
        The 4th element is the counterfactuals dict from ActionDecider.counterfactuals().
        """
        if self._scorer is not None and self._decider is not None:
            assessment = self._scorer.score(signals)
            dial = self._cache.dial
            action = self._decider.decide(assessment.total_score, dial)
            cf = self._decider.counterfactuals(assessment.total_score, self._cf_dials)
            # Normalise cf to a plain dict (handles MagicMock in tests gracefully)
            if not isinstance(cf, dict):
                cf = {}
            return assessment.total_score, action, assessment.signals, cf
        return 0, "allow", [], {}

    # ------------------------------------------------------------------
    # Logging (§2a of STYLE_GUIDE)
    # ------------------------------------------------------------------

    def _emit_log(
        self,
        ctx: ConnectionContext,
        result: PipelineResult,
    ) -> None:
        """Emit the structured connection log line.

        Produces both a human-readable line and a JSON line on the same
        logger. The human-readable line matches §2a exactly.

        Monitor mode is detected when ``result.dial == 0`` and the connection
        was not bypassed.
        """
        dial_val = result.dial if result.dial is not None else self._cache.dial

        if result.bypassed:
            verb = "bypass"
            score_str = "N/A"
            detail = f"bypass={result.bypass_reason}"
        elif result.dial == 0 and not result.bypassed:
            # Monitor mode: log what would happen at counterfactual dial values
            verb = "monitor"
            score_str = str(result.score)
            signals_str = _format_signals(result.signals)
            cf = result.counterfactuals
            if cf and isinstance(cf, dict):
                would_parts = [
                    f"{act}@{d}" for d, act in sorted(cf.items()) if act != "allow"
                ]
                would_str = ",".join(would_parts) if would_parts else "allow@all"
            else:
                would_str = "allow@all"
            detail = f"signals={signals_str} | would={would_str}"
        else:
            verb = result.action
            score_str = str(result.score) if result.score is not None else "0"
            signals_str = _format_signals(result.signals)
            detail = f"signals={signals_str}"

        verb_token = _VERBS.get(verb, f"{verb.upper():<8}")

        human_line = (
            f"{verb_token} | {ctx.client_ip:<15} | score={score_str:<4} "
            f"| dial={dial_val} | {detail}"
        )
        logger.info(human_line)

        # Machine-readable JSON log
        json_doc: dict = {
            "type": "connection",
            "verb": verb_token.strip(),
            "ip": ctx.client_ip,
            "score": result.score,
            "dial": dial_val,
            "action": result.action,
            "signals": [
                {"name": s.name, "score": s.score}
                for s in result.signals
                if hasattr(s, "name")
            ],
        }
        if result.bypassed:
            json_doc["bypass"] = result.bypass_reason
        if (
            result.dial == 0
            and not result.bypassed
            and isinstance(result.counterfactuals, dict)
        ):
            json_doc["counterfactual"] = {
                f"action_at_{d}": act
                for d, act in sorted(result.counterfactuals.items())
            }
        # Phase 16: emit ja4x in log when config enables it and ja4x is available
        ja4x_cfg = self._config.get("fingerprinting", {}).get("ja4x", {})
        if ja4x_cfg.get("emit_in_logs", True) and ctx.ja4x is not None:
            json_doc["ja4x"] = ctx.ja4x

        logger.debug(json.dumps(json_doc))

    # ------------------------------------------------------------------
    # Stream events (Phase 2 — consumed by Phase 12 Analytics)
    # ------------------------------------------------------------------

    async def _emit_stream_event(
        self, ctx: ConnectionContext, result: PipelineResult
    ) -> None:
        """XADD one event to ``ja4proxy:events``. Swallows all errors.

        Uses the synchronous Redis client passed at init time (Phase 12 will
        upgrade to async). The sync call runs in the event loop thread;
        acceptable at Phase 2 scale as a fire-and-forget write.
        """
        try:
            cf = (
                result.counterfactuals
                if isinstance(result.counterfactuals, dict)
                else {}
            )
            fields: dict[str, str] = {
                "ip": ctx.client_ip,
                "ja4": ctx.ja4 or "",
                "risk_score": str(result.score) if result.score is not None else "",
                "action_taken": result.action,
                "dial_setting": str(result.dial or 0),
            }
            for d, act in cf.items():
                fields[f"action_at_{d}"] = act

            if hasattr(self._redis, "xadd"):
                self._redis.xadd(
                    "ja4proxy:events", fields, maxlen=100_000, approximate=True
                )
        except Exception as exc:
            logger.debug("stream | event=xadd_failed | error=%s", exc)


def _format_signals(signals: list) -> str:
    """Format the top-5 signals for the human-readable log line.

    Signals are sorted by absolute weighted contribution, descending.
    At most 5 are shown; ``...`` is appended if more exist.
    """
    if not signals:
        return "[]"

    # Handle both RiskSignal dataclass objects and plain dicts
    def score_of(s: Any) -> float:
        if hasattr(s, "score") and hasattr(s, "weight"):
            return abs(s.score * s.weight)
        if isinstance(s, dict):
            return abs(s.get("score", 0))
        return 0.0

    def name_of(s: Any) -> str:
        if hasattr(s, "name"):
            return s.name
        if isinstance(s, dict):
            return s.get("name", "?")
        return "?"

    def raw_score_of(s: Any) -> int:
        if hasattr(s, "score"):
            return int(s.score)
        if isinstance(s, dict):
            return int(s.get("score", 0))
        return 0

    sorted_sigs = sorted(signals, key=score_of, reverse=True)
    shown = sorted_sigs[:5]
    parts = [
        f"{name_of(s)}({'+' if raw_score_of(s) >= 0 else ''}{raw_score_of(s)})"
        for s in shown
    ]
    suffix = ", ..." if len(signals) > 5 else ""
    return "[" + ", ".join(parts) + suffix + "]"
