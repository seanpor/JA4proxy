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


@dataclass
class ConnectionContext:
    """Immutable snapshot of a connection's observable metadata.

    All signal modules receive this context. Fields are populated by the
    proxy as the TLS handshake progresses. Fields unavailable before a
    particular phase are left at their defaults.

    Attributes:
        client_ip: Canonical client IP (already normalised via canonical_ip).
        ja4: JA4 fingerprint string, or empty string if not yet computed.
        alpn: ALPN negotiated protocol ("h2", "h1", or None).
        has_valid_client_cert: True if a verified mTLS client cert was presented.
        sni: SNI hostname from the ClientHello, or None if absent.
        tls_version: TLS version integer (e.g. 0x0303 for TLS 1.2), or None.
        country: ISO-3166-1 alpha-2 country code from GeoIP, or None.
    """

    client_ip: str
    ja4: str = ""
    alpn: str | None = None
    has_valid_client_cert: bool = False
    sni: str | None = None
    tls_version: int | None = None
    country: str | None = None


@dataclass
class PipelineResult:
    """Result of processing one connection through the pipeline.

    Attributes:
        action: Final action string (allow|flag|rate_limit|tarpit|block|ban).
        bypassed: True if a bypass rule short-circuited the scorer.
        bypass_reason: Bypass label used in logs (e.g. "alpn_browser").
        score: Composite score 0–100, or None for bypassed connections.
        signals: List of RiskSignal dicts (name, score) for logging.
        dial: Dial value at decision time; None for bypassed connections.
        counterfactuals: Dict of {dial_value: action} for monitor-mode logging.
    """

    action: str
    bypassed: bool = False
    bypass_reason: str | None = None
    score: int | None = None
    signals: list[Any] = field(default_factory=list)
    dial: int | None = None
    counterfactuals: dict = field(default_factory=dict)


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
        self._entries: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict]] = []
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

    The pipeline is intentionally additive: new phases plug in by adding
    signal modules to ``_collect_signals()`` and the scorer/decider are
    wired into ``_score_connection()``.
    """

    def __init__(
        self,
        config: dict,
        local_cache: "LocalCache",
        redis_client: object,
    ) -> None:
        self._config = config
        self._cache = local_cache
        self._redis = redis_client
        self._policy = config.get("security_policy", {})
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

    def update_scorer(self, scorer: Any, decider: Any) -> None:
        """Wire in Phase 1 scorer and decider. Called after Phase 1 init."""
        self._scorer = scorer
        self._decider = decider

    def update_sets(self, whitelist: set[str], blacklist: set[str]) -> None:
        """Replace in-process JA4 sets. Called on startup and pub/sub update."""
        self._whitelist = whitelist
        self._blacklist = blacklist

    def on_config_reload(self, new_config: dict) -> None:
        """Apply new config on hot reload. Registered with ConfigLoader."""
        self._config = new_config
        self._policy = new_config.get("security_policy", {})
        self._allowlist.reload(new_config)

    async def process(self, ctx: ConnectionContext) -> PipelineResult:
        """Process one connection through the full pipeline.

        Returns a :class:`PipelineResult` describing the action to take.
        Never raises — all errors result in an allow decision (fail open).
        """
        try:
            return await self._process_inner(ctx)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "pipeline | event=unexpected_error | ip=%s | error=%s",
                ctx.client_ip,
                exc,
                exc_info=True,
            )
            # Fail open: an error in the pipeline must not block real users
            result = PipelineResult(action="allow", score=0, signals=[], dial=self._cache.dial)
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

        # ── 3. Signal collection (stub — phases 3–12 add real signals) ─
        signals = await self._collect_signals(ctx)

        # ── 4. Score + decide ──────────────────────────────────────────
        score, action, scored_signals, cf = self._score_connection(signals)
        dial = self._cache.dial

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
                action=action, score=score, signals=scored_signals, dial=dial,
                counterfactuals=cf,
            )
            self._emit_log(ctx, result)

        _CONNECTIONS.labels(action=result.action).inc()
        # Fire-and-forget stream event (Phase 12 analytics consumes this)
        asyncio.create_task(self._emit_stream_event(ctx, result))
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

        # 4. mTLS bypass
        if self._policy.get("mtls_bypass", {}).get("enabled", True):
            if ctx.has_valid_client_cert:
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
                blocked_countries: list[str] = (
                    self._config.get("geoip", {}).get("country_blacklist", [])
                )
                if ctx.country in blocked_countries:
                    return PipelineResult(
                        action="block",
                        bypassed=True,
                        bypass_reason="country_blacklist",
                    )

        return None

    async def _collect_signals(self, ctx: ConnectionContext) -> list:
        """Collect risk signals from all enabled signal modules.

        Returns an empty list in Phase 0. Each subsequent phase adds its
        module's call here. Modules run concurrently where possible.

        The method must never raise. Individual module errors are caught
        and logged; the pipeline continues with whatever signals were
        collected before the error.
        """
        # Phases 3–12 will add signal collection here:
        #   signals.extend(await self._tls_enforcer.signals(ctx))
        #   signals.extend(await self._sni_analyzer.signals(ctx))
        #   ...
        return []

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
                    f"{act}@{d}"
                    for d, act in sorted(cf.items())
                    if act != "allow"
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
        if result.dial == 0 and not result.bypassed and isinstance(result.counterfactuals, dict):
            json_doc["counterfactual"] = {
                f"action_at_{d}": act
                for d, act in sorted(result.counterfactuals.items())
            }

        logger.debug(json.dumps(json_doc))

    # ------------------------------------------------------------------
    # Stream events (Phase 2 — consumed by Phase 12 Analytics)
    # ------------------------------------------------------------------

    async def _emit_stream_event(self, ctx: ConnectionContext, result: PipelineResult) -> None:
        """XADD one event to ``ja4proxy:events``. Swallows all errors.

        Uses the synchronous Redis client passed at init time (Phase 12 will
        upgrade to async). The sync call runs in the event loop thread;
        acceptable at Phase 2 scale as a fire-and-forget write.
        """
        try:
            cf = result.counterfactuals if isinstance(result.counterfactuals, dict) else {}
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
                self._redis.xadd("ja4proxy:events", fields, maxlen=100_000, approximate=True)
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
