"""SNI (Server Name Indication) analysis for JA4proxy (Phase 4).

Extracts risk signals from the TLS ClientHello SNI field:

- **missing_sni** (+30)  — Modern browsers always send SNI. Absence signals
  malware, C2 clients, or IP scanners.
- **ip_literal_sni** (+25) — Raw IP address in SNI. Common in scanners;
  rare in legitimate traffic.
- **dga** (0–score_cap)  — Domain Generation Algorithm likelihood, derived
  from Shannon entropy, consonant/vowel ratio, label length, and numeric
  density. Entirely deterministic — no ML models.
- **unexpected_sni** (+15) — SNI not matching the operator-configured
  expected hostname list. Catches scanners probing for other services.

Privacy
-------
The raw SNI hostname is *never* logged in cleartext. Signal ``reason``
fields contain only structural descriptions (e.g. ``"SNI absent"`` or
``"DGA confidence 0.73"``). Callers must not forward ``ctx.sni`` to
external logging systems without redacting it first.

Signal names come from the registry in ``docs/STYLE_GUIDE.md §1f``.
"""

import ipaddress
import logging
import math
import re
from typing import Final

from prometheus_client import Counter, Histogram

from .risk_scorer import RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VOWELS: Final[frozenset[str]] = frozenset("aeiou")

# Labels shorter than this are too short for meaningful DGA analysis
_MIN_DGA_LABEL_LEN: Final[int] = 6

# Common non-significant prefixes skipped when picking the primary label
_SKIP_PREFIXES: Final[frozenset[str]] = frozenset(
    {"www", "mail", "m", "api", "static", "cdn", "img", "assets"}
)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_SNI_SIGNAL_TOTAL = Counter(
    "ja4proxy_sni_signal_total",
    "SNI analysis signals emitted by type",
    ["signal"],
)

_DGA_SCORE_HIST = Histogram(
    "ja4proxy_sni_dga_score",
    "DGA confidence score distribution (0–1)",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)


# ---------------------------------------------------------------------------
# DGA helpers (module-level so tests can import and call them directly)
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _get_primary_label(hostname: str) -> str:
    """Return the leftmost label that is not a common non-significant prefix."""
    parts = hostname.lower().rstrip(".").split(".")
    for part in parts:
        if part not in _SKIP_PREFIXES and part:
            return part
    return parts[0] if parts else ""


def dga_score(hostname: str) -> float:
    """Estimate DGA likelihood for *hostname*.

    Returns a value in ``[0.0, 1.0]``:

    - ``0.0`` — the hostname looks like legitimate traffic.
    - ``1.0`` — the hostname exhibits strong DGA characteristics.

    The function is deterministic and dependency-free. It analyses only the
    primary (leftmost significant) label of the hostname using four heuristics:

    1. **Shannon entropy** — random character selection produces high entropy.
    2. **Vowel absence** — DGA labels often lack vowels entirely; a very high
       consonant/vowel ratio with a long label is also suspicious.
    3. **Label length** — DGA labels tend to be long (≥ 16 chars).
    4. **Dense digit sequences** — malware C2 labels often embed timestamps
       or version numbers as 4+ consecutive digits.

    This function must achieve < 1% false-positive rate on Tranco top-10k
    domains (verified by ``tests/fp_corpus/test_dga_fp_rate.py``).
    """
    label = _get_primary_label(hostname)
    if len(label) < _MIN_DGA_LABEL_LEN:
        return 0.0

    score = 0.0

    # 1. Shannon entropy — high entropy suggests randomness (weight 0.40)
    ent = _shannon_entropy(label)
    if ent >= 3.8:
        score += min(0.40, (ent - 3.8) * 2.0)

    # 2. Vowel/consonant analysis
    alpha = [c for c in label if c.isalpha()]
    vowel_count = sum(1 for c in alpha if c in VOWELS)
    alpha_count = len(alpha)

    if alpha_count >= 6:
        if vowel_count == 0:
            # Complete absence of vowels: strong DGA signal (weight 0.30)
            score += 0.30
        elif alpha_count >= 10 and (alpha_count / vowel_count) > 5.0:
            # Very consonant-heavy AND long: moderate DGA signal (weight 0.20)
            score += 0.20

    # 3. Label length — DGA labels tend to be long (weight 0.20)
    if len(label) >= 20:
        score += 0.20
    elif len(label) >= 16:
        score += 0.10

    # 4. Dense digit sequence — 4+ consecutive digits (weight 0.10)
    if re.search(r"\d{4,}", label):
        score += 0.10

    return min(1.0, score)


def _is_ip_literal(value: str) -> bool:
    """Return True if *value* is a raw IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# SNIAnalyzer
# ---------------------------------------------------------------------------


class SNIAnalyzer:
    """Produce :class:`~src.security.risk_scorer.RiskSignal` objects from SNI.

    Thread-safe (no mutable state after construction; hot reload replaces
    all attributes atomically under the GIL for CPython).

    Args:
        config: Full proxy.yml config dict. Reads the ``sni_analyzer``
                sub-section.
    """

    def __init__(self, config: dict) -> None:
        # Handle None config gracefully
        if config is None:
            config = {}
        
        cfg = config.get("sni_analyzer", {})
        self._enabled: bool = bool(cfg.get("enabled", True))

        # missing_sni
        ms_cfg = cfg.get("missing_sni", {})
        self._missing_sni_enabled: bool = bool(ms_cfg.get("enabled", True))
        try:
            self._missing_sni_score: int = int(ms_cfg.get("score", 30))
        except (ValueError, TypeError):
            self._missing_sni_score: int = 30  # Default if conversion fails

        # ip_literal_sni
        il_cfg = cfg.get("ip_literal_sni", {})
        self._ip_literal_enabled: bool = bool(il_cfg.get("enabled", True))
        try:
            self._ip_literal_score: int = int(il_cfg.get("score", 25))
        except (ValueError, TypeError):
            self._ip_literal_score: int = 25  # Default if conversion fails

        # dga_detection
        dga_cfg = cfg.get("dga_detection", {})
        self._dga_enabled: bool = bool(dga_cfg.get("enabled", True))
        try:
            self._entropy_threshold: float = float(
                dga_cfg.get("entropy_threshold", 3.8)
            )
        except (ValueError, TypeError):
            self._entropy_threshold: float = 3.8  # Default if conversion fails
        try:
            self._dga_score_cap: int = int(dga_cfg.get("score_cap", 40))
        except (ValueError, TypeError):
            self._dga_score_cap: int = 40  # Default if conversion fails

        # unexpected_sni
        expected_hostnames = cfg.get("expected_hostnames", [])
        if not isinstance(expected_hostnames, list):
            expected_hostnames = []
        self._expected_hostnames: frozenset[str] = frozenset(
            str(h).lower() for h in expected_hostnames if isinstance(h, str)
        )
        try:
            self._unexpected_sni_score: int = int(cfg.get("score", 15))
        except (ValueError, TypeError):
            self._unexpected_sni_score: int = 15  # Default if conversion fails

    @classmethod
    def from_config(cls, config: dict) -> "SNIAnalyzer":
        """Create an :class:`SNIAnalyzer` from the full proxy.yml config dict."""
        return cls(config)

    def on_config_reload(self, new_config: dict) -> None:
        """Apply hot-reloaded config. Safe to call while connections are in flight."""
        self.__init__(new_config)

    def analyze(self, sni: str | None) -> list[RiskSignal]:
        """Analyse the SNI field of a ClientHello and return risk signals.

        Args:
            sni: The SNI hostname string extracted from the ClientHello, or
                 ``None`` if the SNI extension was absent.

        Returns:
            A list of :class:`~src.security.risk_scorer.RiskSignal` objects
            (may be empty). Never raises.

        Privacy: the raw *sni* value is never included in any signal's
        ``reason`` field or in any log emitted by this module.
        """
        if not self._enabled:
            return []

        signals: list[RiskSignal] = []

        # ── 1. Missing SNI ─────────────────────────────────────────────────
        if sni is None:
            if self._missing_sni_enabled:
                _SNI_SIGNAL_TOTAL.labels(signal="missing_sni").inc()
                signals.append(
                    RiskSignal(
                        name="missing_sni",
                        score=self._missing_sni_score,
                        reason="SNI extension absent from ClientHello",
                    )
                )
            return signals  # no further checks possible without an SNI value

        # Normalise: strip trailing dot, lowercase
        sni_clean = sni.rstrip(".").lower()

        # ── 2. IP-literal SNI ──────────────────────────────────────────────
        if self._ip_literal_enabled and _is_ip_literal(sni_clean):
            _SNI_SIGNAL_TOTAL.labels(signal="ip_literal_sni").inc()
            signals.append(
                RiskSignal(
                    name="ip_literal_sni",
                    score=self._ip_literal_score,
                    reason="SNI contains a raw IP address",
                )
            )
            return signals  # IP-literal → skip DGA / expected-hostname checks

        # ── 3. DGA detection ───────────────────────────────────────────────
        if self._dga_enabled:
            confidence = dga_score(sni_clean)
            _DGA_SCORE_HIST.observe(confidence)
            contrib = int(confidence * self._dga_score_cap)
            if contrib > 0:
                _SNI_SIGNAL_TOTAL.labels(signal="dga").inc()
                signals.append(
                    RiskSignal(
                        name="dga",
                        score=min(contrib, 100),
                        reason=f"DGA confidence {confidence:.2f}",
                    )
                )

        # ── 4. Unexpected hostname ─────────────────────────────────────────
        if self._expected_hostnames:
            if sni_clean not in self._expected_hostnames:
                _SNI_SIGNAL_TOTAL.labels(signal="unexpected_sni").inc()
                signals.append(
                    RiskSignal(
                        name="unexpected_sni",
                        score=self._unexpected_sni_score,
                        reason="SNI hostname not in expected_hostnames list",
                    )
                )

        return signals
