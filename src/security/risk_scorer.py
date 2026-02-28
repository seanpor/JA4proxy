"""Composite risk scorer for JA4proxy (Phase 1).

The scorer aggregates all :class:`RiskSignal` objects produced by signal
modules (Phases 3–12) into a single 0–100 composite score and derives
a threshold-based recommended action.

Design
------
- Each signal has a ``score`` (contribution, may be negative) and a
  ``weight`` (default 1.0). Contribution = ``score × weight``.
- Contributions are summed and clamped to 0–100. The composite score
  never goes below 0 (negative signals reduce, not reverse).
- The ``recommended_action`` is derived from thresholds alone (no dial).
  The :class:`~src.security.action_decider.ActionDecider` applies the
  dial on top of this recommendation.
- ``explanation`` contains the top-3 signals by absolute contribution for
  log output and UI display.

Signal names must come from the registry in ``docs/STYLE_GUIDE.md §1f``.
Do not invent new names without adding them there first.
"""

import logging
from dataclasses import dataclass, field

from prometheus_client import Histogram

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_RISK_SCORE_HIST = Histogram(
    "ja4proxy_risk_score",
    "Composite risk score distribution per connection",
    buckets=[0, 10, 20, 35, 55, 70, 85, 100],
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

# Threshold ordering for recommended_action derivation (highest first)
_THRESHOLD_ORDER = ("ban", "block", "tarpit", "rate_limit", "flag")

# Default thresholds matching proxy.yml defaults
_DEFAULT_THRESHOLDS: dict[str, int] = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


from .models import RiskSignal


@dataclass
class RiskAssessment:
    """The output of :meth:`RiskScorer.score`.

    Attributes:
        total_score: Composite score 0–100 (never below 0, never above 100).
        signals: All contributing signals, as received by the scorer.
        recommended_action: Action string derived from thresholds alone
                            (allow|flag|rate_limit|tarpit|block|ban).
                            The ActionDecider applies the dial on top.
        explanation: Top-3 signals formatted for log output, e.g.
                     ``"rdap_known_bad_org(+45), missing_sni(+30), asn_datacenter(+20)"``.
    """

    total_score: int
    signals: list[RiskSignal]
    recommended_action: str
    explanation: str


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Aggregate :class:`RiskSignal` objects into a :class:`RiskAssessment`.

    Thread-safe: yes (no mutable state after ``__init__``).

    Args:
        thresholds: Mapping of action name → minimum score.
                    Keys: ``flag``, ``rate_limit``, ``tarpit``, ``block``, ``ban``.
                    Missing keys fall back to :data:`_DEFAULT_THRESHOLDS`.
    """

    def __init__(self, thresholds: dict[str, int] | None = None) -> None:
        t = _DEFAULT_THRESHOLDS.copy()
        if thresholds:
            t.update(thresholds)
        self._thresholds = t

    @classmethod
    def from_config(cls, config: dict) -> "RiskScorer":
        """Create a RiskScorer from the ``risk_scorer`` config section.

        Args:
            config: Full proxy.yml config dict.

        Returns:
            Configured :class:`RiskScorer` instance.
        """
        thresholds = config.get("risk_scorer", {}).get("thresholds", {})
        return cls(thresholds=thresholds)

    def score(self, signals: list[RiskSignal]) -> RiskAssessment:
        """Compute the composite score and recommended action.

        Args:
            signals: List of :class:`RiskSignal` objects from all modules.
                     May be empty — returns score=0, action=allow.

        Returns:
            A fully populated :class:`RiskAssessment`.
        """
        # Clamp individual signals to [-100, 100] and warn on out-of-range
        validated: list[RiskSignal] = []
        for sig in signals:
            clamped_score = sig.score
            if sig.score > 100:
                logger.debug(
                    "risk_scorer | event=signal_clamped | name=%s | score=%d → 100",
                    sig.name,
                    sig.score,
                )
                clamped_score = 100
            elif sig.score < -100:
                logger.debug(
                    "risk_scorer | event=signal_clamped | name=%s | score=%d → -100",
                    sig.name,
                    sig.score,
                )
                clamped_score = -100
            if clamped_score != sig.score:
                sig = RiskSignal(
                    name=sig.name,
                    score=clamped_score,
                    reason=sig.reason,
                    weight=sig.weight,
                )
            validated.append(sig)

        # Sum weighted contributions
        raw_total = sum(int(s.score * s.weight) for s in validated)

        # Clamp composite to 0–100
        total_score = max(0, min(100, raw_total))

        # Derive recommended_action from thresholds (highest triggered wins)
        recommended_action = _derive_action(total_score, self._thresholds)

        # Build explanation from top-3 by absolute weighted contribution
        explanation = _build_explanation(validated)

        _RISK_SCORE_HIST.observe(total_score)

        return RiskAssessment(
            total_score=total_score,
            signals=validated,
            recommended_action=recommended_action,
            explanation=explanation,
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _derive_action(score: int, thresholds: dict[str, int]) -> str:
    """Return the highest-triggered action for the given score."""
    for action in _THRESHOLD_ORDER:
        if score >= thresholds.get(action, _DEFAULT_THRESHOLDS[action]):
            return action
    return "allow"


def _build_explanation(signals: list[RiskSignal]) -> str:
    """Format top-3 signals by absolute contribution for log/UI display."""
    if not signals:
        return ""
    sorted_sigs = sorted(
        signals,
        key=lambda s: abs(s.score * s.weight),
        reverse=True,
    )[:3]
    parts = [
        f"{s.name}({'+' if s.score >= 0 else ''}{s.score})"
        for s in sorted_sigs
    ]
    return ", ".join(parts)
