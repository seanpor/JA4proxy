"""Action decider with dial support for JA4proxy (Phase 1).

The decider maps (composite score, dial) → final action string.

Dial semantics
--------------
``dial=0``   — monitor mode: always return ``"allow"`` regardless of score.
               The score is still computed and logged (for retrospective analysis).

``dial=100`` — full blocking: thresholds apply exactly as configured.

``0 < dial < 100`` — thresholds are scaled linearly:
               ``effective_threshold = configured_threshold × dial / 100``

At ``dial=100``, the decider returns the same action as the scorer's
``recommended_action``. At lower dial values, the effective thresholds are
higher, so fewer connections are blocked.

This class is the Phase 1 scaffold. Phase 2 adds:
  - Reading ``config:dial`` from Redis on each connection
  - Receiving dial updates via ``dial_change`` pub/sub messages

For Phase 1, the dial comes from ``local_cache.dial`` (set at startup
from config, updated by pub/sub handler).
"""

# Action resolution order (highest severity first)
_THRESHOLD_ORDER = ("ban", "block", "tarpit", "rate_limit", "flag")

_DEFAULT_THRESHOLDS: dict[str, int] = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


class ActionDecider:
    """Map (score, dial) → final action string.

    Thread-safe: yes (no mutable state after ``__init__``).

    Args:
        thresholds: Mapping of action name → minimum score (0–100).
                    Keys: ``flag``, ``rate_limit``, ``tarpit``, ``block``, ``ban``.
                    Missing keys use defaults from ``_DEFAULT_THRESHOLDS``.
        ban_duration_seconds: How long IP bans last. Passed to the ban
                              enforcement layer. Default: 300 (5 min).
    """

    def __init__(
        self,
        thresholds: dict[str, int] | None = None,
        ban_duration_seconds: int = 300,
    ) -> None:
        t = _DEFAULT_THRESHOLDS.copy()
        if thresholds:
            t.update(thresholds)
        self._thresholds = t
        self.ban_duration_seconds = ban_duration_seconds

    def decide(self, score: int, dial: int) -> str:
        """Return the final action string for this connection.

        Args:
            score: Composite risk score 0–100 from :class:`~src.security.risk_scorer.RiskScorer`.
            dial: Current dial value 0–100 from the local cache.

        Returns:
            Action string: ``allow | flag | rate_limit | tarpit | block | ban``.
        """
        # dial=0 → monitor mode: always allow
        if dial == 0:
            return "allow"

        # Scale thresholds by dial (dial=100 → use configured thresholds directly)
        for action in _THRESHOLD_ORDER:
            configured = self._thresholds.get(action, _DEFAULT_THRESHOLDS[action])
            # At dial=100: effective = configured (no scaling)
            # At dial=50:  effective = configured × 100/50 = 2× configured (higher, harder to trigger)
            # Inverse: lower dial → higher effective threshold → fewer blocks
            effective = int(configured * 100 / max(dial, 1))
            if score >= effective:
                return action

        return "allow"

    @classmethod
    def from_config(cls, config: dict) -> "ActionDecider":
        """Create an ActionDecider from the ``risk_scorer`` config section.

        Args:
            config: Full proxy.yml config dict.

        Returns:
            Configured :class:`ActionDecider` instance.
        """
        scorer_cfg = config.get("risk_scorer", {})
        thresholds = scorer_cfg.get("thresholds", {})
        ban_duration = int(scorer_cfg.get("ban_duration_seconds", 300))
        return cls(thresholds=thresholds, ban_duration_seconds=ban_duration)
