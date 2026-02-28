"""Action decider with dial support for JA4proxy (Phase 2).

The decider maps (composite score, dial) → final action string.

Dial semantics
--------------
``dial=0``   — monitor mode: always return ``"allow"`` regardless of score.
               The score is still computed and logged (for retrospective analysis).

``dial=100`` — full blocking: thresholds apply exactly as configured.

``0 < dial < 100`` — thresholds are interpolated via:
               ``effective_threshold = round(101 - (dial/100) × (101 - configured))``

At ``dial=100``, effective threshold equals configured exactly.
At ``dial=0``, effective threshold is 101 (unreachable — nothing ever triggers).
Lower dial values push thresholds higher, so fewer connections are blocked.

See ``effective_threshold()`` for the exact formula and worked examples.
"""

import datetime
import logging

# Action resolution order (highest severity first)
_THRESHOLD_ORDER = ("ban", "block", "tarpit", "rate_limit", "flag")

_DEFAULT_THRESHOLDS: dict[str, int] = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def effective_threshold(configured: int, dial: int) -> int:
    """Return the effective minimum score to trigger an action at the given dial.

    Formula: ``round(101 - (dial/100) × (101 - configured))``

    Args:
        configured: The configured threshold for the action (0–100).
        dial: Current dial value (0–100).

    Returns:
        Effective threshold integer. At dial=0 this is always 101 (unreachable).
        At dial=100 it equals ``configured`` exactly.

    Examples::

        effective_threshold(70, 0)   → 101   # unreachable
        effective_threshold(70, 100) → 70    # exact configured
        effective_threshold(70, 50)  → 86    # round(101 - 0.5*31) = round(85.5) = 86
        effective_threshold(20, 50)  → 60    # round(101 - 0.5*81) = round(60.5) = 60
    """
    if dial == 0:
        return 101
    return round(101 - (dial / 100) * (101 - configured))


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

        # Interpolate thresholds using the Phase 2 formula
        for action in _THRESHOLD_ORDER:
            configured = self._thresholds.get(action, _DEFAULT_THRESHOLDS[action])
            if score >= effective_threshold(configured, dial):
                return action

        return "allow"

    def counterfactuals(self, score: int, dial_values: list[int]) -> dict[int, str]:
        """Return ``{dial_value: action}`` for each dial in ``dial_values``.

        Used for monitor-mode logging: shows what action would have been taken
        at each dial level without actually blocking anything.

        Args:
            score: Composite risk score 0–100.
            dial_values: List of dial values to evaluate (e.g. [25, 50, 75, 100]).

        Returns:
            Dict mapping each dial value to the action string it would produce.
        """
        return {d: self.decide(score, d) for d in dial_values}

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


class DialManager:
    """Manages ``config:dial`` in Redis with startup reset and hourly rate limiting.

    On startup, reads the current dial from Redis. If ``blocking_acknowledged``
    is false in config, resets the dial to 0 (safety gate — prevents accidental
    blocking on first deploy). Validates dial change requests against an hourly
    rate limit to prevent accidental jumps from 0 → 100.

    Args:
        config: Full proxy.yml config dict. Reads ``monitor_mode`` section.
    """

    DIAL_KEY = "config:dial"
    COUNT_KEY_PREFIX = "config:dial:change_count:"

    def __init__(self, config: dict) -> None:
        monitor = config.get("monitor_mode", {})
        self._max_per_hour: int = int(monitor.get("max_dial_change_per_hour", 25))
        self._acknowledged: bool = bool(monitor.get("blocking_acknowledged", False))
        self._default_dial: int = int(monitor.get("dial", 0))
        self._logger = logging.getLogger(__name__)

    def initialize(self, redis_client) -> int:
        """Read ``config:dial`` from Redis; reset to 0 if blocking not acknowledged.

        Sets the key if absent. Returns effective dial value.

        Args:
            redis_client: Synchronous Redis client.

        Returns:
            Effective dial value (0–100).
        """
        try:
            val = redis_client.get(self.DIAL_KEY)
            current = int(val) if val is not None else self._default_dial
        except Exception:
            current = self._default_dial

        if not self._acknowledged and current != 0:
            self._logger.warning(
                "dial | event=reset_unacknowledged | old=%d | new=0 | "
                "reason=blocking_acknowledged is false",
                current,
            )
            current = 0

        try:
            redis_client.set(self.DIAL_KEY, current)
        except Exception as e:
            self._logger.warning("dial | event=init_redis_error | error=%s", e)

        return current

    def validate_change(
        self,
        old_val: int,
        new_val: int,
        redis_client,
        force: bool = False,
    ) -> None:
        """Raise ValueError if the hourly change limit is exceeded.

        Increments the hourly counter on successful validation.

        Args:
            old_val: Current dial value.
            new_val: Proposed new dial value.
            redis_client: Synchronous Redis client.
            force: If True, bypass the rate limit (Management UI emergency override).

        Raises:
            ValueError: If the hourly change count equals or exceeds ``max_dial_change_per_hour``
                        and ``force`` is False.
        """
        if abs(new_val - old_val) == 0:
            return

        hour_key = self.COUNT_KEY_PREFIX + datetime.datetime.utcnow().strftime("%Y-%m-%d-%H")

        if not force:
            try:
                count = int(redis_client.get(hour_key) or 0)
            except Exception:
                count = 0  # fail open — don't block dial changes on Redis error

            if count >= self._max_per_hour:
                self._logger.warning(
                    "dial | event=change_rejected | count=%d | limit=%d",
                    count,
                    self._max_per_hour,
                )
                raise ValueError(
                    f"Dial change rejected: {count} changes this hour "
                    f"(limit {self._max_per_hour}). Pass force=True to override."
                )

        # Record the change
        try:
            redis_client.incr(hour_key)
            redis_client.expire(hour_key, 3600)
        except Exception as e:
            self._logger.warning("dial | event=count_redis_error | error=%s", e)
