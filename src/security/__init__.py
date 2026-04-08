"""Security module for rate limiting and threat detection.

EXPERIMENTAL — Python prototype code.  The production proxy is the Go
implementation under ``cmd/proxy/`` and ``internal/`` (promoted in Phase 15).
Modules here are used for prototyping new signals before porting them to Go.
Do not deploy the Python proxy; do not assume code in this package ships.
"""

from .action_enforcer import ActionEnforcer
from .action_types import ActionConfig, ActionResult, ActionType
from .gdpr_storage import DataCategory, GDPRStorage
from .rate_strategy import RateLimitStrategy, RateMetrics, StrategyConfig
from .rate_tracker import MultiStrategyRateTracker
from .security_manager import SecurityManager, create_security_manager
from .threat_evaluator import MultiStrategyPolicy, ThreatEvaluation, ThreatEvaluator
from .threat_tier import ThreatTier, ThreatTierConfig

__all__ = [
    "RateLimitStrategy",
    "RateMetrics",
    "StrategyConfig",
    "MultiStrategyRateTracker",
    "ThreatTier",
    "ThreatTierConfig",
    "ThreatEvaluator",
    "ThreatEvaluation",
    "MultiStrategyPolicy",
    "ActionType",
    "ActionResult",
    "ActionConfig",
    "ActionEnforcer",
    "GDPRStorage",
    "DataCategory",
    "SecurityManager",
    "create_security_manager",
]
