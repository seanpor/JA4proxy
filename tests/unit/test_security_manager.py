#!/usr/bin/env python3
"""
Tests for src/security/security_manager.py.

Covers all uncovered lines including exception paths, tier routing,
__repr__, and the create_security_manager convenience function.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis

from src.security.action_types import ActionType
from src.security.security_manager import SecurityManager, create_security_manager
from src.security.threat_tier import ThreatTier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(
    ping_ok=True,
    rate_tracker=None,
    threat_evaluator=None,
    action_enforcer=None,
    gdpr_storage=None,
):
    """Build a SecurityManager with fully mocked sub-components."""
    redis_mock = MagicMock()
    if not ping_ok:
        redis_mock.ping.side_effect = redis.ConnectionError("Redis down")
    else:
        redis_mock.ping.return_value = True

    # Default mock sub-components — track_connection must be async
    rt = rate_tracker or MagicMock()
    if not isinstance(rt.track_connection, AsyncMock):
        rt.track_connection = AsyncMock(return_value={})
    te = threat_evaluator or MagicMock()
    ae = action_enforcer or MagicMock()
    gs = gdpr_storage or MagicMock()

    # By default the action_enforcer is_blocked returns not blocked
    if action_enforcer is None:
        ae.is_blocked.return_value = (False, "")
        ae.unban.return_value = False

    config = {
        "security": {
            "rate_limiting": True,
            "max_requests_per_minute": 100,
        }
    }

    return SecurityManager(
        redis_client=redis_mock,
        config=config,
        rate_tracker=rt,
        threat_evaluator=te,
        action_enforcer=ae,
        gdpr_storage=gs,
    ), redis_mock, rt, te, ae, gs


def _make_action_result(allowed=True, reason="Allowed", action_type=None):
    """Build a mock action enforcement result."""
    result = MagicMock()
    result.allowed = allowed
    result.reason = reason
    result.action_type = action_type or MagicMock(value="allow")
    result.to_dict.return_value = {"allowed": allowed, "reason": reason}
    return result


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestSecurityManagerInit:
    def test_raises_if_redis_none(self):
        with pytest.raises(ValueError, match="Redis client is required"):
            SecurityManager(redis_client=None, config={})

    def test_redis_ping_failure_raises(self):
        """Lines 100-102: SecurityManager's own ping check fails → propagates.

        Sub-components must be pre-mocked so SecurityManager's secondary ping
        (line 98) is actually reached. Without pre-mocked sub-components,
        MultiStrategyRateTracker calls ping() first and raises before line 98.
        """
        with pytest.raises(Exception, match="Redis down"):
            _make_manager(ping_ok=False)

    def test_successful_init(self):
        mgr, _, _, _, _, _ = _make_manager()
        assert mgr.redis is not None

    def test_from_config_classmethod(self):
        """Lines 327-328: from_config delegates to __init__."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True
        mgr = SecurityManager.from_config(redis_mock, {})
        assert isinstance(mgr, SecurityManager)


# ---------------------------------------------------------------------------
# check_access — normal paths
# ---------------------------------------------------------------------------

class TestCheckAccessNormal:
    async def test_invalid_ja4_blocked(self):
        mgr, _, _, _, _, _ = _make_manager()
        allowed, reason = await mgr.check_access("", "1.2.3.4")
        assert allowed is False
        assert reason == "Invalid request"

    async def test_invalid_ip_blocked(self):
        mgr, _, _, _, _, _ = _make_manager()
        allowed, reason = await mgr.check_access("t13d_abc_def", "")
        assert allowed is False
        assert reason == "Invalid request"

    async def test_pre_blocked_returns_immediately(self):
        """Action enforcer says already blocked — no rate tracking."""
        ae = MagicMock()
        ae.is_blocked.return_value = (True, "Already banned")
        mgr, _, rt, _, _, _ = _make_manager(action_enforcer=ae)

        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")

        assert allowed is False
        assert reason == "Already banned"
        rt.track_connection.assert_not_called()

    async def test_normal_traffic_allowed(self):
        """All strategies show normal behavior → Allowed."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {}
        te.should_apply_action.return_value = False

        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, threat_evaluator=te)
        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")

        assert allowed is True
        assert reason == "Allowed"

    async def test_threat_triggers_action_enforcer(self):
        """Threat detected → action enforced → result returned."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.enforce.return_value = _make_action_result(allowed=False, reason="Rate limited")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {"per_ip": MagicMock()}
        te.should_apply_action.return_value = True
        te.get_most_severe_tier.return_value = ThreatTier.BLOCK
        te.get_triggering_strategy.return_value = MagicMock(value="per_ip")

        mgr, _, _, _, _, gs = _make_manager(action_enforcer=ae, threat_evaluator=te)
        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")

        assert allowed is False
        assert reason == "Rate limited"

    async def test_not_allowed_triggers_gdpr_storage(self):
        """When result.allowed is False, _store_enforcement_data is called."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.enforce.return_value = _make_action_result(allowed=False, reason="Blocked")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {"per_ip": MagicMock()}
        te.should_apply_action.return_value = True
        te.get_most_severe_tier.return_value = ThreatTier.BLOCK
        te.get_triggering_strategy.return_value = MagicMock(value="per_ip")

        gs = MagicMock()
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, threat_evaluator=te, gdpr_storage=gs)
        await mgr.check_access("ja4fp", "1.2.3.4")

        gs.store.assert_called()

    async def test_allowed_result_skips_gdpr_storage(self):
        """When result.allowed is True, _store_enforcement_data is NOT called."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.enforce.return_value = _make_action_result(allowed=True, reason="Allowed")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {"per_ip": MagicMock()}
        te.should_apply_action.return_value = True
        te.get_most_severe_tier.return_value = ThreatTier.SUSPICIOUS
        te.get_triggering_strategy.return_value = MagicMock(value="per_ip")

        gs = MagicMock()
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, threat_evaluator=te, gdpr_storage=gs)
        await mgr.check_access("ja4fp", "1.2.3.4")

        gs.store.assert_not_called()


# ---------------------------------------------------------------------------
# check_access — exception path (lines 188-193)
# ---------------------------------------------------------------------------

class TestCheckAccessExceptionPath:
    async def test_exception_in_rate_tracker_returns_blocked(self):
        """Lines 188-193: unexpected exception → fail-secure block."""
        rt = MagicMock()
        rt.track_connection = AsyncMock(side_effect=RuntimeError("unexpected"))

        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")

        mgr, _, _, _, _, _ = _make_manager(rate_tracker=rt, action_enforcer=ae)
        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")

        assert allowed is False
        assert reason == "Security check failed"

    async def test_exception_in_threat_evaluator_returns_blocked(self):
        """Exception in evaluate_multi_strategy → fail-secure block."""
        te = MagicMock()
        te.evaluate_multi_strategy.side_effect = ValueError("bad")

        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")

        mgr, _, _, _, _, _ = _make_manager(threat_evaluator=te, action_enforcer=ae)
        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")

        assert allowed is False
        assert reason == "Security check failed"


# ---------------------------------------------------------------------------
# _store_enforcement_data tier routing (lines 274-281, 290-291)
# ---------------------------------------------------------------------------

class TestStoreTierRouting:
    async def _check_access_with_tier(self, tier):
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.enforce.return_value = _make_action_result(allowed=False, reason="Blocked")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {"per_ip": MagicMock()}
        te.should_apply_action.return_value = True
        te.get_most_severe_tier.return_value = tier
        te.get_triggering_strategy.return_value = MagicMock(value="per_ip")

        gs = MagicMock()
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, threat_evaluator=te, gdpr_storage=gs)
        await mgr.check_access("ja4fp", "1.2.3.4")
        return gs

    async def test_suspicious_tier_uses_suspicious_category(self):
        """Line 275: ThreatTier.SUSPICIOUS → DataCategory.SUSPICIOUS."""
        gs = await self._check_access_with_tier(ThreatTier.SUSPICIOUS)
        call_args = gs.store.call_args
        from src.security.gdpr_storage import DataCategory
        assert call_args.kwargs["category"] == DataCategory.SUSPICIOUS

    async def test_banned_tier_uses_bans_category(self):
        """Lines 278-279: ThreatTier.BANNED → DataCategory.BANS."""
        gs = await self._check_access_with_tier(ThreatTier.BANNED)
        call_args = gs.store.call_args
        from src.security.gdpr_storage import DataCategory
        assert call_args.kwargs["category"] == DataCategory.BANS

    async def test_unknown_tier_uses_fingerprints_category(self):
        """Lines 280-281: unknown tier → DataCategory.FINGERPRINTS (else branch)."""
        # Use a tier that is not SUSPICIOUS, BLOCK, or BANNED
        gs = await self._check_access_with_tier(ThreatTier.NORMAL)
        call_args = gs.store.call_args
        from src.security.gdpr_storage import DataCategory
        assert call_args.kwargs["category"] == DataCategory.FINGERPRINTS

    async def test_store_enforcement_exception_is_silenced(self):
        """Lines 290-291: exception in gdpr_storage.store is caught, not propagated."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.enforce.return_value = _make_action_result(allowed=False, reason="Blocked")

        te = MagicMock()
        te.evaluate_multi_strategy.return_value = {"per_ip": MagicMock()}
        te.should_apply_action.return_value = True
        te.get_most_severe_tier.return_value = ThreatTier.BLOCK
        te.get_triggering_strategy.return_value = MagicMock(value="per_ip")

        gs = MagicMock()
        gs.store.side_effect = redis.RedisError("Redis write failed")

        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, threat_evaluator=te, gdpr_storage=gs)
        # Must not raise
        allowed, reason = await mgr.check_access("ja4fp", "1.2.3.4")
        assert allowed is False


# ---------------------------------------------------------------------------
# get_statistics (lines 209-211)
# ---------------------------------------------------------------------------

class TestGetStatistics:
    def test_returns_stats_dict(self):
        mgr, _, _, _, ae, gs = _make_manager()
        ae.get_enforcement_stats.return_value = {"blocks": 0}
        gs.verify_compliance.return_value = {"compliant_keys": 10}
        gs.get_retention_report.return_value = {"retention_periods": {}}

        stats = mgr.get_statistics()
        assert "enforcement" in stats

    def test_exception_returns_error_dict(self):
        """Lines 209-211: exception → {'error': str(e)}."""
        mgr, _, _, _, ae, _ = _make_manager()
        ae.get_enforcement_stats.side_effect = redis.RedisError("crash")

        stats = mgr.get_statistics()
        assert "error" in stats
        assert "crash" in stats["error"]


# ---------------------------------------------------------------------------
# manual_unban (lines 247-249)
# ---------------------------------------------------------------------------

class TestManualUnban:
    def test_unban_entity_not_banned(self):
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.unban.return_value = False
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae)

        result = mgr.manual_unban("ja4fp", "1.2.3.4")
        assert result is False

    def test_unban_entity_was_banned(self):
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.unban.return_value = True
        gs = MagicMock()
        gs.store.return_value = True
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae, gdpr_storage=gs)

        result = mgr.manual_unban("ja4fp", "1.2.3.4", reason="False positive")
        assert result is True
        gs.store.assert_called()

    def test_unban_exception_returns_false(self):
        """Lines 247-249: exception → return False."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        ae.unban.side_effect = redis.ConnectionError("Redis crashed")
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae)

        result = mgr.manual_unban("ja4fp", "1.2.3.4")
        assert result is False


# ---------------------------------------------------------------------------
# verify_gdpr_compliance (lines 260-262)
# ---------------------------------------------------------------------------

class TestVerifyGdprCompliance:
    def test_delegates_to_gdpr_storage(self):
        gs = MagicMock()
        gs.verify_compliance.return_value = {"compliance_rate": 1.0}
        mgr, _, _, _, _, _ = _make_manager(gdpr_storage=gs)

        result = mgr.verify_gdpr_compliance()
        assert result["compliance_rate"] == 1.0

    def test_exception_returns_error_dict(self):
        """Lines 260-262: exception → error dict with compliance_rate=0.0."""
        gs = MagicMock()
        gs.verify_compliance.side_effect = redis.ConnectionError("redis down")
        mgr, _, _, _, _, _ = _make_manager(gdpr_storage=gs)

        result = mgr.verify_gdpr_compliance()
        assert "error" in result
        assert result["compliance_rate"] == 0.0


# ---------------------------------------------------------------------------
# __repr__ (line 332)
# ---------------------------------------------------------------------------

class TestRepr:
    def test_repr_contains_class_names(self):
        """Line 332: __repr__ includes component class names."""
        mgr, _, _, _, _, _ = _make_manager()
        r = repr(mgr)
        assert "SecurityManager(" in r
        assert "rate_tracker=" in r


# ---------------------------------------------------------------------------
# create_security_manager convenience function (line 355)
# ---------------------------------------------------------------------------

class TestCreateSecurityManager:
    def test_create_security_manager_returns_instance(self):
        """Line 355: create_security_manager delegates to from_config."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True
        mgr = create_security_manager(redis_mock, {})
        assert isinstance(mgr, SecurityManager)


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestAlpnBypassCoverage:
    """Cover lines 141-148: ALPN browser bypass in check_access."""

    @pytest.mark.asyncio
    async def test_alpn_h2_bypasses_rate_limiting_and_allows(self):
        """Lines 141-148: ALPN=h2 skips rate limiting, checks blocked status,
        and returns (True, 'ALPN bypass') when not blocked.
        So what: if the ALPN bypass is missing, browser h2 traffic is scored and
        rate-limited — the proxy would block legitimate Chrome/Firefox users on
        any high-traffic deployment, causing mass false positives."""
        ae = MagicMock()
        ae.is_blocked.return_value = (False, "")
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae)
        # Inject ALPN bypass config
        mgr.config["security_policy"] = {"alpn_browser_bypass": {"enabled": True}}

        allowed, reason = await mgr.check_access(
            ja4="t13d1516h2_abc_def",
            client_ip="1.2.3.4",
            alpn="h2",
        )
        assert allowed is True
        assert "ALPN bypass" in reason

    @pytest.mark.asyncio
    async def test_alpn_bypass_still_blocks_already_blocked_entity(self):
        """Lines 145-147: even with ALPN bypass, an already-blocked entity is
        rejected with the existing block reason.
        So what: if this is_blocked check inside the ALPN bypass is missing,
        a previously banned IP could evade enforcement simply by connecting with
        an h2 ALPN — the ban is silently ignored for browser-like connections."""
        ae = MagicMock()
        ae.is_blocked.return_value = (True, "Permanently banned")
        mgr, _, _, _, _, _ = _make_manager(action_enforcer=ae)
        mgr.config["security_policy"] = {"alpn_browser_bypass": {"enabled": True}}

        allowed, reason = await mgr.check_access(
            ja4="t13d1516h2_abc_def",
            client_ip="1.2.3.4",
            alpn="http/1.1",
        )
        assert allowed is False
        assert reason == "Permanently banned"
