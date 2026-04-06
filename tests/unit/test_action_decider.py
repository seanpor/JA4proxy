"""Unit tests for src/security/action_decider.py — ActionDecider with dial."""

from unittest.mock import MagicMock

import pytest
import redis

from src.security.action_decider import ActionDecider, DialManager, effective_threshold

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


@pytest.fixture
def decider():
    return ActionDecider(thresholds=THRESHOLDS, ban_duration_seconds=300)


# ---------------------------------------------------------------------------
# effective_threshold — Phase 2 formula
# ---------------------------------------------------------------------------


class TestEffectiveThreshold:
    @pytest.mark.parametrize(
        "configured,dial,expected",
        [
            (70, 0, 101),   # dial=0 → always 101 (unreachable)
            (70, 100, 70),  # dial=100 → exact configured
            (70, 50, 86),   # round(101 - 0.5*31) = round(85.5) = 86
            (70, 25, 93),   # round(101 - 0.25*31) = round(93.25) = 93
            (70, 75, 78),   # round(101 - 0.75*31) = round(77.75) = 78
            (85, 10, 99),   # round(101 - 0.1*16) = round(99.4) = 99
            (20, 50, 60),   # round(101 - 0.5*81) = round(60.5) = 60 (banker's rounding)
        ],
    )
    def test_effective_threshold(self, configured, dial, expected):
        assert effective_threshold(configured, dial) == expected


# ---------------------------------------------------------------------------
# dial=0 → always allow (monitor mode)
# ---------------------------------------------------------------------------


class TestDialZeroMonitorMode:
    def test_dial_zero_score_0_allows(self, decider):
        assert decider.decide(score=0, dial=0) == "allow"

    def test_dial_zero_score_50_allows(self, decider):
        assert decider.decide(score=50, dial=0) == "allow"

    def test_dial_zero_score_100_allows(self, decider):
        assert decider.decide(score=100, dial=0) == "allow"

    def test_dial_zero_score_85_allows_not_ban(self, decider):
        """Even ban-level score must be allowed at dial=0."""
        assert decider.decide(score=85, dial=0) == "allow"


# ---------------------------------------------------------------------------
# dial=100 → thresholds apply as configured
# ---------------------------------------------------------------------------


class TestDialHundredFullBlocking:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "allow"),
            (19, "allow"),
            (20, "flag"),
            (34, "flag"),
            (35, "rate_limit"),
            (54, "rate_limit"),
            (55, "tarpit"),
            (69, "tarpit"),
            (70, "block"),
            (84, "block"),
            (85, "ban"),
            (100, "ban"),
        ],
    )
    def test_at_dial_100(self, decider, score, expected):
        result = decider.decide(score=score, dial=100)
        assert result == expected, (
            f"dial=100, score={score}: expected {expected}, got {result}"
        )


# ---------------------------------------------------------------------------
# One below each threshold → previous action
# ---------------------------------------------------------------------------


class TestOneBelowThreshold:
    def test_one_below_flag(self, decider):
        assert decider.decide(score=19, dial=100) == "allow"

    def test_one_below_rate_limit(self, decider):
        assert decider.decide(score=34, dial=100) == "flag"

    def test_one_below_tarpit(self, decider):
        assert decider.decide(score=54, dial=100) == "rate_limit"

    def test_one_below_block(self, decider):
        assert decider.decide(score=69, dial=100) == "tarpit"

    def test_one_below_ban(self, decider):
        assert decider.decide(score=84, dial=100) == "block"


# ---------------------------------------------------------------------------
# Intermediate dial values — interpolated thresholds
# ---------------------------------------------------------------------------


class TestIntermediateDial:
    def test_low_dial_allows_moderate_score(self):
        """At dial=10, effective thresholds are very high — score=70 should allow."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        # effective_flag@10 = round(101 - 0.1*81) = round(92.9) = 93
        result = decider.decide(score=70, dial=10)
        assert result == "allow"

    def test_dial_50_mid_threshold(self):
        """At dial=50, effective_flag = round(101 - 0.5*81) = 60."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        # score=59 → below effective_flag(20,50)=60 → allow
        assert decider.decide(score=59, dial=50) == "allow"
        # score=60 → meets effective_flag → flag
        assert decider.decide(score=60, dial=50) == "flag"

    def test_score_zero_always_allows_at_any_dial(self, decider):
        for dial in [0, 10, 50, 75, 100]:
            assert decider.decide(score=0, dial=dial) == "allow"


# ---------------------------------------------------------------------------
# counterfactuals() — Phase 2 method
# ---------------------------------------------------------------------------


class TestCounterfactuals:
    def test_empty_dial_list_returns_empty_dict(self, decider):
        result = decider.counterfactuals(score=50, dial_values=[])
        assert result == {}

    def test_score_zero_all_dials_return_allow(self, decider):
        result = decider.counterfactuals(score=0, dial_values=[0, 25, 50, 75, 100])
        assert all(v == "allow" for v in result.values())
        assert set(result.keys()) == {0, 25, 50, 75, 100}

    def test_high_score_shows_actions_at_higher_dials(self, decider):
        """score=75 → allow at dial=0, flag at dial=50, block at dial=100."""
        result = decider.counterfactuals(score=75, dial_values=[0, 50, 100])
        assert result[0] == "allow"   # dial=0 → always allow
        # effective_block@50 = round(101 - 0.5*(101-70)) = round(101-15.5) = 86
        # score=75 < 86 → not block; effective_tarpit@50 = round(101-0.5*46)=78; 75<78
        # effective_rate_limit@50 = round(101-0.5*66)=68; 75>=68 → rate_limit
        assert result[50] == "rate_limit"
        assert result[100] == "block"   # score=75 >= block threshold=70

    def test_dial_values_preserved_as_keys(self, decider):
        result = decider.counterfactuals(score=0, dial_values=[25, 50, 75, 100])
        assert list(result.keys()) == [25, 50, 75, 100]


# ---------------------------------------------------------------------------
# from_config factory
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_from_config_reads_thresholds(self):
        config = {
            "risk_scorer": {
                "thresholds": {
                    "flag": 15,
                    "rate_limit": 30,
                    "tarpit": 50,
                    "block": 65,
                    "ban": 80,
                },
                "ban_duration_seconds": 600,
            }
        }
        decider = ActionDecider.from_config(config)
        assert decider.decide(score=15, dial=100) == "flag"
        assert decider.decide(score=80, dial=100) == "ban"
        assert decider.ban_duration_seconds == 600

    def test_from_config_empty_uses_defaults(self):
        decider = ActionDecider.from_config({})
        assert decider.decide(score=70, dial=100) == "block"
        assert decider.ban_duration_seconds == 300

    def test_from_config_partial_thresholds(self):
        config = {
            "risk_scorer": {
                "thresholds": {"ban": 90},  # Only ban overridden
            }
        }
        decider = ActionDecider.from_config(config)
        # block threshold still at default 70
        assert decider.decide(score=70, dial=100) == "block"
        # ban now at 90
        assert decider.decide(score=89, dial=100) == "block"
        assert decider.decide(score=90, dial=100) == "ban"


# ---------------------------------------------------------------------------
# ban_duration_seconds attribute
# ---------------------------------------------------------------------------


class TestBanDuration:
    def test_default_ban_duration(self, decider):
        assert decider.ban_duration_seconds == 300

    def test_custom_ban_duration(self):
        d = ActionDecider(ban_duration_seconds=900)
        assert d.ban_duration_seconds == 900


# ---------------------------------------------------------------------------
# DialManager — Phase 2
# ---------------------------------------------------------------------------


class TestDialManager:
    def _make_redis_mock(self, get_return=None):
        from unittest.mock import AsyncMock
        m = AsyncMock()
        m.get.return_value = get_return
        m.set.return_value = True
        m.incr.return_value = 1
        m.expire.return_value = True
        return m

    @pytest.mark.asyncio
    async def test_initialize_reads_existing_dial(self):
        """Redis returns b'30' → dial=30."""
        redis_mock = self._make_redis_mock(get_return=b"30")
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": True}})
        result = await dm.initialize(redis_mock)
        assert result == 30

    @pytest.mark.asyncio
    async def test_initialize_redis_error_uses_default(self):
        """Redis raises → returns config default (0)."""
        from unittest.mock import AsyncMock
        m = AsyncMock()
        m.get.side_effect = redis.ConnectionError("down")
        m.set.side_effect = redis.ConnectionError("down")
        dm = DialManager({"monitor_mode": {"dial": 0}})
        result = await dm.initialize(m)
        assert result == 0

    @pytest.mark.asyncio
    async def test_initialize_unacknowledged_nonzero_resets_to_zero(self):
        """blocking_acknowledged=False with stored dial=75 → resets to 0."""
        redis_mock = self._make_redis_mock(get_return=b"75")
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": False}})
        result = await dm.initialize(redis_mock)
        assert result == 0

    @pytest.mark.asyncio
    async def test_initialize_acknowledged_preserves_nonzero(self):
        """blocking_acknowledged=True with stored dial=50 → keeps 50."""
        redis_mock = self._make_redis_mock(get_return=b"50")
        dm = DialManager({"monitor_mode": {"blocking_acknowledged": True}})
        result = await dm.initialize(redis_mock)
        assert result == 50

    @pytest.mark.asyncio
    async def test_validate_change_within_limit_succeeds(self):
        """count=0, max=25 → no exception, counter incremented."""
        redis_mock = self._make_redis_mock(get_return=b"0")
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        await dm.validate_change(0, 10, redis_mock)  # must not raise
        redis_mock.incr.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_change_at_limit_raises(self):
        """count=25, max=25 → ValueError raised."""
        redis_mock = self._make_redis_mock(get_return=b"25")
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        with pytest.raises(ValueError, match="Dial change rejected"):
            await dm.validate_change(0, 10, redis_mock)

    @pytest.mark.asyncio
    async def test_validate_change_force_bypasses_limit(self):
        """count=25, force=True → no exception."""
        redis_mock = self._make_redis_mock(get_return=b"25")
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        await dm.validate_change(0, 10, redis_mock, force=True)  # must not raise

    @pytest.mark.asyncio
    async def test_validate_change_same_value_noop(self):
        """old_val == new_val → no Redis calls."""
        redis_mock = self._make_redis_mock()
        dm = DialManager({"monitor_mode": {}})
        await dm.validate_change(50, 50, redis_mock)
        redis_mock.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_change_redis_error_counts_as_zero(self):
        """Redis error reading count → treated as 0, change allowed."""
        from unittest.mock import AsyncMock
        m = AsyncMock()
        m.get.side_effect = redis.ConnectionError("down")
        m.incr.return_value = 1
        m.expire.return_value = True
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        # Should not raise — Redis error means count=0
        await dm.validate_change(0, 10, m)


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestDialManagerRecordRedisError:
    """Cover lines 244-245: Redis error in the 'Record the change' try/except."""

    @pytest.mark.asyncio
    async def test_validate_change_record_redis_error_swallowed(self):
        """Lines 244-245: Redis error on incr() in the record step is logged as
        warning and swallowed — validate_change must still return normally.
        So what: if this exception propagates, a transient Redis hiccup during
        the counter update would reject the operator's dial change, preventing
        security configuration from being applied under the exact conditions
        (high load / Redis instability) when rapid configuration is most needed."""
        from unittest.mock import AsyncMock
        import redis as _redis
        m = AsyncMock()
        m.get.return_value = None   # count = 0 → change allowed
        m.incr.side_effect = _redis.ConnectionError("Redis down")
        from src.security.action_decider import DialManager
        dm = DialManager({"monitor_mode": {"max_dial_change_per_hour": 25}})
        # Must not raise — incr failure in the record step is non-fatal
        await dm.validate_change(0, 10, m)
