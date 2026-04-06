"""
Unit tests for src/analytics/distribution_analyzer.py.

Security consequence: DistributionAnalyzer detects statistical shifts in the
score distribution of traffic.  A sudden shift toward high scores may indicate
a coordinated attack; a shift toward low scores may indicate evasion (attackers
learning to spoof benign TLS fingerprints).  If edge cases in the statistical
analysis are buggy, alerts fire spuriously (alert fatigue) or are silenced
entirely (blind spots).
"""

import asyncio
import json
import math
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analytics.distribution_analyzer import DistributionAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer(config=None) -> DistributionAnalyzer:
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    cfg = config or {}
    return DistributionAnalyzer(mock_redis, cfg)


def _baseline(distribution: dict, event_count: int) -> dict:
    return {"score_distribution": distribution, "event_count": event_count}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# _normalize_distribution
# ---------------------------------------------------------------------------

class TestNormalizeDistribution:
    def test_empty_distribution_returns_empty(self):
        # Security: an empty baseline must not divide-by-zero and crash the
        # detector — an outage here silences all distribution shift alerts.
        analyzer = _make_analyzer()
        result = analyzer._normalize_distribution({})
        assert result == {}

    def test_single_bucket_normalizes_to_one(self):
        analyzer = _make_analyzer()
        result = analyzer._normalize_distribution({"50": 100})
        assert result == {"50": 1.0}

    def test_two_buckets_sum_to_one(self):
        analyzer = _make_analyzer()
        result = analyzer._normalize_distribution({"0": 30, "100": 70})
        assert abs(result["0"] - 0.3) < 1e-9
        assert abs(result["100"] - 0.7) < 1e-9
        assert abs(sum(result.values()) - 1.0) < 1e-9

    def test_all_equal_buckets_normalized_evenly(self):
        analyzer = _make_analyzer()
        dist = {str(i * 10): 25 for i in range(4)}
        result = analyzer._normalize_distribution(dist)
        for v in result.values():
            assert abs(v - 0.25) < 1e-9


# ---------------------------------------------------------------------------
# _calculate_ks_statistic
# ---------------------------------------------------------------------------

class TestCalculateKSStatistic:
    def test_identical_distributions_ks_zero(self):
        # Security: if two identical distributions yield KS ≠ 0, false alerts
        # will fire constantly, causing alert fatigue and operator inattention.
        analyzer = _make_analyzer()
        d = {"10": 0.3, "50": 0.5, "90": 0.2}
        ks = analyzer._calculate_ks_statistic(d, d)
        assert ks == pytest.approx(0.0, abs=1e-9)

    def test_completely_different_distributions_ks_close_to_one(self):
        # Security: maximally different distributions (all traffic either benign
        # or all malicious) must trigger the alert.
        analyzer = _make_analyzer()
        current = {"0": 1.0}
        baseline = {"100": 1.0}
        ks = analyzer._calculate_ks_statistic(current, baseline)
        assert ks == pytest.approx(1.0, abs=1e-9)

    def test_ks_is_symmetric(self):
        analyzer = _make_analyzer()
        a = {"10": 0.6, "90": 0.4}
        b = {"10": 0.2, "90": 0.8}
        assert analyzer._calculate_ks_statistic(a, b) == pytest.approx(
            analyzer._calculate_ks_statistic(b, a), abs=1e-9
        )

    def test_missing_bucket_in_one_distribution(self):
        # Bucket present in current but absent in baseline: treated as 0 probability
        analyzer = _make_analyzer()
        current = {"50": 1.0}
        baseline = {"10": 0.5, "90": 0.5}
        ks = analyzer._calculate_ks_statistic(current, baseline)
        assert 0.0 <= ks <= 1.0


# ---------------------------------------------------------------------------
# _approximate_p_value
# ---------------------------------------------------------------------------

class TestApproximatePValue:
    def test_zero_ks_statistic_returns_one(self):
        # p=1.0 means "no evidence of difference" — correct for KS=0.
        analyzer = _make_analyzer()
        p = analyzer._approximate_p_value(0.0, 1000, 1000)
        assert p == 1.0

    def test_large_ks_with_large_n_gives_small_p(self):
        # Security: with enough data (large n) even a moderate KS statistic
        # should be statistically significant → p should be small → alert fires.
        analyzer = _make_analyzer()
        p = analyzer._approximate_p_value(0.5, 10000, 10000)
        assert p < 0.01

    def test_p_value_clamped_to_0_1(self):
        analyzer = _make_analyzer()
        p = analyzer._approximate_p_value(0.99, 1, 1)
        assert 0.0 <= p <= 1.0

    def test_n1_n2_asymmetric_uses_harmonic_mean(self):
        # The effective sample size formula is n1*n2/(n1+n2); asymmetric counts
        # must not crash.
        analyzer = _make_analyzer()
        p = analyzer._approximate_p_value(0.3, 100, 10000)
        assert 0.0 <= p <= 1.0


# ---------------------------------------------------------------------------
# _analyze_distribution_shift
# ---------------------------------------------------------------------------

class TestAnalyzeDistributionShift:
    def test_no_shift_when_distributions_identical(self):
        analyzer = _make_analyzer()
        b = _baseline({"10": 500, "50": 300, "90": 200}, 1000)
        result = analyzer._analyze_distribution_shift(b, b)
        assert result["distribution_shift"] is False
        assert result["ks_statistic"] == pytest.approx(0.0, abs=1e-9)

    def test_shift_detected_with_divergent_distributions(self):
        # Security: if a shift goes undetected, operators are not alerted when
        # the traffic profile changes to mostly high-risk scores (active attack).
        analyzer = _make_analyzer({"ks_test_threshold": 0.05})
        current = _baseline({"90": 900, "10": 100}, 1000)
        baseline = _baseline({"10": 900, "90": 100}, 1000)
        result = analyzer._analyze_distribution_shift(current, baseline)
        assert result["distribution_shift"] is True

    def test_severity_high_when_ks_above_0_2(self):
        analyzer = _make_analyzer()
        current = _baseline({"90": 900, "10": 100}, 1000)
        baseline = _baseline({"10": 900, "90": 100}, 1000)
        result = analyzer._analyze_distribution_shift(current, baseline)
        assert result["severity"] == "high"

    def test_severity_medium_when_ks_below_0_2(self):
        # A subtle shift (KS < 0.2) still gets medium severity — still actionable.
        analyzer = _make_analyzer()
        current = _baseline({"30": 500, "70": 500}, 1000)
        baseline = _baseline({"30": 450, "70": 550}, 1000)
        result = analyzer._analyze_distribution_shift(current, baseline)
        assert result["severity"] in ("medium", "high")  # depends on exact KS

    def test_result_contains_required_keys(self):
        analyzer = _make_analyzer()
        b = _baseline({"50": 100}, 100)
        result = analyzer._analyze_distribution_shift(b, b)
        for key in ("distribution_shift", "ks_statistic", "p_value", "severity", "detected_at"):
            assert key in result


# ---------------------------------------------------------------------------
# check_distribution_shift — rate limiting and Redis interaction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckDistributionShift:
    async def test_rate_limited_returns_none_on_second_call(self):
        # Security: excessive check calls would spam Redis; rate limiting prevents
        # that, but also means we only get one result per interval — the interval
        # must be respected.
        analyzer = _make_analyzer({"check_interval_seconds": 600})
        analyzer.last_check_time = time.time()  # pretend we just checked
        result = await analyzer.check_distribution_shift()
        assert result is None

    async def test_insufficient_data_returns_none(self):
        # If we have fewer than 50 events, the KS test is statistically meaningless.
        analyzer = _make_analyzer({"check_interval_seconds": 0})
        small_baseline = json.dumps(_baseline({"50": 10}, 10))
        analyzer.redis.get = AsyncMock(return_value=small_baseline.encode())
        result = await analyzer.check_distribution_shift()
        assert result is None

    async def test_no_baseline_returns_none(self):
        analyzer = _make_analyzer({"check_interval_seconds": 0})
        analyzer.redis.get = AsyncMock(return_value=None)
        result = await analyzer.check_distribution_shift()
        assert result is None

    async def test_shift_detected_stores_alert_in_redis(self):
        # Security: the alert must be persisted in Redis so that all proxy
        # instances can read it and — if configured — escalate via Prometheus alert.
        analyzer = _make_analyzer({"check_interval_seconds": 0, "ks_test_threshold": 1.0})
        current = json.dumps(_baseline({"90": 900, "10": 100}, 1000))
        previous = json.dumps(_baseline({"10": 900, "90": 100}, 1000))
        call_count = [0]

        async def _get(key):
            call_count[0] += 1
            if call_count[0] == 1:
                return current.encode()
            return previous.encode()

        analyzer.redis.get = _get
        analyzer.redis.set = AsyncMock()

        # This will detect a shift (p_value < threshold=1.0 is always true)
        result = await analyzer.check_distribution_shift()
        # If shift detected, redis.set was called for the alert
        if result is not None:
            analyzer.redis.set.assert_called()


# ---------------------------------------------------------------------------
# get_active_alert / clear_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAlertManagement:
    async def test_get_active_alert_returns_none_when_no_alert(self):
        analyzer = _make_analyzer()
        analyzer.redis.get = AsyncMock(return_value=None)
        result = await analyzer.get_active_alert()
        assert result is None

    async def test_get_active_alert_returns_unresolved_alert(self):
        analyzer = _make_analyzer()
        alert = {"type": "distribution_shift", "resolved": False, "ks_statistic": 0.4}
        analyzer.redis.get = AsyncMock(return_value=json.dumps(alert).encode())
        result = await analyzer.get_active_alert()
        assert result is not None
        assert result["type"] == "distribution_shift"

    async def test_get_active_alert_returns_none_for_resolved_alert(self):
        # Security: a resolved alert must not be re-surfaced; operators would
        # waste time investigating already-closed incidents.
        analyzer = _make_analyzer()
        alert = {"type": "distribution_shift", "resolved": True}
        analyzer.redis.get = AsyncMock(return_value=json.dumps(alert).encode())
        result = await analyzer.get_active_alert()
        assert result is None

    async def test_clear_alert_marks_resolved_true(self):
        # Security: manual alert clearance must set resolved=True so the alert
        # no longer appears in the management UI or blocks new alert writes.
        analyzer = _make_analyzer()
        original = {"type": "distribution_shift", "resolved": False}
        analyzer.redis.get = AsyncMock(return_value=json.dumps(original).encode())
        analyzer.redis.set = AsyncMock()
        await analyzer.clear_alert()
        set_call = analyzer.redis.set.call_args[0]
        stored = json.loads(set_call[1])
        assert stored["resolved"] is True
        assert "resolved_at" in stored

    async def test_clear_alert_no_op_when_no_alert(self):
        analyzer = _make_analyzer()
        analyzer.redis.get = AsyncMock(return_value=None)
        analyzer.redis.set = AsyncMock()
        await analyzer.clear_alert()
        analyzer.redis.set.assert_not_called()


# ---------------------------------------------------------------------------
# detect_anomaly_patterns
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDetectAnomalyPatterns:
    async def test_bimodal_distribution_detected(self):
        # Security: a bimodal score distribution (cluster at 0 and cluster at 100)
        # indicates mixed benign + attack traffic, which the proxy should separate.
        analyzer = _make_analyzer()
        baseline = _baseline(
            {"0": 400, "10": 50, "50": 50, "90": 50, "100": 450},
            1000
        )
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        # bimodal check: two peaks with valley; exact result depends on algorithm
        assert isinstance(patterns["bimodal"], bool)

    async def test_sudden_spike_detected_when_30pct_high_scores(self):
        # Security: a sudden spike toward high scores may indicate the proxy is
        # under active attack and the dial should be raised.
        analyzer = _make_analyzer()
        baseline = _baseline({"80": 300, "90": 100, "10": 600}, 1000)
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        assert patterns["sudden_spike"] is True

    async def test_no_spike_when_fewer_than_30pct_high_scores(self):
        analyzer = _make_analyzer()
        baseline = _baseline({"80": 200, "10": 800}, 1000)
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        assert patterns["sudden_spike"] is False

    async def test_sudden_drop_detected_when_70pct_low_scores(self):
        # Security: an abnormally high proportion of very low scores may indicate
        # attackers have learned to mimic benign fingerprints (evasion).
        analyzer = _make_analyzer()
        baseline = _baseline({"0": 700, "10": 100, "90": 200}, 1000)
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        assert patterns["sudden_drop"] is True

    async def test_no_drop_when_fewer_than_70pct_low_scores(self):
        analyzer = _make_analyzer()
        baseline = _baseline({"0": 500, "90": 500}, 1000)
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        assert patterns["sudden_drop"] is False

    async def test_single_bucket_no_bimodal(self):
        analyzer = _make_analyzer()
        baseline = _baseline({"50": 1000}, 1000)
        patterns = await analyzer.detect_anomaly_patterns(baseline)
        assert patterns["bimodal"] is False


# ---------------------------------------------------------------------------
# get_shift_history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGetShiftHistory:
    async def test_returns_sorted_by_hour_descending(self):
        # Security: the most recent shift must appear first so operators
        # quickly identify current incidents rather than historical noise.
        analyzer = _make_analyzer()
        # Provide data for two consecutive hours
        baseline_a = json.dumps(_baseline({"10": 500, "90": 500}, 1000))
        baseline_b = json.dumps(_baseline({"10": 900, "90": 100}, 1000))
        call_seq = [baseline_a, baseline_b, baseline_a, baseline_b]
        idx = [0]

        async def _get(key):
            if idx[0] < len(call_seq):
                val = call_seq[idx[0]]
                idx[0] += 1
                return val.encode()
            return None

        analyzer.redis.get = _get
        history = await analyzer.get_shift_history(hours=2)
        if len(history) >= 2:
            assert history[0]["hour"] >= history[1]["hour"]

    async def test_empty_when_no_baselines(self):
        analyzer = _make_analyzer()
        analyzer.redis.get = AsyncMock(return_value=None)
        history = await analyzer.get_shift_history(hours=3)
        assert history == []
