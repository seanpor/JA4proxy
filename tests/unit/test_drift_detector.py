# Unit Tests for Drift Detector
# Phase 12c: Score Drift Monitoring & Observability

import json
import time
from unittest.mock import AsyncMock

import pytest

from src.analytics.drift_detector import DriftDetector


@pytest.mark.asyncio
class TestDriftDetector:
    """Test drift detection functionality."""

    async def test_drift_detection_basic(self):
        """Test basic drift detection."""
        mock_redis = AsyncMock()
        
        # Mock baseline data with all required fields
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'mean_score': 60.0,
            'min_score': 50.0,
            'max_score': 70.0,
            'score_distribution': {'55': 30, '60': 40, '65': 30},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        # Mock get responses
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline)
        ]
        
        config = {
            'z_score_threshold': 2.0,
            'check_interval_seconds': 1
        }
        detector = DriftDetector(mock_redis, config)
        
        # Run drift detection
        result = await detector.check_for_drift()
        
        # Should detect drift (z-score = (60-50)/5 = 2.0, which equals threshold)
        assert result is not None
        assert result['drift_detected'] == True
        assert abs(result['z_score']) == 2.0
        assert result['severity'] == 'medium'  # At threshold

    async def test_no_drift(self):
        """Test when no drift is detected."""
        mock_redis = AsyncMock()
        
        # Mock similar baselines with all required fields
        current_baseline = {
            'median_score': 52.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'mean_score': 52.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 20, '50': 40, '55': 40},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline)
        ]
        
        config = {'z_score_threshold': 2.0}
        detector = DriftDetector(mock_redis, config)
        
        # Run drift detection
        result = await detector.check_for_drift()
        
        # Should not detect drift (z-score = 0.4)
        assert result is None

    async def test_high_severity_drift(self):
        """Test high severity drift detection."""
        mock_redis = AsyncMock()
        
        # Mock baselines with large difference
        current_baseline = {
            'median_score': 80.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'mean_score': 80.0,
            'min_score': 70.0,
            'max_score': 90.0,
            'score_distribution': {'75': 20, '80': 60, '85': 20},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline)
        ]
        
        config = {'z_score_threshold': 2.0}
        detector = DriftDetector(mock_redis, config)
        
        # Run drift detection
        result = await detector.check_for_drift()
        
        # Should detect high severity drift (z-score = 6.0)
        assert result is not None
        assert result['drift_detected'] == True
        assert result['z_score'] == 6.0
        assert result['severity'] == 'high'

    async def test_alert_storage(self):
        """Test alert storage in Redis."""
        mock_redis = AsyncMock()
        
        # Mock baselines that will trigger drift
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'mean_score': 60.0,
            'min_score': 50.0,
            'max_score': 70.0,
            'score_distribution': {'55': 30, '60': 40, '65': 30},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline),
            None  # For get_active_alert check
        ]
        
        config = {'z_score_threshold': 1.5}
        detector = DriftDetector(mock_redis, config)
        
        # Run drift detection
        result = await detector.check_for_drift()
        
        # Check that alert was stored
        assert mock_redis.set.called
        call_args = mock_redis.set.call_args_list[-1]
        alert_data = json.loads(call_args[0][1])
        
        assert alert_data['type'] == 'score_drift'
        assert alert_data['severity'] == 'medium'
        assert alert_data['z_score'] == 2.0

    async def test_insufficient_data(self):
        """Test with insufficient data."""
        mock_redis = AsyncMock()
        
        # Mock baselines with low event counts
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 5,  # Too low
            'mean_score': 60.0,
            'min_score': 50.0,
            'max_score': 70.0,
            'score_distribution': {'55': 2, '60': 2, '65': 1},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline)
        ]
        
        config = {'z_score_threshold': 2.0}
        detector = DriftDetector(mock_redis, config)
        
        # Should not run detection with insufficient data
        result = await detector.check_for_drift()
        assert result is None

    async def test_rate_limiting(self):
        """Test rate limiting of drift checks."""
        mock_redis = AsyncMock()
        
        # Mock baselines with all required fields
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'mean_score': 60.0,
            'min_score': 50.0,
            'max_score': 70.0,
            'score_distribution': {'55': 30, '60': 40, '65': 30},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'mean_score': 50.0,
            'min_score': 40.0,
            'max_score': 60.0,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        mock_redis.get.side_effect = [
            json.dumps(current_baseline),
            json.dumps(historical_baseline)
        ]
        
        config = {
            'z_score_threshold': 2.0,
            'check_interval_seconds': 10  # Long interval
        }
        detector = DriftDetector(mock_redis, config)
        
        # First check should work
        result1 = await detector.check_for_drift()
        assert result1 is not None
        
        # Second check should be rate limited (same timestamp)
        result2 = await detector.check_for_drift()
        assert result2 is None

    async def test_alert_retrieval(self):
        """Test alert retrieval."""
        mock_redis = AsyncMock()
        
        # Mock active alert
        alert_data = {
            'type': 'score_drift',
            'severity': 'high',
            'z_score': 3.5,
            'detected_at': time.time(),
            'resolved': False
        }
        
        mock_redis.get.return_value = json.dumps(alert_data)
        
        config = {'z_score_threshold': 2.0}
        detector = DriftDetector(mock_redis, config)
        
        # Get active alert
        alert = await detector.get_active_alert()
        
        assert alert is not None
        assert alert['type'] == 'score_drift'
        assert alert['severity'] == 'high'

    async def test_alert_clearing(self):
        """Test manual alert clearing."""
        mock_redis = AsyncMock()
        
        # Mock active alert
        alert_data = {
            'type': 'score_drift',
            'severity': 'high',
            'detected_at': time.time(),
            'resolved': False
        }
        
        mock_redis.get.return_value = json.dumps(alert_data)
        
        config = {'z_score_threshold': 2.0}
        detector = DriftDetector(mock_redis, config)
        
        # Clear alert
        await detector.clear_alert()
        
        # Check that alert was updated with resolved status
        assert mock_redis.set.called
        call_args = mock_redis.set.call_args_list[-1]
        updated_alert = json.loads(call_args[0][1])
        
        assert updated_alert['resolved'] == True
        assert 'resolved_at' in updated_alert

# ── Missing-coverage tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestDriftDetectorMissingCoverage:
    """Cover remaining paths in DriftDetector (lines 60, 91, 116, 143, 152, 165, 185-216)."""

    async def test_check_for_drift_returns_none_when_no_current_baseline(self):
        """Redis returns None for current baseline → None returned (line 60).
        So what: the detector must not crash when Redis is empty at startup;
        returning None prevents a false drift alert on first boot."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        detector = DriftDetector(mock_redis, {})
        result = await detector.check_for_drift()
        assert result is None

    async def test_analyze_drift_zero_stddev_gives_z_score_zero(self):
        """baseline_stddev == 0 → z_score = 0.0, no division error (line 91).
        So what: a newly-deployed system with zero historical variance must not
        produce NaN/Infinity z-scores that break JSON serialisation to Redis."""
        mock_redis = AsyncMock()
        current = {
            'median_score': 60.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 60.0,
            'min_score': 50.0, 'max_score': 70.0,
            'score_distribution': {}, 'timestamp': __import__('time').time()
        }
        historical = {
            'median_score': 50.0, 'stddev_score': 0.0,  # Zero stddev
            'event_count': 100, 'mean_score': 50.0,
            'min_score': 50.0, 'max_score': 50.0,
            'score_distribution': {}, 'timestamp': __import__('time').time()
        }
        detector = DriftDetector(mock_redis, {})
        result = detector._analyze_drift(current, historical)
        assert result['z_score'] == 0.0

    async def test_determine_severity_low_returns_low(self):
        """z_score at 'low' threshold → returns 'low' (line 116).
        So what: the severity ladder must correctly bucket low-level drift
        so on-call SREs see 'low' not 'info' in dashboards."""
        mock_redis = AsyncMock()
        detector = DriftDetector(mock_redis, {})
        # Default severity_levels["low"] is typically 1.0 or similar
        low_threshold = detector.severity_levels.get("low", 1.0)
        severity = detector._determine_severity(low_threshold)
        assert severity == "low"

    async def test_check_for_drift_returns_none_when_no_historical_baseline(self):
        """Current baseline present but no historical → None returned (line 143).
        So what: the first hour of operation has no history; the detector must
        remain silent rather than alerting on non-existent baseline."""
        mock_redis = AsyncMock()
        current = {
            'median_score': 60.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 60.0,
            'min_score': 50.0, 'max_score': 70.0,
            'score_distribution': {}, 'timestamp': __import__('time').time()
        }
        # First get: current baseline present; second get: no historical
        import json
        mock_redis.get.side_effect = [json.dumps(current), None]
        detector = DriftDetector(mock_redis, {})
        result = await detector.check_for_drift()
        assert result is None

    async def test_check_for_drift_returns_none_when_no_drift_detected(self):
        """Baselines similar → drift_detected=False → returns None (line 152).
        So what: stable traffic must not generate spurious alerts; a false
        positive here wakes the on-call SRE at 3am unnecessarily."""
        mock_redis = AsyncMock()
        import json, time as _time
        current = {
            'median_score': 51.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 51.0,
            'min_score': 40.0, 'max_score': 60.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        historical = {
            'median_score': 50.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 50.0,
            'min_score': 40.0, 'max_score': 60.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        # First check: setup get side effects
        # Need to bypass rate limit: use fresh detector
        mock_redis.get.side_effect = [json.dumps(current), json.dumps(historical)]
        detector = DriftDetector(mock_redis, {'z_score_threshold': 10.0})  # Very high threshold
        result = await detector.check_for_drift()
        assert result is None

    async def test_check_for_drift_no_historical_event_count_returns_none(self):
        """Historical baseline has event_count < 10 → None returned (line 165).
        So what: a historical baseline built from sparse data is statistically
        unreliable; the detector must not alert based on it."""
        mock_redis = AsyncMock()
        import json, time as _time
        current = {
            'median_score': 60.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 60.0,
            'min_score': 50.0, 'max_score': 70.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        historical = {
            'median_score': 50.0, 'stddev_score': 5.0,
            'event_count': 3,  # Too few
            'mean_score': 50.0, 'min_score': 40.0, 'max_score': 60.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        mock_redis.get.side_effect = [json.dumps(current), json.dumps(historical)]
        detector = DriftDetector(mock_redis, {})
        result = await detector.check_for_drift()
        assert result is None

    async def test_get_drift_history_returns_sorted_results(self):
        """get_drift_history() with matching baselines returns sorted list (lines 185-205).
        So what: unsorted history would corrupt the Grafana time-series panel
        used by SREs to correlate drift with deployment events."""
        mock_redis = AsyncMock()
        import json, time as _time
        baseline = {
            'median_score': 60.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 60.0,
            'min_score': 50.0, 'max_score': 70.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        historical = {
            'median_score': 50.0, 'stddev_score': 5.0,
            'event_count': 100, 'mean_score': 50.0,
            'min_score': 40.0, 'max_score': 60.0,
            'score_distribution': {}, 'timestamp': _time.time()
        }
        # Both get calls return data for each hour pair
        mock_redis.get.side_effect = [
            json.dumps(baseline), json.dumps(historical),  # Hour 0
            json.dumps(baseline), json.dumps(historical),  # Hour 1
        ]
        detector = DriftDetector(mock_redis, {'z_score_threshold': 1.0})
        history = await detector.get_drift_history(hours=2)
        assert isinstance(history, list)
        if len(history) >= 2:
            # Should be reverse sorted (most recent first)
            assert history[0]['hour'] >= history[1]['hour']

    async def test_get_current_baseline_for_hour_returns_none_on_miss(self):
        """_get_current_baseline_for_hour() → Redis miss → None returned (line 216).
        So what: a missing hour in Redis is normal; returning None prevents the
        history builder from treating missing hours as zero-drift hours."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        detector = DriftDetector(mock_redis, {})
        result = await detector._get_current_baseline_for_hour("2024-01-01-12")
        assert result is None

    async def test_get_current_baseline_for_hour_parses_json(self):
        """_get_current_baseline_for_hour() → Redis hit → parsed dict (line 214-215).
        So what: if this path is untested, a JSON format change would go
        undetected until production history queries silently return raw strings."""
        mock_redis = AsyncMock()
        import json
        data = {'median_score': 42.0, 'event_count': 50}
        mock_redis.get.return_value = json.dumps(data)
        detector = DriftDetector(mock_redis, {})
        result = await detector._get_current_baseline_for_hour("2024-01-01-12")
        assert result == data


@pytest.mark.asyncio
async def test_get_active_alert_resolved_alert_returns_none():
    """get_active_alert() with resolved=True → returns None (line 165).
    So what: a resolved alert must not be returned to callers as an active alert;
    if it were, dashboards would continuously show a cleared alert as active."""
    from src.analytics.drift_detector import DriftDetector
    import json
    mock_redis = AsyncMock()
    resolved_alert = {
        'type': 'score_drift', 'severity': 'high',
        'z_score': 3.5, 'detected_at': 0.0,
        'resolved': True,  # Already resolved
    }
    mock_redis.get.return_value = json.dumps(resolved_alert)
    detector = DriftDetector(mock_redis, {})
    result = await detector.get_active_alert()
    assert result is None
