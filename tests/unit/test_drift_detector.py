# Unit Tests for Drift Detector
# Phase 12c: Score Drift Monitoring & Observability

import pytest
import time
import json
from unittest.mock import AsyncMock
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