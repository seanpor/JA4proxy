# Integration Tests for Monitoring System
# Phase 12c: Score Drift Monitoring & Observability

import pytest
import time
import json
from unittest.mock import AsyncMock
from src.analytics.monitoring import MonitoringSystem


@pytest.mark.asyncio
class TestMonitoringIntegration:
    """Test integrated monitoring system functionality."""

    async def test_full_monitoring_cycle(self):
        """Test complete monitoring cycle."""
        mock_redis = AsyncMock()
        
        # Mock baseline data for drift detection
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'score_distribution': {'50': 20, '55': 30, '60': 50},
            'timestamp': time.time()
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'score_distribution': {'45': 30, '50': 60, '55': 30},
            'timestamp': time.time() - 3600
        }
        
        # Mock shadow scores
        shadow_stats = {
            'median': 8.0,  # Below threshold
            'mean': 7.5,
            'stddev': 2.0,
            'count': 50
        }
        
        # Setup mock responses
        call_count = 0
        async def mock_get(key):
            nonlocal call_count
            call_count += 1
            
            if 'baseline:hourly' in key:
                if call_count == 1:
                    return json.dumps(current_baseline)
                else:
                    return json.dumps(historical_baseline)
            elif 'shadow_scores' in key:
                return json.dumps(shadow_stats)
            elif 'score_drift' in key:
                return json.dumps({
                    'type': 'score_drift',
                    'severity': 'medium',
                    'z_score': 2.0,
                    'detected_at': time.time(),
                    'resolved': False
                })
            elif 'distribution_shift' in key:
                return json.dumps({
                    'type': 'distribution_shift',
                    'severity': 'high',
                    'ks_statistic': 0.55,
                    'detected_at': time.time(),
                    'resolved': False
                })
            elif 'calibration_issue' in key:
                return None
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system
        config = {
            'baseline': {'capture_interval_seconds': 3600},
            'drift_detection': {'z_score_threshold': 1.5, 'check_interval_seconds': 1},
            'distribution_analysis': {'ks_test_threshold': 0.05, 'check_interval_seconds': 1},
            'shadow_scoring': {'calibration_threshold': 10.0, 'check_interval_seconds': 1},
            'monitoring_cycle_seconds': 1
        }
        
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Update with events (need at least 10 for drift detection)
        events = [
            {'score': 55, 'alpn': 'h2'},
            {'score': 60, 'alpn': 'h1'},
            {'score': 62, 'alpn': 'h2'},
            {'score': 58, 'alpn': 'h2'},
            {'score': 61, 'alpn': 'h1'},
            {'score': 63, 'alpn': 'h2'},
            {'score': 59, 'alpn': 'h2'},
            {'score': 64, 'alpn': 'h1'},
            {'score': 60, 'alpn': 'h2'},
            {'score': 61, 'alpn': 'h1'}
        ]
        
        for event in events:
            await monitoring.update_with_event(event)
        
        # Mock the baseline monitor to return our test data
        async def mock_get_current_baseline():
            return current_baseline
        
        async def mock_get_historical_baseline(hour_str):
            return historical_baseline
        
        monitoring.baseline_monitor.get_current_baseline = mock_get_current_baseline
        monitoring.drift_detector._get_current_baseline = mock_get_current_baseline
        monitoring.drift_detector._get_historical_baseline = mock_get_historical_baseline
        monitoring.distribution_analyzer._get_current_baseline = mock_get_current_baseline
        monitoring.distribution_analyzer._get_historical_baseline = mock_get_historical_baseline
        
        # Run monitoring cycle
        await monitoring.run_monitoring_cycle()
        
        # Check that drift was detected
        drift_alert = await monitoring.drift_detector.get_active_alert()
        assert drift_alert is not None
        assert drift_alert['type'] == 'score_drift'
        assert drift_alert['z_score'] == 2.0
        
        # Check that distribution shift was detected
        dist_alert = await monitoring.distribution_analyzer.get_active_alert()
        assert dist_alert is not None
        assert dist_alert['type'] == 'distribution_shift'
        assert dist_alert['ks_statistic'] == 0.55
        
        # Check that no calibration issue was detected (shadow median = 8 < threshold = 10)
        cal_alert = await monitoring.shadow_scoring.get_active_alert()
        assert cal_alert is None
        
        # Get monitoring status
        status = await monitoring.get_monitoring_status()
        assert status['metrics']['active_alerts'] == 2  # Drift and distribution
        assert status['components']['baseline_monitor'] == 'healthy'

    async def test_calibration_issue_detection(self):
        """Test calibration issue detection."""
        mock_redis = AsyncMock()
        
        # Mock baseline data
        current_baseline = {
            'median_score': 55.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'score_distribution': {'50': 20, '55': 30, '60': 50}
        }
        
        # Mock shadow scores with high median (calibration issue)
        shadow_stats = {
            'median': 15.0,  # Above threshold
            'mean': 14.0,
            'stddev': 3.0,
            'count': 50
        }
        
        def mock_get(key):
            if 'baseline:hourly' in key:
                return json.dumps(current_baseline)
            elif 'shadow_scores' in key:
                return json.dumps(shadow_stats)
            elif 'calibration_issue' in key:
                return json.dumps({
                    'type': 'calibration_issue',
                    'severity': 'high',
                    'detected_at': time.time(),
                    'resolved': False
                })
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system
        config = {
            'shadow_scoring': {'calibration_threshold': 10.0, 'check_interval_seconds': 1}
        }
        
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Update with known-good traffic
        events = [
            {'score': 12, 'alpn': 'h2'},
            {'score': 18, 'alpn': 'h1'},
            {'score': 15, 'alpn': 'h2'}
        ]
        
        for event in events:
            await monitoring.update_with_event(event)
        
        # Run monitoring cycle
        await monitoring.run_monitoring_cycle()
        
        # Check that calibration issue was detected
        cal_alert = await monitoring.shadow_scoring.get_active_alert()
        assert cal_alert is not None
        assert cal_alert['type'] == 'calibration_issue'
        assert cal_alert['severity'] == 'high'

    async def test_alert_management(self):
        """Test alert management functionality."""
        mock_redis = AsyncMock()
        
        # Mock active alerts
        drift_alert = {
            'type': 'score_drift',
            'severity': 'high',
            'z_score': 3.0,
            'detected_at': time.time(),
            'resolved': False
        }
        
        dist_alert = {
            'type': 'distribution_shift',
            'severity': 'medium',
            'ks_statistic': 0.15,
            'detected_at': time.time(),
            'resolved': False
        }
        
        def mock_get(key):
            if 'score_drift' in key:
                return json.dumps(drift_alert)
            elif 'distribution_shift' in key:
                return json.dumps(dist_alert)
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system
        config = {}
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Get all alerts
        alerts = await monitoring.get_alerts()
        
        assert alerts['score_drift'] is not None
        assert alerts['distribution_shift'] is not None
        assert alerts['calibration_issue'] is None
        
        # Clear all alerts
        await monitoring.clear_all_alerts()
        
        # Verify alerts were marked as resolved
        assert mock_redis.set.call_count == 2
        for call in mock_redis.set.call_args_list:
            alert_data = json.loads(call[0][1])
            assert alert_data['resolved'] == True

    async def test_metrics_update(self):
        """Test Prometheus metrics update."""
        mock_redis = AsyncMock()
        
        # Mock baseline data
        current_baseline = {
            'median_score': 55.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'score_distribution': {'50': 20, '55': 30, '60': 50}
        }
        
        shadow_stats = {
            'median': 8.0,
            'mean': 7.5,
            'stddev': 2.0,
            'count': 50
        }
        
        def mock_get(key):
            if 'baseline:hourly' in key:
                return json.dumps(current_baseline)
            elif 'shadow_scores' in key:
                return json.dumps(shadow_stats)
            elif 'score_drift' in key:
                return json.dumps({
                    'type': 'score_drift',
                    'severity': 'high',
                    'detected_at': time.time(),
                    'resolved': False
                })
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system
        config = {}
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Mock the baseline monitor to return our test data
        async def mock_get_current_baseline():
            return current_baseline
        
        monitoring.baseline_monitor.get_current_baseline = mock_get_current_baseline
        
        # Update metrics
        await monitoring._update_metrics()
        
        # Check that gauges were set
        assert monitoring.score_median_gauge._value.get() == 55.0
        assert monitoring.score_drift_detected_gauge._value.get() == 1.0
        assert monitoring.shadow_score_median_gauge._value.get() == 8.0

    async def test_disabled_components(self):
        """Test behavior when monitoring is disabled."""
        mock_redis = AsyncMock()
        
        # Mock baseline data
        current_baseline = {
            'median_score': 55.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'score_distribution': {'50': 20, '55': 30, '60': 50}
        }
        
        shadow_stats = {
            'median': 8.0,
            'mean': 7.5,
            'stddev': 2.0,
            'count': 50
        }
        
        def mock_get(key):
            if 'baseline:hourly' in key:
                return json.dumps(current_baseline)
            elif 'shadow_scores' in key:
                return json.dumps(shadow_stats)
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system with disabled components
        config = {
            'drift_detection': {'enabled': False},
            'distribution_analysis': {'enabled': False},
            'shadow_scoring': {'enabled': False}
        }
        
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Update with event
        event = {'score': 50, 'alpn': 'h2'}
        await monitoring.update_with_event(event)
        
        # Run monitoring cycle
        await monitoring.run_monitoring_cycle()
        
        # Check that no alerts were generated
        alerts = await monitoring.get_alerts()
        assert alerts['score_drift'] is None
        assert alerts['distribution_shift'] is None
        assert alerts['calibration_issue'] is None

    async def test_performance_metrics(self):
        """Test performance metrics collection."""
        mock_redis = AsyncMock()
        
        # Mock baseline data
        current_baseline = {
            'median_score': 60.0,
            'stddev_score': 5.0,
            'event_count': 100,
            'score_distribution': {'50': 20, '55': 30, '60': 50}
        }
        
        historical_baseline = {
            'median_score': 50.0,
            'stddev_score': 5.0,
            'event_count': 120,
            'score_distribution': {'45': 30, '50': 60, '55': 30}
        }
        
        shadow_stats = {
            'median': 8.0,
            'mean': 7.5,
            'stddev': 2.0,
            'count': 50
        }
        
        def mock_get(key):
            if 'baseline:hourly' in key:
                if 'current' in key or 'baseline:hourly:' in key:
                    return json.dumps(current_baseline)
                else:
                    return json.dumps(historical_baseline)
            elif 'shadow_scores' in key:
                return json.dumps(shadow_stats)
            else:
                return None
        
        mock_redis.get.side_effect = mock_get
        
        # Create monitoring system
        config = {
            'drift_detection': {'check_interval_seconds': 1},
            'distribution_analysis': {'check_interval_seconds': 1},
            'shadow_scoring': {'check_interval_seconds': 1}
        }
        
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Run monitoring cycle to collect performance metrics
        await monitoring.run_monitoring_cycle()
        
        # Check that performance metrics were recorded
        assert len(monitoring.drift_check_duration._buckets) > 0
        assert len(monitoring.distribution_check_duration._buckets) > 0
        assert len(monitoring.calibration_check_duration._buckets) > 0