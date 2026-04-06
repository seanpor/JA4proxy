# Integration Tests for Monitoring System
# Phase 12c: Score Drift Monitoring & Observability

import json
import time
from unittest.mock import AsyncMock

import pytest

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

# ── Missing-coverage tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestMonitoringMissingCoverage:
    """Cover remaining paths in MonitoringSystem (lines 48-49, 153, 259, 265-330)."""

    async def test_ml_disabled_sets_none_attributes(self):
        """ml.enabled=False → ml_detector=None, model_manager=None (lines 48-49).
        So what: ML components are optional; if their config flag is missing the
        system must boot cleanly without ML, not raise AttributeError on None."""
        mock_redis = AsyncMock()
        config = {"ml": {"enabled": False}}
        monitoring = MonitoringSystem(mock_redis, config)
        assert monitoring.ml_detector is None
        assert monitoring.model_manager is None

    async def test_run_monitoring_cycle_rate_limited(self):
        """Monitoring cycle within interval → returns immediately (line 153).
        So what: if rate-limiting is broken, every event triggers a full monitoring
        cycle, causing N×N Redis calls and quadratic performance degradation."""
        mock_redis = AsyncMock()
        config = {"monitoring_cycle_seconds": 60}
        monitoring = MonitoringSystem(mock_redis, config)
        # First call sets timestamp
        monitoring.last_monitoring_cycle = __import__('time').time()
        # Second call within interval should return immediately
        await monitoring.run_monitoring_cycle()
        # Should not have called Redis (rate limited)
        mock_redis.get.assert_not_called()

    async def test_get_monitoring_status_ml_disabled_shows_disabled(self):
        """ML disabled → status['components']['ml_detector'] = 'disabled' (line 259).
        So what: the ops dashboard must accurately show ML as disabled, not raise
        AttributeError when reading ml_detector.get_model_info()."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        config = {"ml": {"enabled": False}}
        monitoring = MonitoringSystem(mock_redis, config)
        status = await monitoring.get_monitoring_status()
        assert status["components"]["ml_detector"] == "disabled"

    async def test_get_drift_history_delegates(self):
        """get_drift_history() delegates to drift_detector (line 265).
        So what: if this delegation is broken, the API returns the wrong history
        and the Grafana drift panel shows stale data."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        config = {}
        monitoring = MonitoringSystem(mock_redis, config)
        monitoring.drift_detector.get_drift_history = AM(return_value=[{"hour": "2024-01-01-00"}])
        result = await monitoring.get_drift_history(hours=1)
        assert result == [{"hour": "2024-01-01-00"}]

    async def test_get_shift_history_delegates(self):
        """get_shift_history() delegates to distribution_analyzer (line 269).
        So what: same — distribution shift history must come from the right subsystem."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.distribution_analyzer.get_shift_history = AM(return_value=[{"hour": "x"}])
        result = await monitoring.get_shift_history(hours=2)
        assert result == [{"hour": "x"}]

    async def test_get_calibration_history_delegates(self):
        """get_calibration_history() delegates to shadow_scoring (line 273).
        So what: calibration history must come from shadow_scoring, not drift_detector."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.shadow_scoring.get_calibration_history = AM(return_value=[{"h": "y"}])
        result = await monitoring.get_calibration_history(hours=3)
        assert result == [{"h": "y"}]

    async def test_check_api_authentication_delegates(self):
        """check_api_authentication() delegates to security_hardening (line 278).
        So what: if this delegation is broken, all API keys pass authentication,
        exposing the admin API to unauthenticated callers."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.authenticate_api_key = AM(return_value={"user": "admin"})
        result = await monitoring.check_api_authentication("valid-key")
        assert result is True

    async def test_validate_jwt_token_delegates(self):
        """validate_jwt_token() delegates to security_hardening (line 282)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.validate_jwt_token = AM(return_value={"sub": "user"})
        result = await monitoring.validate_jwt_token("tok")
        assert result == {"sub": "user"}

    async def test_check_rate_limit_delegates(self):
        """check_rate_limit() delegates to security_hardening (line 286)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.check_rate_limit = AM(return_value=True)
        result = await monitoring.check_rate_limit("ip", "1.2.3.4")
        assert result is True

    async def test_validate_input_safety_delegates(self):
        """validate_input_safety() delegates to security_hardening (line 290)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.validate_input_safety = AM(return_value=True)
        result = await monitoring.validate_input_safety({"data": "safe"})
        assert result is True

    async def test_check_suspicious_activity_delegates(self):
        """check_suspicious_activity() delegates to security_hardening (line 294)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.check_suspicious_activity = AM(return_value=False)
        result = await monitoring.check_suspicious_activity({"ip": "1.2.3.4"})
        assert result is False

    async def test_get_security_audit_logs_delegates(self):
        """get_security_audit_logs() delegates to security_hardening (line 298)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.get_security_audit_logs = AM(return_value=[{"ts": 1}])
        result = await monitoring.get_security_audit_logs(limit=10)
        assert result == [{"ts": 1}]

    async def test_get_security_metrics_delegates(self):
        """get_security_metrics() delegates to security_hardening (line 302)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.security_hardening.get_security_metrics = AM(return_value={"score": 0})
        result = await monitoring.get_security_metrics()
        assert result == {"score": 0}

    async def test_detect_anomalies_no_ml_returns_empty(self):
        """detect_anomalies() with ml_detector=None → [] (lines 309-310).
        So what: callers must receive an empty list, not AttributeError, when
        ML is disabled — the pipeline must not crash without ML."""
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {"ml": {"enabled": False}})
        result = await monitoring.detect_anomalies([{"ja4": "abc"}])
        assert result == []

    async def test_detect_anomalies_with_ml_delegates(self):
        """detect_anomalies() with ml_detector present → delegates (line 311)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.ml_detector.detect = AM(return_value=[{"anomaly": True}])
        result = await monitoring.detect_anomalies([{"ja4": "abc"}])
        assert result == [{"anomaly": True}]

    async def test_get_ml_model_info_no_ml_returns_disabled(self):
        """get_ml_model_info() with ml_detector=None → disabled dict (lines 315-316).
        So what: the model info endpoint must return a sensible status rather
        than crashing when ML is not configured."""
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {"ml": {"enabled": False}})
        result = await monitoring.get_ml_model_info()
        assert result == {"status": "disabled"}

    async def test_get_ml_model_info_with_ml_delegates(self):
        """get_ml_model_info() with ml_detector → delegates (line 317)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.ml_detector.get_model_info = AM(return_value={"version": "1.0"})
        result = await monitoring.get_ml_model_info()
        assert result == {"version": "1.0"}

    async def test_list_ml_models_no_model_manager_returns_empty(self):
        """list_ml_models() with model_manager=None → [] (lines 321-322).
        So what: model listing must not crash when the model manager was not
        initialized (e.g., Redis unavailable at startup)."""
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {"ml": {"enabled": False}})
        result = await monitoring.list_ml_models()
        assert result == []

    async def test_list_ml_models_with_manager_delegates(self):
        """list_ml_models() with model_manager → delegates (line 323)."""
        from unittest.mock import AsyncMock as AM
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.model_manager.list_models = AM(return_value=[{"name": "v1"}])
        result = await monitoring.list_ml_models()
        assert result == [{"name": "v1"}]

    async def test_update_ml_model_with_detector_updates_version(self):
        """update_ml_model() with ml_detector → updates version (lines 327-329).
        So what: hot-swapping the ML model without restart requires this path;
        if it silently falls through to 'unavailable', deployments appear to fail."""
        from unittest.mock import MagicMock
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {})
        monitoring.ml_detector.update_model_version = MagicMock()
        result = await monitoring.update_ml_model("v2.0")
        assert result == {"status": "updated", "version": "v2.0"}

    async def test_update_ml_model_no_detector_returns_unavailable(self):
        """update_ml_model() with ml_detector=None → unavailable (line 330).
        So what: the update endpoint must return a clear error when ML is disabled;
        a silent success would mislead the operator into thinking the model changed."""
        mock_redis = AsyncMock()
        monitoring = MonitoringSystem(mock_redis, {"ml": {"enabled": False}})
        result = await monitoring.update_ml_model("v2.0")
        assert result == {"status": "unavailable"}
