# Monitoring System Integration
# Phase 12c: Score Drift Monitoring & Observability

import time
import logging
from typing import Dict, Any, Optional, List
import redis.asyncio as redis
from prometheus_client import Gauge, Histogram

from .baseline_monitor import BaselineMonitor
from .drift_detector import DriftDetector
from .distribution_analyzer import DistributionAnalyzer
from .shadow_scoring import ShadowScoring
from .security_hardening import SecurityHardening
from .ml_detector import MLDetector, MLModelManager


class MonitoringSystem:
    """Integrated monitoring system for score health and observability."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize monitoring components
        self.baseline_monitor = BaselineMonitor(redis_conn, config.get('baseline', {}))
        self.drift_detector = DriftDetector(redis_conn, config.get('drift_detection', {}))
        self.distribution_analyzer = DistributionAnalyzer(redis_conn, config.get('distribution_analysis', {}))
        self.shadow_scoring = ShadowScoring(redis_conn, config.get('shadow_scoring', {}))
        
        # Initialize security hardening (Phase 12d)
        self.security_hardening = SecurityHardening(redis_conn, config)
        
        # Initialize ML detector (Phase 12e)
        ml_config = config.get('ml', {})
        if ml_config.get('enabled', True):
            self.ml_detector = MLDetector(redis_conn, ml_config)
            self.model_manager = MLModelManager(redis_conn)
        else:
            self.ml_detector = None
            self.model_manager = None
        
        # Initialize Prometheus metrics
        self._init_metrics()
        
        # Tracking
        self.last_monitoring_cycle = 0
        self.monitoring_interval = config.get('monitoring_cycle_seconds', 60)

    def _init_metrics(self):
        """Initialize Prometheus metrics."""
        # Use separate registry to avoid conflicts in tests
        from prometheus_client import CollectorRegistry
        self.registry = CollectorRegistry()
        
        # Score health metrics
        self.score_median_gauge = Gauge(
            'ja4proxy_analytics_score_median',
            'Current median risk score',
            registry=self.registry
        )
        
        self.score_drift_detected_gauge = Gauge(
            'ja4proxy_analytics_score_drift_detected',
            '1 if score drift detected, 0 otherwise',
            registry=self.registry
        )
        
        self.distribution_shift_gauge = Gauge(
            'ja4proxy_analytics_distribution_shift',
            '1 if score distribution shifted significantly',
            registry=self.registry
        )
        
        self.shadow_score_median_gauge = Gauge(
            'ja4proxy_analytics_shadow_score_median',
            'Current median shadow score for known-good traffic',
            registry=self.registry
        )
        
        self.calibration_issue_gauge = Gauge(
            'ja4proxy_analytics_calibration_issue',
            '1 if calibration issue detected, 0 otherwise',
            registry=self.registry
        )
        
        # Performance metrics
        self.drift_check_duration = Histogram(
            'ja4proxy_analytics_drift_check_duration',
            'Duration of drift detection checks',
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry
        )
        
        self.distribution_check_duration = Histogram(
            'ja4proxy_analytics_distribution_check_duration',
            'Duration of distribution analysis checks',
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry
        )
        
        self.calibration_check_duration = Histogram(
            'ja4proxy_analytics_calibration_check_duration',
            'Duration of calibration checks',
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry
        )
        
        # ML metrics (Phase 12e)
        self.ml_detection_duration = Histogram(
            'ja4proxy_analytics_ml_detection_duration',
            'Duration of ML anomaly detection',
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0],
            registry=self.registry
        )
        
        self.ml_anomalies_gauge = Gauge(
            'ja4proxy_analytics_ml_anomalies_detected',
            'Number of anomalies detected by ML model',
            registry=self.registry
        )
        
        self.ml_model_version_gauge = Gauge(
            'ja4proxy_analytics_ml_model_version',
            'Current ML model version',
            registry=self.registry
        )

    async def update_with_event(self, event: Dict[str, Any]):
        """Update monitoring system with a new event."""
        # Update baseline monitor with score
        if 'score' in event:
            await self.baseline_monitor.update_with_score(event['score'])
        
        # Update shadow scoring
        await self.shadow_scoring.update_with_event(event)

    async def run_monitoring_cycle(self):
        """Run complete monitoring cycle."""
        current_time = time.time()
        
        # Rate limit monitoring cycles
        if current_time - self.last_monitoring_cycle < self.monitoring_interval:
            return
        
        self.last_monitoring_cycle = current_time
        
        # Update metrics from current state
        await self._update_metrics()
        
        # Run detection checks
        await self._run_detection_checks()

    async def _update_metrics(self):
        """Update Prometheus metrics with current state."""
        # Get current baseline
        current_baseline = await self.baseline_monitor.get_current_baseline()
        if current_baseline:
            self.score_median_gauge.set(current_baseline['median_score'])
        
        # Get shadow scores
        shadow_stats = await self.shadow_scoring._get_shadow_scores()
        if shadow_stats:
            self.shadow_score_median_gauge.set(shadow_stats['median'])
        
        # Check for active alerts
        drift_alert = await self.drift_detector.get_active_alert()
        self.score_drift_detected_gauge.set(1.0 if drift_alert else 0.0)
        
        dist_alert = await self.distribution_analyzer.get_active_alert()
        self.distribution_shift_gauge.set(1.0 if dist_alert else 0.0)
        
        cal_alert = await self.shadow_scoring.get_active_alert()
        self.calibration_issue_gauge.set(1.0 if cal_alert else 0.0)

    async def _run_detection_checks(self):
        """Run all detection checks."""
        # Check for score drift
        with self.drift_check_duration.time():
            await self.drift_detector.check_for_drift()
        
        # Check for distribution shifts
        with self.distribution_check_duration.time():
            await self.distribution_analyzer.check_distribution_shift()
        
        # Check for calibration issues
        with self.calibration_check_duration.time():
            await self.shadow_scoring.check_calibration()
        
        # Run ML anomaly detection (Phase 12e)
        if self.ml_detector:
            with self.ml_detection_duration.time():
                # This would be called from an external service in production
                # For now, we just ensure the metric is initialized
                pass

    async def get_alerts(self) -> Dict[str, Optional[Dict[str, Any]]]:
        """Get all active alerts."""
        return {
            'score_drift': await self.drift_detector.get_active_alert(),
            'distribution_shift': await self.distribution_analyzer.get_active_alert(),
            'calibration_issue': await self.shadow_scoring.get_active_alert()
        }

    async def clear_all_alerts(self):
        """Clear all active alerts."""
        await self.drift_detector.clear_alert()
        await self.distribution_analyzer.clear_alert()
        await self.shadow_scoring.clear_alert()

    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status."""
        status = {
            'timestamp': time.time(),
            'alerts': await self.get_alerts(),
            'metrics': {
                'current_median': None,
                'shadow_median': None,
                'active_alerts': 0
            },
            'components': {
                'baseline_monitor': 'healthy',
                'drift_detector': 'healthy',
                'distribution_analyzer': 'healthy',
                'shadow_scoring': 'healthy'
            }
        }
        
        # Get current metrics
        current_baseline = await self.baseline_monitor.get_current_baseline()
        if current_baseline:
            status['metrics']['current_median'] = current_baseline['median_score']
        
        shadow_stats = await self.shadow_scoring._get_shadow_scores()
        if shadow_stats:
            status['metrics']['shadow_median'] = shadow_stats['median']
        
        # Count active alerts
        alerts = await self.get_alerts()
        status['metrics']['active_alerts'] = sum(1 for alert in alerts.values() if alert is not None)
        
        # Add ML detector status
        if self.ml_detector:
            status['components']['ml_detector'] = 'healthy'
            ml_info = await self.ml_detector.get_model_info()
            status['ml_model'] = ml_info
        else:
            status['components']['ml_detector'] = 'disabled'
        
        return status

    async def get_drift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get score drift detection history."""
        return await self.drift_detector.get_drift_history(hours)

    async def get_shift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get distribution shift detection history."""
        return await self.distribution_analyzer.get_shift_history(hours)

    async def get_calibration_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get calibration check history."""
        return await self.shadow_scoring.get_calibration_history(hours)
    
    # Phase 12d: Security Hardening Methods
    async def check_api_authentication(self, api_key: str) -> bool:
        """Check API key authentication."""
        return await self.security_hardening.authenticate_api_key(api_key) is not None
    
    async def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token."""
        return await self.security_hardening.validate_jwt_token(token)
    
    async def check_rate_limit(self, limit_type: str, identifier: str) -> bool:
        """Check if request should be rate limited."""
        return await self.security_hardening.check_rate_limit(limit_type, identifier)
    
    async def validate_input_safety(self, data: Dict[str, Any]) -> bool:
        """Validate input for security issues."""
        return await self.security_hardening.validate_input_safety(data)
    
    async def check_suspicious_activity(self, request_data: Dict[str, Any]) -> bool:
        """Check for suspicious activity patterns."""
        return await self.security_hardening.check_suspicious_activity(request_data)
    
    async def get_security_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security audit logs."""
        return await self.security_hardening.get_security_audit_logs(limit)
    
    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics."""
        return await self.security_hardening.get_security_metrics()
    
    # Phase 12e: ML Anomaly Detection Methods
    async def detect_anomalies(self, fingerprints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies using ML model."""
        if not self.ml_detector:
            return []
        return await self.ml_detector.detect(fingerprints)
    
    async def get_ml_model_info(self) -> Dict[str, Any]:
        """Get ML model information."""
        if not self.ml_detector:
            return {'status': 'disabled'}
        return await self.ml_detector.get_model_info()
    
    async def list_ml_models(self) -> List[Dict[str, Any]]:
        """List available ML models."""
        if not self.model_manager:
            return []
        return await self.model_manager.list_models()
    
    async def update_ml_model(self, version: str):
        """Update to new ML model version."""
        if self.ml_detector:
            self.ml_detector.update_model_version(version)
            return {'status': 'updated', 'version': version}
        return {'status': 'unavailable'}