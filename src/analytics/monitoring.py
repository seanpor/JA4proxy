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