# Score Drift Detection System
# Phase 12c: Score Drift Monitoring & Observability

import time
import json
import math
from typing import Dict, Any, List, Optional
import redis.asyncio as redis
from datetime import datetime, timedelta
import logging


class DriftDetector:
    """Detects significant score drift using statistical analysis."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration parameters
        self.z_score_threshold = config.get('z_score_threshold', 2.0)
        self.check_interval = config.get('check_interval_seconds', 60)
        self.alert_ttl = config.get('alert_ttl_seconds', 3600)
        self.alert_key = config.get('alert_key', 'analytics:alerts:score_drift')
        self.baseline_key_prefix = config.get('baseline_key_prefix', 'analytics:baseline:hourly')
        
        # Severity levels
        self.severity_levels = config.get('severity_levels', {
            'low': 1.5,
            'medium': 2.0,
            'high': 3.0
        })
        
        # Last check tracking
        self.last_check_time = 0

    async def check_for_drift(self) -> Optional[Dict[str, Any]]:
        """Check for score drift between current and baseline."""
        current_time = time.time()
        
        # Rate limit checks
        if current_time - self.last_check_time < self.check_interval:
            return None
        
        self.last_check_time = current_time
        
        # Get current baseline (this hour)
        current_hour = datetime.now().strftime("%Y-%m-%d-%H")
        current_baseline = await self._get_current_baseline()
        
        if not current_baseline or current_baseline['event_count'] < 10:
            return None
        
        # Get historical baseline (previous hour)
        previous_hour_time = datetime.now() - timedelta(hours=1)
        previous_hour = previous_hour_time.strftime("%Y-%m-%d-%H")
        historical_baseline = await self._get_historical_baseline(previous_hour)
        
        if not historical_baseline or historical_baseline['event_count'] < 10:
            return None
        
        # Perform drift analysis
        drift_result = self._analyze_drift(current_baseline, historical_baseline)
        
        if drift_result['drift_detected']:
            # Store alert
            await self._store_alert(drift_result)
            
            self.logger.warning(f"Score drift detected: z_score={drift_result['z_score']:.2f}, "
                               f"severity={drift_result['severity']}")
            
            return drift_result
        
        return None

    def _analyze_drift(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze drift using z-score comparison."""
        current_median = current['median_score']
        baseline_median = baseline['median_score']
        baseline_stddev = baseline['stddev_score']
        
        # Calculate z-score
        if baseline_stddev > 0:
            z_score = (current_median - baseline_median) / baseline_stddev
        else:
            z_score = 0.0
        
        # Determine severity
        severity = self._determine_severity(abs(z_score))
        
        return {
            'drift_detected': abs(z_score) >= self.z_score_threshold,
            'z_score': z_score,
            'current_median': current_median,
            'baseline_median': baseline_median,
            'current_stddev': current['stddev_score'],
            'baseline_stddev': baseline_stddev,
            'current_event_count': current['event_count'],
            'baseline_event_count': baseline['event_count'],
            'severity': severity,
            'detected_at': time.time()
        }

    def _determine_severity(self, z_score: float) -> str:
        """Determine alert severity based on z-score."""
        if z_score >= self.severity_levels['high']:
            return 'high'
        elif z_score >= self.severity_levels['medium']:
            return 'medium'
        elif z_score >= self.severity_levels['low']:
            return 'low'
        else:
            return 'info'

    async def _store_alert(self, drift_result: Dict[str, Any]):
        """Store drift alert in Redis with TTL."""
        alert_data = {
            'type': 'score_drift',
            'severity': drift_result['severity'],
            'z_score': drift_result['z_score'],
            'current_median': drift_result['current_median'],
            'baseline_median': drift_result['baseline_median'],
            'detected_at': drift_result['detected_at'],
            'resolved': False
        }
        
        # Store alert with TTL
        await self.redis.set(self.alert_key, json.dumps(alert_data), ex=self.alert_ttl)

    async def _get_current_baseline(self) -> Optional[Dict[str, Any]]:
        """Get current hour baseline from Redis."""
        current_hour = datetime.now().strftime("%Y-%m-%d-%H")
        key = f"{self.baseline_key_prefix}:{current_hour}"
        baseline_json = await self.redis.get(key)
        
        if baseline_json:
            return json.loads(baseline_json)
        return None

    async def _get_historical_baseline(self, hour: str) -> Optional[Dict[str, Any]]:
        """Get historical baseline from Redis."""
        key = f"{self.baseline_key_prefix}:{hour}"
        baseline_json = await self.redis.get(key)
        
        if baseline_json:
            return json.loads(baseline_json)
        return None

    async def get_active_alert(self) -> Optional[Dict[str, Any]]:
        """Get current active drift alert."""
        alert_json = await self.redis.get(self.alert_key)
        
        if alert_json:
            alert_data = json.loads(alert_json)
            
            # Check if alert is still valid (not expired)
            if not alert_data.get('resolved', False):
                return alert_data
        
        return None

    async def clear_alert(self):
        """Manually clear current drift alert."""
        alert_json = await self.redis.get(self.alert_key)
        
        if alert_json:
            alert_data = json.loads(alert_json)
            alert_data['resolved'] = True
            alert_data['resolved_at'] = time.time()
            
            # Store resolved alert (will expire naturally)
            await self.redis.set(self.alert_key, json.dumps(alert_data), ex=self.alert_ttl)
            
            self.logger.info("Score drift alert manually cleared")

    async def get_drift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get drift detection history."""
        history = []
        
        for i in range(hours):
            hour_time = datetime.now() - timedelta(hours=i)
            hour_str = hour_time.strftime("%Y-%m-%d-%H")
            
            current_baseline = await self._get_current_baseline_for_hour(hour_str)
            previous_baseline = await self._get_historical_baseline(hour_str)
            
            if current_baseline and previous_baseline:
                drift_result = self._analyze_drift(current_baseline, previous_baseline)
                history.append({
                    'hour': hour_str,
                    'drift_detected': drift_result['drift_detected'],
                    'z_score': drift_result['z_score'],
                    'severity': drift_result['severity']
                })
        
        return sorted(history, key=lambda x: x['hour'], reverse=True)

    async def _get_current_baseline_for_hour(self, hour: str) -> Optional[Dict[str, Any]]:
        """Get baseline for specific hour (used in history)."""
        key = f"{self.baseline_key_prefix}:{hour}"
        baseline_json = await self.redis.get(key)
        
        if baseline_json:
            return json.loads(baseline_json)
        return None