# Score Distribution Analysis System
# Phase 12c: Score Drift Monitoring & Observability

import json
import logging
import math
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as redis


class DistributionAnalyzer:
    """Analyzes score distribution shifts using statistical tests."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration parameters
        self.ks_test_threshold = config.get('ks_test_threshold', 0.05)
        self.check_interval = config.get('check_interval_seconds', 300)
        self.alert_ttl = config.get('alert_ttl_seconds', 3600)
        self.alert_key = config.get('alert_key', 'analytics:alerts:distribution_shift')
        self.baseline_key_prefix = config.get('baseline_key_prefix', 'analytics:baseline:hourly')
        
        # Last check tracking
        self.last_check_time: float = 0

    async def check_distribution_shift(self) -> Optional[Dict[str, Any]]:
        """Check for significant distribution shifts."""
        current_time = time.time()
        
        # Rate limit checks
        if current_time - self.last_check_time < self.check_interval:
            return None
        
        self.last_check_time = current_time
        
        # Get current and historical baselines
        current_baseline = await self._get_current_baseline()
        
        if not current_baseline or current_baseline['event_count'] < 50:
            return None
        
        # Get historical baseline (previous hour)
        previous_hour_time = datetime.now() - timedelta(hours=1)
        previous_hour = previous_hour_time.strftime("%Y-%m-%d-%H")
        historical_baseline = await self._get_historical_baseline(previous_hour)
        
        if not historical_baseline or historical_baseline['event_count'] < 50:
            return None
        
        # Perform distribution analysis
        shift_result = self._analyze_distribution_shift(current_baseline, historical_baseline)
        
        if shift_result['distribution_shift']:
            # Store alert
            await self._store_alert(shift_result)
            
            self.logger.warning(f"Distribution shift detected: ks_statistic={shift_result['ks_statistic']:.3f}, "
                               f"p_value={shift_result['p_value']:.4f}")
            
            return shift_result
        
        return None

    def _analyze_distribution_shift(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze distribution shift using simplified KS test approach."""
        current_dist = self._normalize_distribution(current['score_distribution'])
        baseline_dist = self._normalize_distribution(baseline['score_distribution'])
        
        # Calculate simplified KS statistic (max difference between CDFs)
        ks_statistic = self._calculate_ks_statistic(current_dist, baseline_dist)
        
        # Simplified p-value calculation (approximation)
        p_value = self._approximate_p_value(ks_statistic, 
                                           current['event_count'], 
                                           baseline['event_count'])
        
        return {
            'distribution_shift': p_value < self.ks_test_threshold,
            'ks_statistic': ks_statistic,
            'p_value': p_value,
            'current_distribution': current_dist,
            'baseline_distribution': baseline_dist,
            'current_event_count': current['event_count'],
            'baseline_event_count': baseline['event_count'],
            'severity': 'high' if ks_statistic > 0.2 else 'medium',
            'detected_at': time.time()
        }

    def _normalize_distribution(self, distribution: Dict[str, int]) -> Dict[str, float]:
        """Normalize distribution to probabilities."""
        total = sum(distribution.values())
        if total == 0:
            return {}
        
        return {bucket: count / total for bucket, count in distribution.items()}

    def _calculate_ks_statistic(self, current_dist: Dict[str, float], baseline_dist: Dict[str, float]) -> float:
        """Calculate KS statistic (max difference between CDFs)."""
        # Get all unique buckets
        all_buckets = set(current_dist.keys()) | set(baseline_dist.keys())
        sorted_buckets = sorted(all_buckets, key=float)
        
        # Calculate CDFs
        current_cdf = {}
        baseline_cdf = {}
        current_cumulative = 0.0
        baseline_cumulative = 0.0
        
        for bucket in sorted_buckets:
            current_cumulative += current_dist.get(bucket, 0.0)
            baseline_cumulative += baseline_dist.get(bucket, 0.0)
            current_cdf[bucket] = current_cumulative
            baseline_cdf[bucket] = baseline_cumulative
        
        # Find maximum difference
        max_diff = 0.0
        for bucket in sorted_buckets:
            diff = abs(current_cdf[bucket] - baseline_cdf[bucket])
            if diff > max_diff:
                max_diff = diff
        
        return max_diff

    def _approximate_p_value(self, ks_statistic: float, n1: int, n2: int) -> float:
        """Approximate p-value for KS test (simplified)."""
        # This is a simplified approximation - in production, use scipy.stats.ks_2samp
        # Effective sample size
        n_effective = (n1 * n2) / (n1 + n2)
        
        # Approximate p-value using asymptotic formula
        if ks_statistic == 0:
            return 1.0
        
        # Very rough approximation
        p_value = math.exp(-2 * n_effective * ks_statistic * ks_statistic)
        return min(1.0, max(0.0, p_value))

    async def _store_alert(self, shift_result: Dict[str, Any]):
        """Store distribution shift alert in Redis with TTL."""
        alert_data = {
            'type': 'distribution_shift',
            'severity': shift_result['severity'],
            'ks_statistic': shift_result['ks_statistic'],
            'p_value': shift_result['p_value'],
            'detected_at': shift_result['detected_at'],
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
        """Get current active distribution shift alert."""
        alert_json = await self.redis.get(self.alert_key)
        
        if alert_json:
            alert_data = json.loads(alert_json)
            
            # Check if alert is still valid (not expired)
            if not alert_data.get('resolved', False):
                return alert_data
        
        return None

    async def clear_alert(self):
        """Manually clear current distribution shift alert."""
        alert_json = await self.redis.get(self.alert_key)
        
        if alert_json:
            alert_data = json.loads(alert_json)
            alert_data['resolved'] = True
            alert_data['resolved_at'] = time.time()
            
            # Store resolved alert (will expire naturally)
            await self.redis.set(self.alert_key, json.dumps(alert_data), ex=self.alert_ttl)
            
            self.logger.info("Distribution shift alert manually cleared")

    async def get_shift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get distribution shift detection history."""
        history = []
        
        for i in range(hours):
            hour_time = datetime.now() - timedelta(hours=i)
            hour_str = hour_time.strftime("%Y-%m-%d-%H")
            
            current_baseline = await self._get_current_baseline_for_hour(hour_str)
            previous_baseline = await self._get_historical_baseline(hour_str)
            
            if current_baseline and previous_baseline:
                shift_result = self._analyze_distribution_shift(current_baseline, previous_baseline)
                history.append({
                    'hour': hour_str,
                    'distribution_shift': shift_result['distribution_shift'],
                    'ks_statistic': shift_result['ks_statistic'],
                    'p_value': shift_result['p_value'],
                    'severity': shift_result['severity']
                })
        
        return sorted(history, key=lambda x: x['hour'], reverse=True)

    async def _get_current_baseline_for_hour(self, hour: str) -> Optional[Dict[str, Any]]:
        """Get baseline for specific hour (used in history)."""
        key = f"{self.baseline_key_prefix}:{hour}"
        baseline_json = await self.redis.get(key)
        
        if baseline_json:
            return json.loads(baseline_json)
        return None

    async def detect_anomaly_patterns(self, baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Detect specific anomaly patterns in score distribution."""
        patterns = {
            'bimodal': False,
            'sudden_spike': False,
            'sudden_drop': False,
            'unusual_clustering': False,
            'outlier_proliferation': False
        }
        
        distribution = baseline['score_distribution']
        
        # Check for bimodal distribution (two distinct peaks)
        if len(distribution) >= 2:
            buckets = sorted(distribution.keys(), key=float)
            counts = [distribution[b] for b in buckets]
            
            # Simple bimodal detection: look for two peaks with valley in between
            if len(counts) >= 3:
                max1_idx = counts.index(max(counts))
                counts_without_max1 = counts[:max1_idx] + counts[max1_idx+1:]
                
                if counts_without_max1:
                    max2_idx = counts_without_max1.index(max(counts_without_max1))
                    actual_max2_idx = max2_idx if max2_idx < max1_idx else max2_idx + 1
                    
                    # Check if peaks are separated by at least one bucket
                    if abs(max1_idx - actual_max2_idx) >= 2:
                        # Check if there's a valley between peaks
                        valley_bucket = buckets[min(max1_idx, actual_max2_idx) + 1]
                        valley_count = distribution[valley_bucket]
                        
                        if valley_count < max(counts) * 0.5:  # Valley is less than 50% of peak
                            patterns['bimodal'] = True
        
        # Check for sudden spikes (high concentration in high-score buckets)
        high_score_buckets = [b for b in distribution if float(b) >= 80]
        if high_score_buckets:
            high_score_total = sum(distribution[b] for b in high_score_buckets)
            total_events = baseline['event_count']
            
            if high_score_total / total_events > 0.3:  # >30% in high scores
                patterns['sudden_spike'] = True
        
        # Check for sudden drops (high concentration in low-score buckets)
        low_score_buckets = [b for b in distribution if float(b) <= 20]
        if low_score_buckets:
            low_score_total = sum(distribution[b] for b in low_score_buckets)
            total_events = baseline['event_count']
            
            if low_score_total / total_events > 0.7:  # >70% in low scores
                patterns['sudden_drop'] = True
        
        return patterns