# Shadow Scoring & Calibration Monitoring
# Phase 12c: Score Drift Monitoring & Observability

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as redis


class ShadowScoring:
    """Monitors known-good traffic to detect calibration issues."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Configuration parameters
        self.known_good_alpn = config.get('known_good_alpn', ['h2', 'h1'])
        self.calibration_threshold = config.get('calibration_threshold', 10.0)
        self.check_interval = config.get('check_interval_seconds', 300)
        self.alert_ttl = config.get('alert_ttl_seconds', 3600)
        self.shadow_key = config.get('shadow_key', 'analytics:shadow_scores:latest')
        self.alert_key = config.get('calibration_alert_key', 'analytics:alerts:calibration_issue')

        # Current window tracking
        self.current_window = None
        self.shadow_scores = []

        # Last check tracking
        self.last_check_time = 0

    async def update_with_event(self, event: Dict[str, Any]):
        """Update shadow scoring with a new event."""
        # Check if this is known-good traffic
        if not self._is_known_good_traffic(event):
            return

        # Get current time window (1 hour windows)
        current_time = int(time.time())
        window = current_time // 3600

        if self.current_window is None:
            self.current_window = window

        # Rotate windows if needed
        if window != self.current_window:
            await self._rotate_window(window)

        # Add score to shadow monitoring
        self.shadow_scores.append(event['score'])

    def _is_known_good_traffic(self, event: Dict[str, Any]) -> bool:
        """Check if event represents known-good traffic."""
        # Check ALPN protocol
        alpn = event.get('alpn', '')
        if alpn in self.known_good_alpn:
            return True

        # Additional checks could be added here
        # (e.g., known safe domains, IP ranges, etc.)

        return False

    async def _rotate_window(self, new_window: int):
        """Rotate to a new time window."""
        if len(self.shadow_scores) > 0:
            # Store shadow scores for current window
            await self._store_shadow_scores()

        # Initialize new window
        self.current_window = new_window
        self.shadow_scores = []

    async def _store_shadow_scores(self):
        """Store shadow scores for current window."""
        if len(self.shadow_scores) == 0:
            return

        # Calculate statistics
        shadow_stats = {
            'median': self._calculate_median(sorted(self.shadow_scores)),
            'mean': self._calculate_mean(self.shadow_scores),
            'stddev': self._calculate_stddev(self.shadow_scores),
            'count': len(self.shadow_scores),
            'timestamp': time.time()
        }

        # Store in Redis
        await self.redis.set(self.shadow_key, json.dumps(shadow_stats), ex=3600)  # 1 hour TTL

        self.logger.info("Stored shadow scores: median=%.2f, count=%d",
                        shadow_stats['median'], shadow_stats['count'])

    def _calculate_median(self, sorted_scores: List[float]) -> float:
        """Calculate median score."""
        n = len(sorted_scores)
        if n == 0:
            return 0.0

        if n % 2 == 1:
            return float(sorted_scores[n // 2])
        else:
            return (sorted_scores[n // 2 - 1] + sorted_scores[n // 2]) / 2.0

    def _calculate_mean(self, scores: List[float]) -> float:
        """Calculate mean score."""
        if len(scores) == 0:
            return 0.0
        return sum(scores) / len(scores)

    def _calculate_stddev(self, scores: List[float]) -> float:
        """Calculate standard deviation."""
        if len(scores) < 2:
            return 0.0

        mean = self._calculate_mean(scores)
        variance = sum((x - mean) ** 2 for x in scores) / len(scores)
        return variance ** 0.5

    async def check_calibration(self) -> Optional[Dict[str, Any]]:
        """Check for calibration issues in shadow scoring."""
        current_time = time.time()

        # Rate limit checks
        if current_time - self.last_check_time < self.check_interval:
            return None

        self.last_check_time = current_time

        # Get current shadow scores
        shadow_stats = await self._get_shadow_scores()

        if not shadow_stats or shadow_stats['count'] < 10:
            return None

        # Check for calibration issues
        if shadow_stats['median'] > self.calibration_threshold:
            # Calibration issue detected
            alert_data = {
                'type': 'calibration_issue',
                'severity': 'high',
                'shadow_median': shadow_stats['median'],
                'threshold': self.calibration_threshold,
                'shadow_count': shadow_stats['count'],
                'detected_at': time.time(),
                'resolved': False,
                'message': f'Shadow scoring median ({shadow_stats["median"]:.2f}) exceeds threshold ({self.calibration_threshold})'
            }

            # Store alert
            await self._store_alert(alert_data)

            self.logger.warning("Calibration issue detected: %s", alert_data['message'])

            return alert_data

        return None

    async def _get_shadow_scores(self) -> Optional[Dict[str, Any]]:
        """Get current shadow scores from Redis."""
        shadow_json = await self.redis.get(self.shadow_key)

        if shadow_json:
            return json.loads(shadow_json)
        return None

    async def _store_alert(self, alert_data: Dict[str, Any]):
        """Store calibration alert in Redis with TTL."""
        await self.redis.set(self.alert_key, json.dumps(alert_data), ex=self.alert_ttl)

    async def get_active_alert(self) -> Optional[Dict[str, Any]]:
        """Get current active calibration alert."""
        alert_json = await self.redis.get(self.alert_key)

        if alert_json:
            alert_data = json.loads(alert_json)

            # Check if alert is still valid (not expired)
            if not alert_data.get('resolved', False):
                return alert_data

        return None

    async def clear_alert(self):
        """Manually clear current calibration alert."""
        alert_json = await self.redis.get(self.alert_key)

        if alert_json:
            alert_data = json.loads(alert_json)
            alert_data['resolved'] = True
            alert_data['resolved_at'] = time.time()

            # Store resolved alert (will expire naturally)
            await self.redis.set(self.alert_key, json.dumps(alert_data), ex=self.alert_ttl)

            self.logger.info("Calibration alert manually cleared")

    async def get_calibration_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get calibration check history."""
        history = []

        for i in range(hours):
            # In a real implementation, we would store historical shadow scores
            # For this simplified version, we'll just check current state
            shadow_stats = await self._get_shadow_scores()

            if shadow_stats:
                has_issue = shadow_stats['median'] > self.calibration_threshold
                history.append({
                    'timestamp': time.time() - (i * 3600),
                    'shadow_median': shadow_stats['median'],
                    'has_calibration_issue': has_issue,
                    'severity': 'high' if has_issue else 'normal'
                })

            # Sleep briefly to avoid overwhelming Redis
            await asyncio.sleep(0.01)

        return sorted(history, key=lambda x: x['timestamp'], reverse=True)


# Import asyncio for sleep
import asyncio