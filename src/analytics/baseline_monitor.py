# Score Baseline Monitoring System
# Phase 12c: Score Drift Monitoring & Observability

import time
import json
import math
from typing import Dict, Any, List, Optional
from collections import defaultdict
import redis.asyncio as redis
from datetime import datetime
import logging


class BaselineMonitor:
    """Tracks hourly score baselines and detects drift."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration parameters
        self.capture_interval = config.get('capture_interval_seconds', 3600)
        self.retention_days = config.get('retention_days', 7)
        self.baseline_key_prefix = config.get('baseline_key_prefix', 'analytics:baseline:hourly')
        
        # Current window tracking
        self.current_hour = None
        self.current_stats = {
            'scores': [],
            'event_count': 0,
            'timestamp': None
        }

    async def update_with_score(self, score: float):
        """Update current hour statistics with a new score."""
        current_hour = datetime.now().strftime("%Y-%m-%d-%H")
        
        # Rotate to new hour if needed
        if self.current_hour != current_hour:
            await self._rotate_hour(current_hour)
        
        # Add score to current hour
        self.current_stats['scores'].append(score)
        self.current_stats['event_count'] += 1
        self.current_stats['timestamp'] = time.time()

    async def _rotate_hour(self, new_hour: str):
        """Rotate to a new hour, capturing baseline for previous hour."""
        if self.current_hour is not None and self.current_stats['event_count'] > 0:
            # Capture baseline for previous hour
            await self._capture_baseline()
        
        # Initialize new hour
        self.current_hour = new_hour
        self.current_stats = {
            'scores': [],
            'event_count': 0,
            'timestamp': time.time()
        }

    async def _capture_baseline(self):
        """Capture and store baseline statistics for current hour."""
        if len(self.current_stats['scores']) == 0:
            return
        
        # Calculate statistics
        scores = self.current_stats['scores']
        scores_sorted = sorted(scores)
        
        baseline = {
            "median_score": self._calculate_median(scores_sorted),
            "mean_score": self._calculate_mean(scores),
            "stddev_score": self._calculate_stddev(scores),
            "min_score": min(scores),
            "max_score": max(scores),
            "score_distribution": self._calculate_histogram(scores),
            "timestamp": self.current_stats['timestamp'],
            "event_count": self.current_stats['event_count']
        }
        
        # Store in Redis
        key = f"{self.baseline_key_prefix}:{self.current_hour}"
        await self.redis.set(key, json.dumps(baseline), ex=self.retention_days * 86400)
        
        self.logger.info(f"Captured baseline for hour {self.current_hour}: median={baseline['median_score']:.2f}, "
                        f"events={baseline['event_count']}")

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
        return math.sqrt(variance)

    def _calculate_histogram(self, scores: List[float]) -> Dict[str, int]:
        """Calculate score distribution histogram."""
        histogram = defaultdict(int)
        
        for score in scores:
            # Round to nearest 5 for bucketing
            bucket = round(score / 5) * 5
            histogram[str(bucket)] += 1
        
        return dict(sorted(histogram.items()))

    async def get_current_baseline(self) -> Optional[Dict[str, Any]]:
        """Get the current hour's baseline (if available)."""
        if self.current_hour is None or len(self.current_stats['scores']) == 0:
            return None
        
        return {
            "median_score": self._calculate_median(sorted(self.current_stats['scores'])),
            "mean_score": self._calculate_mean(self.current_stats['scores']),
            "stddev_score": self._calculate_stddev(self.current_stats['scores']),
            "event_count": self.current_stats['event_count'],
            "timestamp": self.current_stats['timestamp']
        }

    async def get_historical_baseline(self, hour: str) -> Optional[Dict[str, Any]]:
        """Get baseline for a specific hour."""
        key = f"{self.baseline_key_prefix}:{hour}"
        baseline_json = await self.redis.get(key)
        
        if baseline_json:
            return json.loads(baseline_json)
        return None

    async def get_recent_baselines(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent baselines for trend analysis."""
        baselines = []
        
        for i in range(hours):
            hour_time = datetime.now() - timedelta(hours=i)
            hour_str = hour_time.strftime("%Y-%m-%d-%H")
            
            baseline = await self.get_historical_baseline(hour_str)
            if baseline:
                baselines.append(baseline)
        
        return sorted(baselines, key=lambda x: x['timestamp'], reverse=True)


# Import timedelta at top level
from datetime import timedelta