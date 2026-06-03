"""
Phase 47 — Confidence-Based Weighting System.

Tracks historical accuracy of threat intelligence feeds and provides dynamic
confidence weights to improve signal quality and reduce false positives.
"""

import json
import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional

import redis.asyncio
from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_FEED_ACCURACY = Gauge(
    "ja4proxy_feed_accuracy_score",
    "Current accuracy score for each threat intelligence feed (0.0-1.0)",
    ["feed_name"],
)

_CONFIDENCE_ADJUSTMENTS = Counter(
    "ja4proxy_confidence_adjustments_total",
    "Number of confidence weight adjustments made",
    ["feed_name", "direction"],  # direction: up|down|manual
)

_FEED_VALIDATIONS = Counter(
    "ja4proxy_feed_validations_total",
    "Number of feed validation events",
    ["feed_name", "result"],  # result: tp|fp|tn|fn
)


@dataclass
class FeedConfidence:
    """Current confidence metrics for a single feed."""

    accuracy_score: float = 1.0  # 0.0-1.0, where 1.0 = perfect accuracy
    true_positives: int = 0
    false_positives: int = 0
    last_updated: float = 0.0
    manual_override: Optional[float] = None  # None means use calculated value


class ConfidenceManager:
    """
    Tracks feed accuracy and provides dynamic confidence weights.

    Uses a simple Bayesian approach to track true positives vs false positives
    and adjusts confidence weights accordingly.
    """

    def __init__(self, redis_client: redis.asyncio.Redis):
        self._redis = redis_client
        self._feeds: Dict[str, FeedConfidence] = {}
        self._initialized = False

        # Default confidence weights for known feeds
        self._default_confidence = {
            "misp": 0.9,
            "threatfox": 0.85,
            "virustotal": 0.95,
            "greynoise": 0.92,
            "alienvault_otx": 0.88,
        }

    async def initialize(self) -> None:
        """Load confidence data from Redis."""
        try:
            data = await self._redis.get("ja4proxy:confidence:state")
            if data:
                stored = json.loads(data)
                for feed_name, metrics in stored.items():
                    self._feeds[feed_name] = FeedConfidence(
                        accuracy_score=metrics.get("accuracy_score", 1.0),
                        true_positives=metrics.get("true_positives", 0),
                        false_positives=metrics.get("false_positives", 0),
                        last_updated=metrics.get("last_updated", 0.0),
                        manual_override=metrics.get("manual_override"),
                    )
                    self._update_metrics(feed_name)

            # Initialize any feeds not in storage with defaults
            for feed_name in self._default_confidence:
                if feed_name not in self._feeds:
                    self._feeds[feed_name] = FeedConfidence(
                        accuracy_score=self._default_confidence[feed_name],
                        last_updated=time.time(),
                    )
                    self._update_metrics(feed_name)

            self._initialized = True
            logger.info(
                "confidence_manager | event=initialized | feed_count=%d",
                len(self._feeds),
            )
        except Exception as e:
            logger.error("confidence_manager | event=init_failed | error=%s", e)
            # Fall back to defaults
            for feed_name in self._default_confidence:
                self._feeds[feed_name] = FeedConfidence(
                    accuracy_score=self._default_confidence[feed_name],
                    last_updated=time.time(),
                )
            self._initialized = True

    async def save_state(self) -> None:
        """Save current confidence state to Redis."""
        if not self._initialized:
            return

        try:
            state = {}
            for feed_name, confidence in self._feeds.items():
                state[feed_name] = {
                    "accuracy_score": confidence.accuracy_score,
                    "true_positives": confidence.true_positives,
                    "false_positives": confidence.false_positives,
                    "last_updated": confidence.last_updated,
                    "manual_override": confidence.manual_override,
                }

            await self._redis.setex(
                "ja4proxy:confidence:state", 86400, json.dumps(state)  # 24h TTL
            )
        except Exception as e:
            logger.error("confidence_manager | event=save_failed | error=%s", e)

    def _update_metrics(self, feed_name: str) -> None:
        """Update Prometheus metrics for a feed."""
        confidence = self._feeds[feed_name]
        effective_score = (
            confidence.manual_override
            if confidence.manual_override is not None
            else confidence.accuracy_score
        )
        _FEED_ACCURACY.labels(feed_name=feed_name).set(effective_score)

    def get_confidence_weight(self, feed_name: str) -> float:
        """
        Get the current confidence weight for a feed.

        Args:
            feed_name: Name of the feed (e.g., "misp", "virustotal")

        Returns:
            Confidence weight (0.5-1.5 range, where 1.0 = neutral)
        """
        if not self._initialized:
            # Fallback to default if not initialized
            return self._default_confidence.get(feed_name, 1.0)

        if feed_name not in self._feeds:
            # Unknown feed - neutral weight
            return 1.0

        confidence = self._feeds[feed_name]

        # Use manual override if set, otherwise use calculated accuracy
        if confidence.manual_override is not None:
            return confidence.manual_override

        # Convert accuracy score (0.0-1.0) to weight (0.5-1.5)
        # This gives us a reasonable range while preventing extreme values
        weight = 0.5 + (confidence.accuracy_score * 1.0)
        return max(0.5, min(1.5, weight))  # Clamp to 0.5-1.5 range

    async def record_validation(self, feed_name: str, is_true_positive: bool) -> None:
        """
        Record a validation event for a feed.

        Args:
            feed_name: Name of the feed
            is_true_positive: True if the signal was correct, False if it was a false positive
        """
        if not self._initialized:
            return

        if feed_name not in self._feeds:
            self._feeds[feed_name] = FeedConfidence()

        confidence = self._feeds[feed_name]

        if is_true_positive:
            confidence.true_positives += 1
            _FEED_VALIDATIONS.labels(feed_name=feed_name, result="tp").inc()
        else:
            confidence.false_positives += 1
            _FEED_VALIDATIONS.labels(feed_name=feed_name, result="fp").inc()

        # Update accuracy score using a simple moving average
        # This gives more weight to recent performance while considering historical data
        total = confidence.true_positives + confidence.false_positives
        if total > 0:
            old_score = confidence.accuracy_score
            new_score = confidence.true_positives / total

            # Blend old and new scores (80% old, 20% new) for stability
            blended_score = (old_score * 0.8) + (new_score * 0.2)
            confidence.accuracy_score = blended_score

            # Record adjustment direction
            if blended_score > old_score:
                _CONFIDENCE_ADJUSTMENTS.labels(
                    feed_name=feed_name, direction="up"
                ).inc()
            elif blended_score < old_score:
                _CONFIDENCE_ADJUSTMENTS.labels(
                    feed_name=feed_name, direction="down"
                ).inc()

        confidence.last_updated = time.time()
        self._update_metrics(feed_name)

        # Save state periodically (not on every call to reduce Redis load)
        if total % 10 == 0:  # Save every 10 validations
            await self.save_state()

    async def set_manual_override(self, feed_name: str, weight: float) -> None:
        """
        Manually override the confidence weight for a feed.

        Args:
            feed_name: Name of the feed
            weight: Manual weight to apply (0.5-1.5 range)
        """
        if feed_name not in self._feeds:
            self._feeds[feed_name] = FeedConfidence()

        # Clamp to reasonable range
        weighted = max(0.5, min(1.5, weight))

        self._feeds[feed_name].manual_override = weighted
        self._feeds[feed_name].last_updated = time.time()

        self._update_metrics(feed_name)
        _CONFIDENCE_ADJUSTMENTS.labels(feed_name=feed_name, direction="manual").inc()

        await self.save_state()

        logger.info(
            "confidence_manager | event=manual_override | feed=%s | weight=%.2f",
            feed_name,
            weighted,
        )

    async def clear_manual_override(self, feed_name: str) -> None:
        """Clear manual override for a feed, returning to automatic calculation."""
        if feed_name in self._feeds:
            self._feeds[feed_name].manual_override = None
            self._feeds[feed_name].last_updated = time.time()
            self._update_metrics(feed_name)
            await self.save_state()

            logger.info(
                "confidence_manager | event=override_cleared | feed=%s", feed_name
            )

    def get_feed_stats(self, feed_name: str) -> Dict:
        """Get statistics for a feed."""
        if feed_name not in self._feeds:
            return {
                "accuracy_score": 1.0,
                "true_positives": 0,
                "false_positives": 0,
                "effective_weight": 1.0,
                "manual_override": None,
            }

        confidence = self._feeds[feed_name]
        return {
            "accuracy_score": confidence.accuracy_score,
            "true_positives": confidence.true_positives,
            "false_positives": confidence.false_positives,
            "effective_weight": self.get_confidence_weight(feed_name),
            "manual_override": confidence.manual_override,
        }
