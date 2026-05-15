# Unit Tests for Baseline Monitor
# Phase 12c: Score Drift Monitoring & Observability

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analytics.baseline_monitor import BaselineMonitor


@pytest.mark.asyncio
class TestBaselineMonitor:
    """Test baseline monitoring functionality."""

    async def test_baseline_capture(self):
        """Test baseline capture and storage."""
        # Create mock Redis
        mock_redis = AsyncMock()

        # Create baseline monitor
        config = {
            "capture_interval_seconds": 1,  # Short interval for testing
            "retention_days": 1,
            "baseline_key_prefix": "test:baseline",
        }
        monitor = BaselineMonitor(mock_redis, config)

        # Add some scores
        for i in range(10):
            await monitor.update_with_score(50 + i)

        # Get current baseline
        baseline = await monitor.get_current_baseline()
        assert baseline is not None
        assert baseline["median_score"] == 54.5  # Median of 50-59
        assert baseline["mean_score"] == 54.5  # Mean of 50-59
        assert baseline["event_count"] == 10

        # Manually trigger capture to test storage
        await monitor._capture_baseline()

        # Check that baseline was captured
        assert mock_redis.set.called
        call_args = mock_redis.set.call_args_list[-1]
        key = call_args[0][0]
        assert key.startswith("test:baseline:")

        # Verify stored data
        stored_data = json.loads(call_args[0][1])
        assert "median_score" in stored_data
        assert "mean_score" in stored_data
        assert "stddev_score" in stored_data
        assert "score_distribution" in stored_data

    async def test_histogram_calculation(self):
        """Test histogram bucketing."""
        mock_redis = AsyncMock()
        config = {"capture_interval_seconds": 3600}
        monitor = BaselineMonitor(mock_redis, config)

        # Add scores that should create distinct buckets
        scores = [5, 10, 15, 20, 25, 30, 85, 90, 95]
        for score in scores:
            await monitor.update_with_score(score)

        # Manually trigger capture to get full baseline
        await monitor._capture_baseline()

        # Get the captured baseline data
        call_args = mock_redis.set.call_args_list[-1]
        stored_data = json.loads(call_args[0][1])
        histogram = stored_data["score_distribution"]

        # Should have buckets at 0, 5, 10, 15, 20, 25, 30, 85, 90, 95
        assert "0" in histogram or "5" in histogram
        assert "95" in histogram or "90" in histogram
        assert sum(histogram.values()) == len(scores)

    async def test_window_rotation(self):
        """Test window rotation."""
        mock_redis = AsyncMock()
        config = {"capture_interval_seconds": 1}
        monitor = BaselineMonitor(mock_redis, config)

        # Add scores to first window
        for i in range(5):
            await monitor.update_with_score(50 + i)

        first_baseline = await monitor.get_current_baseline()
        assert first_baseline["event_count"] == 5

        # Manually trigger rotation
        await monitor._rotate_hour("2024-01-01-02")  # New hour

        # Add scores to new window
        for i in range(3):
            await monitor.update_with_score(70 + i)

        second_baseline = await monitor.get_current_baseline()
        assert second_baseline["event_count"] == 3  # Only new window's data

    async def test_statistical_calculations(self):
        """Test statistical calculations."""
        mock_redis = AsyncMock()
        config = {"capture_interval_seconds": 3600}
        monitor = BaselineMonitor(mock_redis, config)

        # Add a range of scores
        scores = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        for score in scores:
            await monitor.update_with_score(score)

        baseline = await monitor.get_current_baseline()

        # Test median (average of 50 and 60)
        assert baseline["median_score"] == 55.0

        # Test mean
        assert baseline["mean_score"] == 55.0

        # Test stddev
        assert baseline["stddev_score"] > 0
        assert baseline["stddev_score"] < 30  # Should be reasonable

    async def test_empty_baseline(self):
        """Test behavior with no scores."""
        mock_redis = AsyncMock()
        config = {"capture_interval_seconds": 3600}
        monitor = BaselineMonitor(mock_redis, config)

        # Should return None when no scores
        baseline = await monitor.get_current_baseline()
        assert baseline is None

    async def test_recent_baselines(self):
        """Test retrieval of recent baselines."""
        mock_redis = AsyncMock()

        # Mock get responses
        mock_redis.get.side_effect = [
            json.dumps(
                {"median_score": 50, "timestamp": time.time(), "event_count": 100}
            ),
            json.dumps(
                {
                    "median_score": 55,
                    "timestamp": time.time() - 3600,
                    "event_count": 120,
                }
            ),
            None,  # No baseline for this hour
            json.dumps(
                {"median_score": 45, "timestamp": time.time() - 7200, "event_count": 90}
            ),
        ]

        config = {"capture_interval_seconds": 3600}
        monitor = BaselineMonitor(mock_redis, config)

        # Get recent baselines
        baselines = await monitor.get_recent_baselines(hours=4)

        # Should have 3 baselines (one hour had no data)
        assert len(baselines) == 3
        assert all("median_score" in b for b in baselines)


# Import asyncio for sleep
import asyncio

# ── Missing-coverage additions ────────────────────────────────────────────────


class TestBaselineMonitorCoverageGaps:
    """Cover lines 60, 92, 102."""

    @pytest.mark.asyncio
    async def test_capture_baseline_returns_early_when_no_scores(self):
        """Line 60: _capture_baseline() returns immediately when scores list is empty.
        So what: if this guard is missing, the function proceeds to compute statistics
        on an empty list — causing ZeroDivisionError or storing a meaningless baseline
        with all zeros, which would suppress legitimate anomaly alerts."""
        mock_redis = MagicMock()
        monitor = BaselineMonitor(mock_redis, {})
        # Don't add any scores — scores list stays empty
        await monitor._capture_baseline()
        # Redis set must NOT be called (no baseline stored for empty window)
        mock_redis.set.assert_not_called()

    def test_calculate_median_empty_list_returns_zero(self):
        """Line 92: _calculate_median([]) returns 0.0 without IndexError.
        So what: if this guard is missing, sorted_scores[n//2] raises IndexError
        when the list is empty — the analytics node crashes instead of returning
        a neutral score, taking down all anomaly detection."""
        mock_redis = MagicMock()
        monitor = BaselineMonitor(mock_redis, {})
        assert monitor._calculate_median([]) == 0.0

    def test_calculate_mean_empty_list_returns_zero(self):
        """Line 102: _calculate_mean([]) returns 0.0.
        So what: if this guard is missing, sum([]) / 0 raises ZeroDivisionError —
        same consequence as above: analytics node crash on an empty baseline window."""
        mock_redis = MagicMock()
        monitor = BaselineMonitor(mock_redis, {})
        assert monitor._calculate_mean([]) == 0.0
