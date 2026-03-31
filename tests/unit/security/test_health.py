"""
Unit tests for Robust Health Check API (Phase 41).
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.health import HealthMonitor, HealthServer


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    return client


@pytest.fixture
def monitor(mock_redis):
    config = {"version": "1.4.2", "dial": 75}
    return HealthMonitor(
        redis_client=mock_redis,
        config=config,
        rise_threshold=3,
        fall_threshold=2
    )


@pytest.mark.asyncio
async def test_health_monitor_initial_state(monitor):
    assert monitor.is_healthy is False
    assert monitor.is_ready is True  # Ready during grace period


@pytest.mark.asyncio
async def test_health_monitor_rise_hysteresis(monitor, mock_redis):
    # Success 1
    await monitor.check()
    assert monitor.is_healthy is False
    
    # Success 2
    await monitor.check()
    assert monitor.is_healthy is False
    
    # Success 3 -> Healthy
    await monitor.check()
    assert monitor.is_healthy is True
    assert monitor.get_status_report()["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_monitor_fall_hysteresis(monitor, mock_redis):
    # Get to healthy first
    for _ in range(3):
        await monitor.check()
    assert monitor.is_healthy is True
    
    # Failure 1
    mock_redis.ping.side_effect = Exception("Redis Down")
    await monitor.check()
    assert monitor.is_healthy is True  # Still healthy due to fall_threshold=2
    
    # Failure 2 -> Unhealthy
    await monitor.check()
    assert monitor.is_healthy is False
    assert monitor.get_status_report()["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_health_monitor_geoip_check(mock_redis):
    with patch("src.security.health.Path") as mock_path:
        # Mock file missing
        mock_path.return_value.exists.return_value = False
        monitor = HealthMonitor(mock_redis, {}, geoip_path="/tmp/fake.mmdb")
        
        await monitor.check()
        report = monitor.get_status_report()
        assert report["components"]["geoip"]["status"] == "unhealthy"
        
        # Mock file exists
        mock_path.return_value.exists.return_value = True
        mock_path.return_value.stat.return_value.st_size = 2048
        await monitor.check()
        report = monitor.get_status_report()
        assert report["components"]["geoip"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_monitor_latency_recording(monitor):
    monitor.record_pipeline_latency(5.5)
    monitor.record_pipeline_latency(10.5)
    report = monitor.get_status_report()
    assert report["pipeline_latency_avg_ms"] == 8.0


@pytest.mark.asyncio
async def test_health_server_ready_grace_period(monitor):
    # Mocking time to be past grace period
    with patch("time.time", return_value=time.time() + 20):
        assert monitor.is_ready is False
        
    # Becomes ready if healthy even if past grace period
    for _ in range(3):
        await monitor.check()
    assert monitor.is_healthy is True
    assert monitor.is_ready is True
