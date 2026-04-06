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


# ── Missing-coverage tests ────────────────────────────────────────────────────

class TestHealthMonitorLatencyBuffer:
    """Line 72: eviction when pipeline latency buffer exceeds max_latencies."""

    def test_latency_buffer_evicts_oldest_entry(self, monitor):
        """record_pipeline_latency() evicts the oldest entry when buffer is full (line 72).
        So what: unbounded latency history would grow indefinitely and consume memory
        under sustained traffic."""
        max_lat = monitor._max_latencies
        for i in range(max_lat + 5):
            monitor.record_pipeline_latency(float(i))
        assert len(monitor._pipeline_latencies) == max_lat
        # The first entry added (0.0) should have been evicted
        assert 0.0 not in monitor._pipeline_latencies


class TestHealthServerHandlers:
    """Lines 161, 164-166, 169-170: /metrics, /health (503), /ready (503)."""

    def _make_server(self, healthy: bool = True, ready: bool = True):
        mon = MagicMock()
        mon.is_healthy = healthy
        mon.is_ready = ready
        mon.get_status_report.return_value = {"status": "healthy" if healthy else "unhealthy"}
        server = HealthServer(monitor=mon, host="127.0.0.1", port=9090)
        return server

    @pytest.mark.asyncio
    async def test_handle_metrics_returns_prometheus_text(self):
        """GET /metrics returns Prometheus text content (line 161).
        So what: if /metrics is broken, Prometheus scrapes fail silently — no alerts fire."""
        server = self._make_server()
        resp = await server.handle_metrics(MagicMock())
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_handle_health_200_when_healthy(self):
        """GET /health returns 200 when monitor is healthy (line 164-166)."""
        server = self._make_server(healthy=True)
        resp = await server.handle_health(MagicMock())
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_handle_health_503_when_unhealthy(self):
        """GET /health returns 503 when monitor is unhealthy (lines 164-166).
        So what: load balancers use /health to route traffic; wrong status code
        means a broken instance keeps receiving prod traffic."""
        server = self._make_server(healthy=False)
        resp = await server.handle_health(MagicMock())
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_handle_ready_200_when_ready(self):
        """GET /ready returns 200 when ready (lines 169-170)."""
        server = self._make_server(ready=True)
        resp = await server.handle_ready(MagicMock())
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_handle_ready_503_when_not_ready(self):
        """GET /ready returns 503 when not ready (lines 169-170).
        So what: Kubernetes uses /ready to decide when to add pods to the service;
        wrong status means unready pods receive traffic before Redis is reachable."""
        server = self._make_server(ready=False)
        resp = await server.handle_ready(MagicMock())
        assert resp.status == 503


class TestHealthServerStartStop:
    """Lines 175-188: HealthServer start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_sets_runner(self):
        """start() creates and sets up the aiohttp runner (lines 175-179).
        So what: if the runner isn't created, /health and /ready never become reachable
        and the proxy is invisible to load balancers."""
        server = self._make_server()
        mock_runner = AsyncMock()
        mock_site = AsyncMock()
        with (
            patch("src.security.health.web.AppRunner", return_value=mock_runner),
            patch("src.security.health.web.TCPSite", return_value=mock_site),
        ):
            await server.start()
        mock_runner.setup.assert_awaited_once()
        mock_site.start.assert_awaited_once()
        assert server.runner is mock_runner

    @pytest.mark.asyncio
    async def test_stop_cleans_up_runner(self):
        """stop() calls runner.cleanup() (lines 185-188).
        So what: without cleanup the aiohttp server holds the TCP port open,
        blocking future starts (e.g. after config reload)."""
        server = self._make_server()
        mock_runner = AsyncMock()
        server.runner = mock_runner
        await server.stop()
        mock_runner.cleanup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_when_runner_none_is_safe(self):
        """stop() with runner=None must not raise."""
        server = self._make_server()
        server.runner = None
        await server.stop()  # must not raise

    def _make_server(self, healthy=True, ready=True):
        mon = MagicMock()
        mon.is_healthy = healthy
        mon.is_ready = ready
        mon.get_status_report.return_value = {"status": "healthy" if healthy else "unhealthy"}
        return HealthServer(monitor=mon, host="127.0.0.1", port=9090)
