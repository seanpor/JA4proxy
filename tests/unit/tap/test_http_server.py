"""
Unit tests for TapHttpServer (Phase 20 Group 2).

Uses aiohttp.test_utils.TestServer/TestClient so no real port is bound.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient, TestServer

from src.tap.http_server import TapHttpServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_redis(ping_ok: bool = True) -> MagicMock:
    r = MagicMock()
    if ping_ok:
        r.ping.return_value = True
    else:
        r.ping.side_effect = Exception("Connection refused")
    r.zrange.return_value = []
    r.get.return_value = None
    return r


def _make_http_server(
    redis=None,
    sensor=None,
    edl_server=None,
    taxii_server=None,
    interface: str = "eth0",
) -> TapHttpServer:
    config = {
        "tap": {
            "http_port": 8090,
            "interface": interface,
        }
    }
    return TapHttpServer(
        config=config,
        redis=redis if redis is not None else _mock_redis(),
        edl_server=edl_server,
        taxii_server=taxii_server,
        sensor=sensor,
    )


def _client(server: TapHttpServer) -> TestClient:
    """Return a TestClient context manager for *server*'s aiohttp app."""
    app = server._create_app()
    ts = TestServer(app)
    return TestClient(ts)


# ---------------------------------------------------------------------------
# /api/v1/mode
# ---------------------------------------------------------------------------


class TestModeEndpoint:
    @pytest.mark.asyncio
    async def test_mode_endpoint_returns_tap_mode(self):
        srv = _make_http_server()
        async with _client(srv) as c:
            resp = await c.get("/api/v1/mode")
            assert resp.status == 200
            data = await resp.json()
        assert data["mode"] == "tap"

    @pytest.mark.asyncio
    async def test_mode_endpoint_includes_interface_and_stream_counts(self):
        sensor = MagicMock()
        sensor.get_stats.return_value = {
            "streams_active": 42,
            "packets_captured": 10000,
            "packets_dropped": 3,
        }
        srv = _make_http_server(sensor=sensor, interface="eth1")
        async with _client(srv) as c:
            resp = await c.get("/api/v1/mode")
            data = await resp.json()
        assert data["interface"] == "eth1"
        assert data["streams_active"] == 42
        assert data["packets_captured"] == 10000


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_endpoint_returns_healthy_when_all_subsystems_ok(self):
        sensor = MagicMock()
        sensor.get_exporter_status.return_value = {"edl": "healthy", "f5": "healthy"}
        sensor.get_enforcement_status.return_value = {"iptables": "healthy"}
        srv = _make_http_server(redis=_mock_redis(ping_ok=True), sensor=sensor)
        async with _client(srv) as c:
            resp = await c.get("/health")
            data = await resp.json()
        assert resp.status == 200
        assert data["status"] == "healthy"
        assert data["redis"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_degraded_when_one_exporter_down(self):
        sensor = MagicMock()
        sensor.get_exporter_status.return_value = {
            "edl": "healthy",
            "syslog": "degraded",
        }
        sensor.get_enforcement_status.return_value = {}
        srv = _make_http_server(redis=_mock_redis(ping_ok=True), sensor=sensor)
        async with _client(srv) as c:
            resp = await c.get("/health")
            data = await resp.json()
        assert resp.status == 200
        assert data["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_unhealthy_when_redis_down(self):
        srv = _make_http_server(redis=_mock_redis(ping_ok=False))
        async with _client(srv) as c:
            resp = await c.get("/health")
            data = await resp.json()
        assert resp.status == 503
        assert data["status"] == "unhealthy"
        assert data["redis"] == "unhealthy"


# ---------------------------------------------------------------------------
# /api/v1/fingerprints/ip/{ip}
# ---------------------------------------------------------------------------


class TestFpIpEndpoint:
    @pytest.mark.asyncio
    async def test_fp_ip_endpoint_returns_connection_history(self):
        redis = _mock_redis()
        redis.zrange.return_value = [
            (b"conn_abc123", 1_700_000_000.0),
            (b"conn_def456", 1_700_000_100.0),
        ]
        srv = _make_http_server(redis=redis)
        async with _client(srv) as c:
            resp = await c.get("/api/v1/fingerprints/ip/1.2.3.4")
            data = await resp.json()
        assert resp.status == 200
        assert data["ip"] == "1.2.3.4"
        assert len(data["connections"]) == 2
        assert data["connections"][0]["conn_id"] == "conn_abc123"

    @pytest.mark.asyncio
    async def test_fp_ip_endpoint_returns_404_for_unknown_ip(self):
        srv = _make_http_server()  # redis.zrange returns []
        async with _client(srv) as c:
            resp = await c.get("/api/v1/fingerprints/ip/9.9.9.9")
        assert resp.status == 404


# ---------------------------------------------------------------------------
# /api/v1/fingerprints/ja4/{fingerprint}
# ---------------------------------------------------------------------------


class TestFpJa4Endpoint:
    @pytest.mark.asyncio
    async def test_fp_ja4_endpoint_returns_usage_stats(self):
        redis = _mock_redis()
        redis.get.return_value = b"75"
        srv = _make_http_server(redis=redis)
        fp = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        async with _client(srv) as c:
            resp = await c.get(f"/api/v1/fingerprints/ja4/{fp}")
            data = await resp.json()
        assert resp.status == 200
        assert data["fingerprint"] == fp
        assert data["count"] == 75


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Coverage gap additions — lines 146-149, 154-155, 176-177
# ---------------------------------------------------------------------------


class TestHttpServerCoverageGaps:
    """Missing branches: sensor-delegated IP history, Redis exceptions, count exception."""

    @pytest.mark.asyncio
    async def test_fp_ip_sensor_returns_none_gives_404(self):
        """Lines 147-148: sensor.get_ip_history() returns None → 404.
        So what: without this check, returning None from the sensor would cause
        json_response to serialize None as 'connections: null' instead of a 404,
        misleading consumers into thinking the IP has empty connection history."""
        sensor = MagicMock()
        sensor.get_ip_history = AsyncMock(return_value=None)
        srv = _make_http_server(sensor=sensor)
        async with _client(srv) as c:
            resp = await c.get("/api/v1/fingerprints/ip/1.2.3.4")
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_fp_ip_sensor_returns_history_gives_200(self):
        """Line 146-149: sensor with get_ip_history returns list → 200 with connections.
        So what: without this delegation, the sensor's assembled history is never used
        and the API always falls back to raw Redis zrange, losing enriched connection data.
        """
        sensor = MagicMock()
        sensor.get_ip_history = AsyncMock(
            return_value=[{"conn_id": "abc", "timestamp": "2024"}]
        )
        srv = _make_http_server(sensor=sensor)
        async with _client(srv) as c:
            resp = await c.get("/api/v1/fingerprints/ip/1.2.3.4")
            data = await resp.json()
        assert resp.status == 200
        assert data["connections"][0]["conn_id"] == "abc"

    @pytest.mark.asyncio
    async def test_fp_ip_redis_exception_returns_404(self):
        """Lines 154-155: Redis zrange raises → raw=[] → 404.
        So what: without this except, a transient Redis error on the fingerprint
        endpoint crashes the aiohttp handler with a 500 instead of a clean 404."""
        redis = _mock_redis()
        redis.zrange.side_effect = Exception("Redis connection refused")
        srv = _make_http_server(redis=redis)
        async with _client(srv) as c:
            resp = await c.get("/api/v1/fingerprints/ip/1.2.3.4")
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_fp_ja4_redis_exception_returns_zero_count(self):
        """Lines 176-177: Redis get raises → count=0 → 200 with count=0.
        So what: without this except, a Redis error on the JA4 stats endpoint
        returns a 500, breaking dashboards that poll this endpoint continuously."""
        redis = _mock_redis()
        redis.get.side_effect = Exception("Redis unavailable")
        srv = _make_http_server(redis=redis)
        fp = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        async with _client(srv) as c:
            resp = await c.get(f"/api/v1/fingerprints/ja4/{fp}")
            data = await resp.json()
        assert resp.status == 200
        assert data["count"] == 0


class TestServerLifecycle:
    @pytest.mark.asyncio
    async def test_server_starts_on_configured_port(self):
        """start() creates a runner; no exception expected."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from aiohttp import web

        srv = _make_http_server()
        mock_runner = MagicMock()
        mock_runner.setup = AsyncMock(return_value=None)
        mock_runner.cleanup = AsyncMock(return_value=None)
        mock_site = MagicMock()
        mock_site.start = AsyncMock(return_value=None)

        with patch("aiohttp.web.AppRunner", return_value=mock_runner), patch(
            "aiohttp.web.TCPSite", return_value=mock_site
        ):
            await srv.start()
            assert srv._runner is not None
            await srv.stop()

    @pytest.mark.asyncio
    async def test_server_shuts_down_cleanly(self):
        """stop() clears the runner without raising."""
        from unittest.mock import AsyncMock, MagicMock, patch

        srv = _make_http_server()
        mock_runner = MagicMock()
        mock_runner.setup = AsyncMock(return_value=None)
        mock_runner.cleanup = AsyncMock(return_value=None)
        mock_site = MagicMock()
        mock_site.start = AsyncMock(return_value=None)

        with patch("aiohttp.web.AppRunner", return_value=mock_runner), patch(
            "aiohttp.web.TCPSite", return_value=mock_site
        ):
            await srv.start()
            await srv.stop()
        assert srv._runner is None
