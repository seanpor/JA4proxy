"""Phase 86a — Tests for /api/v1/health/deep and /api/v1/metrics/summary."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.management.app import _parse_prometheus_text, app
from src.management.schemas import DeepHealthResponse


@pytest.fixture
def mock_redis():
    """Mock RedisManager with connected _client."""
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(return_value=True)
    mock_client.get = AsyncMock(return_value="25")
    mock_client.scan = AsyncMock(return_value=(0, ["ja4proxy:ban:abc", "ja4proxy:ban:def"]))

    mock_manager = MagicMock()
    mock_manager._client = mock_client
    mock_manager.get_dial = AsyncMock(return_value=25)
    return mock_manager


@pytest.fixture
def mock_prometheus_response():
    """Mock aiohttp response with Prometheus text format."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(
        return_value=(
            "# HELP ja4proxy_active_connections Active connections\n"
            "# TYPE ja4proxy_active_connections gauge\n"
            "ja4proxy_active_connections 42\n"
            "# HELP ja4proxy_connections_total Total connections by action\n"
            "# TYPE ja4proxy_connections_total counter\n"
            'ja4proxy_connections_total{action="allow"} 1000\n'
            'ja4proxy_connections_total{action="block"} 50\n'
            'ja4proxy_connections_total{action="ban"} 10\n'
            "# HELP ja4proxy_tls_cert_expiry_timestamp_seconds Cert expiry\n"
            "# TYPE ja4proxy_tls_cert_expiry_timestamp_seconds gauge\n"
            "ja4proxy_tls_cert_expiry_timestamp_seconds 1775865600\n"
        )
    )
    return mock_resp


@pytest.fixture
def app_with_mocks(mock_redis, mock_prometheus_response):
    """Inject mocks into the FastAPI app."""
    import src.management.app as app_module

    app_module.redis_manager = mock_redis

    # Mock aiohttp
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get = AsyncMock(return_value=mock_prometheus_response)

    mock_aiohttp = MagicMock()
    mock_aiohttp.ClientSession = MagicMock(return_value=mock_session)
    mock_aiohttp.ClientTimeout = MagicMock()

    app_module.aiohttp = mock_aiohttp
    return app


class TestParsePrometheusText:
    """Unit tests for _parse_prometheus_text helper."""

    def test_simple_gauge(self):
        text = "ja4proxy_active_connections 42\n"
        result = _parse_prometheus_text(text)
        assert result["ja4proxy_active_connections"] == 42.0

    def test_labelled_counter(self):
        text = 'ja4proxy_connections_total{action="block"} 50\n'
        result = _parse_prometheus_text(text)
        assert result['ja4proxy_connections_total{action="block"}'] == 50.0

    def test_skips_comments_and_blanks(self):
        text = "# HELP foo\n\n# TYPE bar\ngauge 0\nbar 1\n"
        result = _parse_prometheus_text(text)
        assert "HELP" not in result
        assert "bar" in result  # Only "bar 1" matches

    def test_empty_input(self):
        assert _parse_prometheus_text("") == {}


class TestHealthDeep:
    """Tests for /api/v1/health/deep endpoint."""

    @pytest.mark.asyncio
    async def test_health_deep_returns_200(self, app_with_mocks, httpx_mock=None):
        """Basic smoke: endpoint returns 200 with valid JSON."""
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app_with_mocks)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/v1/health/deep")
            assert resp.status_code == 200
            data = resp.json()
            assert "status" in data
            assert "redis_connected" in data
            assert data["redis_connected"] is True

    @pytest.mark.asyncio
    async def test_health_deep_schema_fields(self, app_with_mocks):
        """All 9 fields must be present in the response."""
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app_with_mocks)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/v1/health/deep")
            data = resp.json()

        expected = {
            "status",
            "redis_connected",
            "redis_latency_ms",
            "dial",
            "active_connections",
            "connections_total",
            "block_rate_pct",
            "active_bans",
            "cert_days_remaining",
        }
        assert expected.issubset(set(data.keys()))


class TestMetricsSummary:
    """Tests for /api/v1/metrics/summary alias endpoint."""

    @pytest.mark.asyncio
    async def test_metrics_summary_returns_200(self, app_with_mocks):
        """Same schema as health/deep."""
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app_with_mocks)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/v1/metrics/summary")
            assert resp.status_code == 200
            data = resp.json()
            assert "status" in data

    @pytest.mark.asyncio
    async def test_metrics_summary_same_schema_as_health_deep(self, app_with_mocks):
        """Both endpoints return the same field set."""
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app_with_mocks)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r1 = await c.get("/api/v1/health/deep")
            r2 = await c.get("/api/v1/metrics/summary")

        assert set(r1.json().keys()) == set(r2.json().keys())


class TestHealthDeepRedisFailure:
    """Fail-open behaviour when Redis is unreachable."""

    @pytest.mark.asyncio
    async def test_health_deep_redis_down(self):
        """When Redis fails, endpoint returns status=error with zeroed fields."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("redis down"))

        mock_manager = MagicMock()
        mock_manager._client = mock_client
        mock_manager.get_dial = AsyncMock(side_effect=ConnectionError("redis down"))

        import src.management.app as app_module
        orig = app_module.redis_manager
        app_module.redis_manager = mock_manager

        try:
            from httpx import AsyncClient, ASGITransport

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/api/v1/health/deep")
                data = resp.json()
                assert data["status"] == "error"
                assert data["redis_connected"] is False
                assert data["dial"] == 0
        finally:
            app_module.redis_manager = orig
