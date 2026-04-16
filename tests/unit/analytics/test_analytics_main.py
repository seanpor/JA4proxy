"""
Tests for src/analytics/main.py — AnalyticsNode.
Phase 104: coverage gap closure.
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
import pytest_asyncio

from src.analytics.main import AnalyticsNode

# ── helpers ──────────────────────────────────────────────────────────────────

MINIMAL_CONFIG = {
    "redis": {"host": "127.0.0.1", "port": 6379, "password": None},
    "stream": {
        "key": "ja4proxy:events",
        "consumer_group": "analytics-test",
        "consumer_name": "analytics-test-1",
        "batch_size": 10,
        "timeout_ms": 500,
    },
    "security": {"hmac_secret": "test-secret-xxx", "hmac_required": False},
    "aggregation": {"window_seconds": 60},
    "monitoring": {"enabled": False},
    "logging": {"format": "legacy"},
}


@pytest.fixture
def node():
    """AnalyticsNode with config loaded from a dict instead of file."""
    with patch("src.analytics.main.load_config", return_value=MINIMAL_CONFIG.copy()):
        n = AnalyticsNode(config_file="config/analytics.yaml")
    return n


# ── constructor ──────────────────────────────────────────────────────────────

class TestConstructor:
    def test_defaults(self, node):
        assert node.consumer is None
        assert node.ti_runner is None
        assert not node.shutdown_event.is_set()

    def test_config_loaded(self, node):
        assert node.config["redis"]["host"] == "127.0.0.1"


# ── health_check ─────────────────────────────────────────────────────────────

class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_unhealthy_no_consumer(self, node):
        result = await node.health_check()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_unhealthy_no_redis(self, node):
        node.consumer = MagicMock()
        node.consumer.redis = None
        result = await node.health_check()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_healthy(self, node):
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        node.consumer = MagicMock()
        node.consumer.redis = mock_redis
        result = await node.health_check()
        assert result["status"] == "healthy"
        assert result["redis"] == "connected"

    @pytest.mark.asyncio
    async def test_unhealthy_ping_fails(self, node):
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("test-conn-err"))
        node.consumer = MagicMock()
        node.consumer.redis = mock_redis
        result = await node.health_check()
        assert result["status"] == "unhealthy"
        assert "test-conn-err" in result["error"]


# ── _handle_shutdown ─────────────────────────────────────────────────────────

class TestHandleShutdown:
    def test_sets_event(self, node):
        node._handle_shutdown()
        assert node.shutdown_event.is_set()


# ── _handle_reload ───────────────────────────────────────────────────────────

class TestHandleReload:
    def test_reload_updates_config(self, node):
        new_config = MINIMAL_CONFIG.copy()
        new_config["stream"] = {**MINIMAL_CONFIG["stream"], "batch_size": 999}
        node.consumer = MagicMock()
        with patch("src.analytics.main.load_config", return_value=new_config):
            node._handle_reload()
        assert node.consumer.batch_size == 999

    def test_reload_failure_logged(self, node):
        with patch("src.analytics.main.load_config", side_effect=ValueError("bad yaml")):
            node._handle_reload()  # should not raise

    def test_reload_with_ti_runner(self, node):
        """When ti_runner exists, reload schedules async config reload."""
        new_config = MINIMAL_CONFIG.copy()
        node.consumer = MagicMock()
        node.ti_runner = MagicMock()
        node.ti_runner.reload_config = AsyncMock()

        mock_loop = MagicMock()
        with patch("src.analytics.main.load_config", return_value=new_config), \
             patch("asyncio.get_running_loop", return_value=mock_loop):
            node._handle_reload()
        mock_loop.create_task.assert_called_once()


# ── _start_ti_runner ─────────────────────────────────────────────────────────

class TestStartTIRunner:
    @pytest.mark.asyncio
    async def test_skipped_when_disabled(self, node):
        """TI runner not started when threat_intel.enabled is false."""
        node.config["threat_intel"] = {"enabled": False}
        await node._start_ti_runner("redis://127.0.0.1:6379")
        assert node.ti_runner is None

    @pytest.mark.asyncio
    async def test_skipped_when_no_config(self, node):
        """TI runner not started when threat_intel key is missing."""
        node.config.pop("threat_intel", None)
        await node._start_ti_runner("redis://127.0.0.1:6379")
        assert node.ti_runner is None

    @pytest.mark.asyncio
    async def test_skipped_when_import_failed(self, node):
        """TI runner not started when FeedRunner import failed."""
        node.config["threat_intel"] = {"enabled": True}
        with patch("src.analytics.main._FeedRunner", None), \
             patch("src.analytics.main._ti_feed_import_error", ImportError("no module")):
            await node._start_ti_runner("redis://127.0.0.1:6379")
        assert node.ti_runner is None

    @pytest.mark.asyncio
    async def test_started_successfully(self, node):
        """TI runner starts when enabled and import works."""
        node.config["threat_intel"] = {"enabled": True, "feeds": [{"name": "test-feed"}]}
        mock_runner = AsyncMock()
        mock_runner.start = AsyncMock()
        mock_feed_cls = MagicMock(return_value=mock_runner)

        with patch("src.analytics.main._FeedRunner", mock_feed_cls), \
             patch("src.analytics.main.redis_async") as mock_redis_mod:
            mock_redis_mod.from_url = MagicMock(return_value=AsyncMock())
            await node._start_ti_runner("redis://127.0.0.1:6379")

        assert node.ti_runner is mock_runner
        mock_runner.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_failure_fail_open(self, node):
        """If runner.start() raises, we log and continue."""
        node.config["threat_intel"] = {"enabled": True, "feeds": []}
        mock_runner = AsyncMock()
        mock_runner.start = AsyncMock(side_effect=RuntimeError("test-start-fail"))
        mock_feed_cls = MagicMock(return_value=mock_runner)

        with patch("src.analytics.main._FeedRunner", mock_feed_cls), \
             patch("src.analytics.main.redis_async") as mock_redis_mod:
            mock_redis_mod.from_url = MagicMock(return_value=AsyncMock())
            await node._start_ti_runner("redis://127.0.0.1:6379")

        assert node.ti_runner is None  # cleared on failure


# ── _stop_ti_runner ──────────────────────────────────────────────────────────

class TestStopTIRunner:
    @pytest.mark.asyncio
    async def test_stop_noop_when_none(self, node):
        await node._stop_ti_runner()  # should not raise

    @pytest.mark.asyncio
    async def test_stop_success(self, node):
        mock_runner = AsyncMock()
        mock_runner.stop = AsyncMock()
        node.ti_runner = mock_runner
        node._ti_async_redis = AsyncMock()
        await node._stop_ti_runner()
        assert node.ti_runner is None
        assert node._ti_async_redis is None

    @pytest.mark.asyncio
    async def test_stop_timeout(self, node):
        """Timeout during stop is logged but not raised."""
        mock_runner = AsyncMock()

        async def slow_stop():
            await asyncio.sleep(999)
        mock_runner.stop = slow_stop
        node.ti_runner = mock_runner
        node._ti_async_redis = AsyncMock()

        # We patch wait_for to raise TimeoutError immediately
        with patch("src.analytics.main.asyncio.wait_for",
                   side_effect=asyncio.TimeoutError):
            await node._stop_ti_runner()
        assert node.ti_runner is None

    @pytest.mark.asyncio
    async def test_stop_error(self, node):
        """Exception during stop is logged but not raised."""
        mock_runner = AsyncMock()
        mock_runner.stop = AsyncMock(side_effect=RuntimeError("test-stop-err"))
        node.ti_runner = mock_runner
        node._ti_async_redis = AsyncMock()

        with patch("src.analytics.main.asyncio.wait_for",
                   side_effect=RuntimeError("test-stop-err")):
            await node._stop_ti_runner()
        assert node.ti_runner is None


# ── HTTP handlers ────────────────────────────────────────────────────────────

class TestHTTPHandlers:
    @pytest.mark.asyncio
    async def test_handle_health_healthy(self, node):
        mock_redis = AsyncMock()
        node.consumer = MagicMock()
        node.consumer.redis = mock_redis
        request = MagicMock()
        resp = await node._handle_health(request)
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_handle_health_unhealthy(self, node):
        node.consumer = None
        request = MagicMock()
        resp = await node._handle_health(request)
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_handle_ready_ok(self, node):
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        node.consumer = MagicMock()
        node.consumer.redis = mock_redis
        request = MagicMock()
        resp = await node._handle_ready(request)
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_handle_ready_not_connected(self, node):
        node.consumer = None
        request = MagicMock()
        resp = await node._handle_ready(request)
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_handle_ready_ping_fails(self, node):
        import redis
        mock_redis_client = AsyncMock()
        mock_redis_client.ping = AsyncMock(side_effect=redis.RedisError("test-err"))
        node.consumer = MagicMock()
        node.consumer.redis = mock_redis_client
        request = MagicMock()
        resp = await node._handle_ready(request)
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_handle_metrics_no_registry(self, node):
        node.consumer = MagicMock()
        node.consumer.monitoring_system = None
        request = MagicMock()
        resp = await node._handle_metrics(request)
        assert resp.status == 200
        assert b"" != resp.body  # prometheus output is non-empty

    @pytest.mark.asyncio
    async def test_handle_metrics_with_registry(self, node):
        from prometheus_client import CollectorRegistry
        registry = CollectorRegistry()
        node.consumer = MagicMock()
        node.consumer.monitoring_system = MagicMock()
        node.consumer.monitoring_system.registry = registry
        request = MagicMock()
        resp = await node._handle_metrics(request)
        assert resp.status == 200


# ── start (integration-ish) ─────────────────────────────────────────────────

class TestStart:
    @pytest.mark.asyncio
    async def test_start_and_shutdown(self, node):
        """Start the node, then immediately signal shutdown."""
        mock_consumer = AsyncMock()
        mock_consumer.connect = AsyncMock()
        mock_consumer.consume_events = AsyncMock()
        mock_consumer.close = AsyncMock()
        mock_consumer.redis = AsyncMock()
        mock_consumer.monitoring_system = None

        mock_runner = AsyncMock()
        mock_runner.setup = AsyncMock()
        mock_runner.cleanup = AsyncMock()

        with patch("src.analytics.main.StreamConsumer", return_value=mock_consumer), \
             patch("src.analytics.main.setup_logging"), \
             patch.object(node, "_start_http_server", return_value=mock_runner), \
             patch.object(node, "_start_ti_runner", new_callable=AsyncMock), \
             patch("asyncio.get_running_loop") as mock_loop:

            mock_loop_inst = MagicMock()
            mock_loop.return_value = mock_loop_inst

            # Schedule shutdown after start begins waiting
            async def trigger_shutdown():
                await asyncio.sleep(0.01)
                node.shutdown_event.set()

            task = asyncio.create_task(node.start())
            shutdown_task = asyncio.create_task(trigger_shutdown())
            await asyncio.gather(task, shutdown_task)

        mock_consumer.connect.assert_awaited_once()
        mock_consumer.close.assert_awaited_once()
        mock_runner.cleanup.assert_awaited_once()


# ── _start_http_server ───────────────────────────────────────────────────────

class TestStartHTTPServer:
    @pytest.mark.asyncio
    async def test_start_http_server_creates_routes(self, node):
        """Verify the HTTP server sets up /health, /ready, /metrics."""
        with patch("src.analytics.main.web.AppRunner") as MockRunner, \
             patch("src.analytics.main.web.TCPSite") as MockSite:
            mock_runner = AsyncMock()
            MockRunner.return_value = mock_runner
            mock_site = AsyncMock()
            MockSite.return_value = mock_site

            result = await node._start_http_server()

            assert result is mock_runner
            mock_runner.setup.assert_awaited_once()
            mock_site.start.assert_awaited_once()
