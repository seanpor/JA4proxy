# Main module for Analytics Node
# Phase 12a: Foundation

import asyncio
import logging
import signal
import sys
from typing import Optional

from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .config import load_config
from .stream_consumer import StreamConsumer

logger = logging.getLogger(__name__)


class AnalyticsNode:
    """Main analytics node application."""

    def __init__(self, config_file: str = "config/analytics.yaml"):
        self.config_file = config_file
        self.config = load_config(config_file)
        self.consumer: Optional[StreamConsumer] = None
        self.shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the analytics node: HTTP server + stream consumer."""
        logging.basicConfig(
            level=logging.INFO,
            format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}',
        )
        logger.info("Starting JA4Proxy Analytics Node")

        redis_url = (
            f"redis://{self.config['redis']['host']}:{self.config['redis']['port']}"
        )
        if self.config["redis"].get("password"):
            redis_url = (
                f"redis://:{self.config['redis']['password']}"
                f"@{self.config['redis']['host']}:{self.config['redis']['port']}"
            )

        monitoring_config = self.config.get("monitoring", {})
        monitoring_enabled = monitoring_config.get("enabled", True)

        self.consumer = StreamConsumer(
            redis_url=redis_url,
            stream_key=self.config["stream"]["key"],
            consumer_group=self.config["stream"]["consumer_group"],
            consumer_name=self.config["stream"]["consumer_name"],
            hmac_secret=self.config["security"]["hmac_secret"],
            hmac_required=self.config["security"]["hmac_required"],
            aggregation_window=self.config["aggregation"]["window_seconds"],
            monitoring_enabled=monitoring_enabled,
            monitoring_config=monitoring_config,
        )

        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self._handle_shutdown)
        loop.add_signal_handler(signal.SIGTERM, self._handle_shutdown)
        loop.add_signal_handler(signal.SIGHUP, self._handle_reload)

        await self.consumer.connect()
        logger.info("Connected to Redis stream")

        consumer_task = asyncio.create_task(
            self.consumer.consume_events(
                batch_size=self.config["stream"]["batch_size"],
                timeout_ms=self.config["stream"]["timeout_ms"],
            )
        )

        http_runner = await self._start_http_server()
        logger.info("HTTP server listening on :8080")

        await self.shutdown_event.wait()

        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

        await http_runner.cleanup()
        await self.consumer.close()
        logger.info("Analytics node shutdown complete")

    def _handle_shutdown(self) -> None:
        logger.info("Shutdown signal received")
        self.shutdown_event.set()

    def _handle_reload(self) -> None:
        """SIGHUP: reload config from disk; apply hot-reloadable values immediately."""
        try:
            new_config = load_config(self.config_file)
            self.config = new_config
            # Propagate hot-reloadable stream settings to consumer
            if self.consumer:
                self.consumer.batch_size = new_config["stream"].get("batch_size", 100)
                self.consumer.timeout_ms = new_config["stream"].get("timeout_ms", 5000)
            logger.info(
                '{"type":"system","level":"INFO","event":"config_reloaded",'
                '"subsystem":"analytics"}'
            )
        except Exception as exc:
            logger.warning(
                '{"type":"system","level":"WARN","event":"config_reload_failed",'
                '"subsystem":"analytics","error":"%s"}',
                exc,
            )

    # ── HTTP server ────────────────────────────────────────────────────────

    async def _start_http_server(self) -> web.AppRunner:
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/ready", self._handle_ready)
        app.router.add_get("/metrics", self._handle_metrics)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", 8080)
        await site.start()
        return runner

    async def _handle_health(self, request: web.Request) -> web.Response:
        status = await self.health_check()
        http_status = 200 if status.get("status") == "healthy" else 503
        return web.json_response(status, status=http_status)

    async def _handle_ready(self, request: web.Request) -> web.Response:
        if self.consumer and self.consumer.redis:
            try:
                await self.consumer.redis.ping()
                return web.json_response({"status": "ready"})
            except Exception:
                pass
        return web.json_response({"status": "not ready"}, status=503)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        registry = None
        if self.consumer and self.consumer.monitoring_system:
            registry = self.consumer.monitoring_system.registry
        output = generate_latest(registry) if registry else generate_latest()
        return web.Response(body=output, content_type=CONTENT_TYPE_LATEST)

    # ── Health check (also called by /health endpoint) ─────────────────────

    async def health_check(self) -> dict:
        if not self.consumer or not self.consumer.redis:
            return {"status": "unhealthy", "error": "not connected to Redis"}
        try:
            await self.consumer.redis.ping()
            return {
                "status": "healthy",
                "redis": "connected",
                "consumer_group": self.config["stream"]["consumer_group"],
                "stream_key": self.config["stream"]["key"],
            }
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)}


async def main() -> None:  # pragma: no cover
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/analytics.yaml"
    node = AnalyticsNode(config_file)
    await node.start()


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
