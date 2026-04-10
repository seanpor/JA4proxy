# Main module for Analytics Node
# Phase 12a: Foundation

import asyncio
import logging
import signal
import sys
from typing import Any, Optional

import redis
import redis.asyncio as redis_async
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .config import load_config
from .stream_consumer import StreamConsumer
from src.utils.logging_config import setup_logging

# phase-85: optional import — the analytics container can run without ti_feeds
# (config flag off, missing aiohttp, etc.). Importing the runner module never
# starts a feed; the import is guarded so the analytics container is never
# blocked by an issue inside the ti_feeds package.
try:  # pragma: no cover
    from .ti_feeds.runner import FeedRunner as _FeedRunner
except Exception as _ti_import_exc:  # pragma: no cover  # noqa: BLE001
    _FeedRunner = None  # type: ignore[assignment]
    _ti_feed_import_error: Optional[BaseException] = _ti_import_exc
else:
    _ti_feed_import_error = None

logger = logging.getLogger(__name__)


class AnalyticsNode:
    """Main analytics node application."""

    def __init__(self, config_file: str = "config/analytics.yaml"):
        self.config_file = config_file
        self.config = load_config(config_file)
        self.consumer: Optional[StreamConsumer] = None
        self.shutdown_event = asyncio.Event()
        # phase-85: threat-intel feed runner — populated in start() iff enabled
        self.ti_runner: Optional[Any] = None
        self._ti_runner_task: Optional[asyncio.Task] = None
        self._ti_async_redis: Optional[Any] = None

    async def start(self) -> None:
        """Start the analytics node: HTTP server + stream consumer."""
        # phase-80: use structured logging config; format driven by proxy.yml logging.format
        log_format = self.config.get("logging", {}).get("format", "legacy")
        setup_logging(format=log_format)
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

        # phase-85: start the threat-intel feed runner. Fail-open: any exception
        # is logged and the consumer / HTTP server keep running.
        await self._start_ti_runner(redis_url)

        await self.shutdown_event.wait()

        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

        await self._stop_ti_runner()

        await http_runner.cleanup()
        await self.consumer.close()
        logger.info("Analytics node shutdown complete")

    # ── threat-intel feed runner (phase-85) ────────────────────────────────

    async def _start_ti_runner(self, redis_url: str) -> None:
        """Start the Phase 85 threat-intel feed runner if enabled in config.

        The runner is launched as a background asyncio task. Any failure is
        logged and the rest of the analytics container keeps running — the
        feed runner is strictly auxiliary.
        """
        ti_cfg = self.config.get("threat_intel") or {}
        if not ti_cfg.get("enabled", False):
            logger.info(
                "ti_feed | event=runner_skipped | reason=threat_intel.enabled=false"
            )
            return
        if _FeedRunner is None:
            logger.warning(
                "ti_feed | event=runner_skipped | reason=import_failed | error=%s",
                _ti_feed_import_error,
            )
            return

        try:
            self._ti_async_redis = redis_async.from_url(
                redis_url, decode_responses=True
            )
            mgmt_base_url = (
                self.config.get("management_api", {}).get("base_url")
                or "http://management:8090"
            )
            self.ti_runner = _FeedRunner(
                redis=self._ti_async_redis,
                mgmt_base_url=mgmt_base_url,
                config=self.config,
            )
            await self.ti_runner.start()
            logger.info(
                "ti_feed | event=runner_started | mgmt_base_url=%s | feeds=%d",
                mgmt_base_url,
                len(ti_cfg.get("feeds", []) or []),
            )
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.error(
                "ti_feed | event=runner_start_failed | error=%s",
                exc,
            )
            self.ti_runner = None

    async def _stop_ti_runner(self) -> None:
        """Stop the feed runner cleanly with a 5 s timeout."""
        if self.ti_runner is None:
            return
        try:
            await asyncio.wait_for(self.ti_runner.stop(), timeout=5.0)
            logger.info("ti_feed | event=runner_stopped")
        except asyncio.TimeoutError:
            logger.warning(
                "ti_feed | event=runner_stop_timeout | "
                "tasks_may_be_orphaned=true"
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ti_feed | event=runner_stop_error | error=%s", exc)
        finally:
            self.ti_runner = None
            if self._ti_async_redis is not None:
                try:
                    await self._ti_async_redis.aclose()
                except Exception:  # noqa: BLE001
                    pass
                self._ti_async_redis = None

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
            # phase-85: hand the new threat_intel block to the feed runner.
            # Schedule the async reload on the running loop because SIGHUP
            # callbacks run in the signal-handler context (sync).
            if self.ti_runner is not None:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.ti_runner.reload_config(new_config))
                except RuntimeError:  # pragma: no cover
                    pass
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
        site = web.TCPSite(runner, "0.0.0.0", 8080)  # nosec B104
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
            except (redis.RedisError, ConnectionError):
                pass
        return web.json_response({"status": "not ready"}, status=503)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        registry = None
        if self.consumer and self.consumer.monitoring_system:
            registry = self.consumer.monitoring_system.registry
        output = generate_latest(registry) if registry else generate_latest()
        return web.Response(body=output, headers={"Content-Type": CONTENT_TYPE_LATEST})

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
