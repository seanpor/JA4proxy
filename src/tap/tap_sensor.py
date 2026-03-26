"""
Top-level orchestrator for TAP/SPAN passive capture mode (Phase 20).

Instantiated by proxy.py when ``proxy.mode = tap``.
"""
import asyncio
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class TapSensor:
    """Top-level orchestrator for TAP mode.

    Instantiated by proxy.py when mode=tap.  Owns and starts (in later groups):
    - PacketCapture (or PcapReplay)
    - StreamWorker × N
    - WorkerWatchdog
    - TapPipeline
    - FingerprintStore
    - EnforcementBridge
    - ExportManager
    - TapHttpServer
    - ScheduledBackupManager

    Runs until SIGTERM or SIGINT.
    """

    def __init__(self, config: dict, redis_client: Optional[Any] = None) -> None:
        self._config = config
        self._redis_client = redis_client
        self._shutdown_event: asyncio.Event = asyncio.Event()

    async def run(self) -> None:
        """Start all components; block until shutdown event."""
        logger.info(
            '{"type": "system", "level": "INFO", "subsystem": "tap",'
            ' "event": "tap_sensor_started"}'
        )
        await self._shutdown_event.wait()

    async def shutdown(self) -> None:
        """Signal the sensor to stop and wait for clean teardown."""
        self._shutdown_event.set()
