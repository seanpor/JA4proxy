"""
ExportManager — orchestrates all intelligence export backends (Phase 20, Group 9).

Fires fingerprint events and ban events to all enabled exporters concurrently.
Individual failures are logged and never re-raised.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ExportManager:
    """Fan-out hub for all intelligence export backends.

    Config section: ``intelligence_export`` in the proxy config dict.
    Sub-sections: ``edl``, ``f5``, ``palo_alto``, ``kafka``, ``syslog``, ``taxii``, ``misp``.

    Args:
        config: Full proxy config dict.
        redis: Redis client instance.
        http_session: Optional aiohttp.ClientSession for HTTP-based exporters.
    """

    def __init__(
        self,
        config: dict,
        redis: Any,
        http_session: Any = None,
    ) -> None:
        self._config = config
        self._redis = redis
        self._session = http_session
        self._cfg: dict = config.get("intelligence_export", {})

        # Exporter instances (populated by start())
        self._edl: Any = None
        self._f5: Any = None
        self._palo_alto: Any = None
        self._kafka: Any = None
        self._syslog: Any = None
        self._taxii: Any = None
        self._misp: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Instantiate and start all enabled exporters."""
        cfg = self._cfg

        if cfg.get("edl", {}).get("enabled", False):
            try:
                from src.tap.export.edl_server import EDLServer

                self._edl = EDLServer(self._config, self._redis)
                await self._edl.start()
                logger.info("export_manager | event=exporter_started | exporter=edl")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=edl"
                )

        if cfg.get("f5", {}).get("enabled", False):
            try:
                from src.tap.export.f5_client import F5Client

                self._f5 = F5Client(cfg.get("f5", {}), self._session)
                logger.info("export_manager | event=exporter_started | exporter=f5")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=f5"
                )

        if cfg.get("palo_alto", {}).get("enabled", False):
            try:
                from src.tap.export.palo_alto_client import PaloAltoClient

                self._palo_alto = PaloAltoClient(
                    cfg.get("palo_alto", {}), self._session
                )
                logger.info(
                    "export_manager | event=exporter_started | exporter=palo_alto"
                )
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=palo_alto"
                )

        if cfg.get("kafka", {}).get("enabled", False):
            try:
                from src.tap.export.kafka_producer import KafkaExporter

                self._kafka = KafkaExporter(cfg.get("kafka", {}))
                await self._kafka.start()
                logger.info("export_manager | event=exporter_started | exporter=kafka")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=kafka"
                )

        if cfg.get("syslog", {}).get("enabled", False):
            try:
                from src.tap.export.syslog_exporter import SyslogExporter

                self._syslog = SyslogExporter(cfg.get("syslog", {}))
                logger.info("export_manager | event=exporter_started | exporter=syslog")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=syslog"
                )

        if cfg.get("taxii", {}).get("enabled", False):
            try:
                from src.tap.export.taxii_server import TaxiiServer

                self._taxii = TaxiiServer(self._config, self._redis)
                await self._taxii.start()
                logger.info("export_manager | event=exporter_started | exporter=taxii")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=taxii"
                )

        if cfg.get("misp", {}).get("enabled", False):
            try:
                from src.tap.export.misp_client import MISPClient

                self._misp = MISPClient(cfg.get("misp", {}), self._session)
                logger.info("export_manager | event=exporter_started | exporter=misp")
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_start_failed | exporter=misp"
                )

    async def on_fingerprint(self, fp: Any) -> None:
        """Fire fingerprint event to all streaming exporters.

        Uses ``asyncio.gather(return_exceptions=True)``.  Individual failures are
        logged and never re-raised.
        """
        tasks = []

        if self._kafka is not None:
            tasks.append(self._kafka.send_fingerprint(fp))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                logger.error(
                    "export_manager | event=fingerprint_export_error | exporter_idx=%d | err=%s",
                    i,
                    result,
                )

    async def on_ban(self, ip: str, score: int, ttl: int, reason: str) -> None:
        """Fire ban event to all ban exporters.

        Uses ``asyncio.gather(return_exceptions=True)``.  Individual failures are
        logged and never re-raised.
        """
        tasks = []

        if self._kafka is not None:
            tasks.append(self._kafka.send_ban("ban", ip, score, ttl, reason))

        if self._f5 is not None:
            tasks.append(self._f5.delta_push(ip, "add"))

        if self._palo_alto is not None:
            pa_tags = self._cfg.get("palo_alto", {}).get("tags", ["ja4proxy-ban"])
            tasks.append(self._palo_alto.register_ip(ip, pa_tags))

        if self._misp is not None:
            tasks.append(self._misp.push_ban(ip, score, reason))

        # Syslog is sync — run in executor
        if self._syslog is not None:
            action = (
                "signal_ban"
                if score >= 85
                else ("signal_block" if score >= 70 else "flag")
            )
            loop = asyncio.get_event_loop()
            tasks.append(
                loop.run_in_executor(
                    None, self._syslog.send, "ban", ip, score, action, None
                )
            )

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                logger.error(
                    "export_manager | event=ban_export_error | exporter_idx=%d | err=%s",
                    i,
                    result,
                )

    async def close(self) -> None:
        """Stop all exporters."""
        for name, exporter in [
            ("edl", self._edl),
            ("taxii", self._taxii),
            ("kafka", self._kafka),
        ]:
            if exporter is not None:
                try:
                    await exporter.close()
                except Exception:
                    logger.exception(
                        "export_manager | event=exporter_close_error | exporter=%s",
                        name,
                    )

        if self._syslog is not None:
            try:
                self._syslog.close()
            except Exception:
                logger.exception(
                    "export_manager | event=exporter_close_error | exporter=syslog"
                )
