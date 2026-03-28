"""
SyslogExporter — sends events via UDP syslog in CEF or RFC 5424 format (Phase 20, Group 9).

Synchronous (no async). Uses socket.socket for UDP.

CEF format:
    CEF:0|JA4proxy|ja4proxy|1.0|{event}|{event}|{severity}|src={ip} ja4={ja4} score={score}

RFC 5424 format:
    <{priority}>1 {timestamp} {hostname} ja4proxy - - - {msg_json}
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# CEF severity mapping
_CEF_SEVERITY: dict[str, int] = {
    "signal_ban": 9,
    "signal_block": 7,
    "signal_slow": 5,
    "flag": 4,
    "observe": 3,
}

# RFC 5424 facility × 8 + severity
# facility 1 = LOCAL0; severity 5 = Notice (default for informational events)
_RFC5424_SEVERITY_MAP: dict[str, int] = {
    "signal_ban": 2,  # Critical
    "signal_block": 3,  # Error
    "signal_slow": 4,  # Warning
    "flag": 5,  # Notice
    "observe": 6,  # Informational
}


class SyslogExporter:
    """UDP syslog exporter.

    Config section: ``intelligence_export.syslog``.

    Args:
        config: The ``syslog`` sub-dict from ``intelligence_export``.
    """

    def __init__(self, config: dict) -> None:
        self._host: str = config.get("host", "127.0.0.1")
        self._port: int = int(config.get("port", 514))
        self._format: str = config.get("format", "cef")
        self._facility: int = int(config.get("facility", 1))
        self._app_name: str = config.get("app_name", "ja4proxy")
        self._send_observe: bool = bool(config.get("send_observe", False))

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            logger.exception("syslog_exporter | event=socket_create_failed")
            self._sock = None  # type: ignore[assignment]

        self._hostname = socket.gethostname()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the UDP socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def send(
        self,
        event: str,
        ip: str,
        score: int,
        action: str,
        ja4: Optional[str] = None,
    ) -> None:
        """Format and send a syslog message.

        Skips sending if ``send_observe=False`` and action is ``"observe"``.
        """
        if not self._send_observe and action == "observe":
            return

        if self._sock is None:
            return

        try:
            if self._format == "rfc5424":
                msg = self._format_rfc5424(event, ip, score, action, ja4)
            else:
                msg = self._format_cef(event, ip, score, action, ja4)

            self._sock.sendto(msg.encode(), (self._host, self._port))
        except Exception:
            logger.exception(
                "syslog_exporter | event=send_failed | ip=%s | action=%s", ip, action
            )

    # ------------------------------------------------------------------
    # Format helpers
    # ------------------------------------------------------------------

    def _format_cef(
        self,
        event: str,
        ip: str,
        score: int,
        action: str,
        ja4: Optional[str],
    ) -> str:
        """Format message as CEF."""
        severity = _CEF_SEVERITY.get(event, _CEF_SEVERITY.get(action, 3))
        ja4_part = f" ja4={ja4}" if ja4 else ""
        ext = f"src={ip}{ja4_part} score={score} action={action}"
        return f"CEF:0|JA4proxy|{self._app_name}|1.0|{event}|{event}|{severity}|{ext}"

    def _format_rfc5424(
        self,
        event: str,
        ip: str,
        score: int,
        action: str,
        ja4: Optional[str],
    ) -> str:
        """Format message as RFC 5424 syslog."""
        sev = _RFC5424_SEVERITY_MAP.get(event, _RFC5424_SEVERITY_MAP.get(action, 6))
        priority = self._facility * 8 + sev
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg_json = json.dumps(
            {"event": event, "ip": ip, "score": score, "action": action, "ja4": ja4},
            separators=(",", ":"),
        )
        return (
            f"<{priority}>1 {timestamp} {self._hostname} "
            f"{self._app_name} - - - {msg_json}"
        )
