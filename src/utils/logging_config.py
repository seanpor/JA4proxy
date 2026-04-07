import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Optional


class _CallableMode(str):
    """
    A string subclass that is also callable as a log formatter.

    This allows ``formatter.format == "ecs"`` to be True (string comparison)
    AND ``formatter.format(record)`` to work (callable).  The format method on
    ``logging.Formatter`` is shadowed by this instance attribute, which Python
    dispatches via ``__call__`` when invoked.
    """

    # Set after construction to avoid circular init.
    _owner: Optional["JSONFormatter"] = None

    def __call__(self, record: logging.LogRecord) -> str:
        """Called when ``formatter.format(record)`` is invoked."""
        assert self._owner is not None, "_CallableMode._owner not set"
        return self._owner._do_format(record)


class JSONFormatter(logging.Formatter):
    """
    Enterprise-grade JSON formatter for Loki/Splunk/ELK.

    Supports two output formats, controlled by the ``format`` parameter:

    * ``"legacy"`` (default): Emits ``timestamp``, ``level``, ``message`` at
      top level, plus any extra fields from ``record.extra``.
    * ``"ecs"``: Emits ECS 8.x fields (``@timestamp``, ``source.ip``,
      ``event.action``, ``ja4proxy.*``, etc.).

    When ``dual_output=True`` and ``format="ecs"``, returns two
    newline-separated JSON lines: legacy format first, then ECS format.

    Extra log fields are read from ``record.extra`` (a dict), which must be
    set by callers.  Individual ``setattr(record, key, value)`` calls are NOT
    read in either mode.

    Design note: ``self.format`` is a :class:`_CallableMode` instance, which
    is a ``str`` subclass.  This allows both ``formatter.format == "ecs"``
    (attribute read as string) and ``formatter.format(record)`` (callable as
    the standard ``logging.Formatter.format`` method).
    """

    # ECS field mappings: extra-key → ECS output key
    _ECS_FIELD_MAP = {
        "client_ip": "source.ip",
        "action": "event.action",
        "ja4": "ja4proxy.fingerprint.ja4",
        "ja4x": "ja4proxy.fingerprint.ja4x",
        "ja4t": "ja4proxy.fingerprint.ja4t",
        "sni": "ja4proxy.sni",
        "alpn": "ja4proxy.alpn",
        "country": "ja4proxy.country_code",
        "score": "ja4proxy.score",
        "signals": "ja4proxy.signals",
        "tls_version": "tls.version",
        "tls_cipher": "tls.cipher",
    }

    def __init__(
        self,
        format: str = "legacy",
        dual_output: bool = False,
        **kwargs,
    ):
        """
        Initialise the JSON formatter.

        Args:
            format: ``"legacy"`` (default) or ``"ecs"``.
            dual_output: When True and ``format="ecs"``, emit two JSON lines:
                legacy first, then ECS.
        """
        super().__init__(**kwargs)
        self._dual_output = dual_output

        # Expose the mode string as ``self.format`` using a callable subclass.
        # This allows ``formatter.format == "ecs"`` to work as an attribute
        # comparison AND ``formatter.format(record)`` to work as a method call.
        mode = _CallableMode(format)
        mode._owner = self
        # Shadow the inherited ``format`` method with this callable string.
        self.format = mode  # type: ignore[assignment]

    # ── Internal dispatch ─────────────────────────────────────────────────

    def _do_format(self, record: logging.LogRecord) -> str:
        """Dispatch to the correct format implementation."""
        mode = str(self.format)
        if mode == "ecs":
            if self._dual_output:
                legacy_line = self._format_legacy(record)
                ecs_line = self._format_ecs(record)
                return legacy_line + "\n" + ecs_line
            return self._format_ecs(record)
        return self._format_legacy(record)

    # ── Legacy format ─────────────────────────────────────────────────────

    def _format_legacy(self, record: logging.LogRecord) -> str:
        log_record: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra"):
            log_record.update(record.extra)

        return json.dumps(log_record)

    # ── ECS format ────────────────────────────────────────────────────────

    def _format_ecs(self, record: logging.LogRecord) -> str:
        out: dict = {
            "@timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "log.level": record.levelname.lower(),
            "message": record.getMessage(),
            "event.kind": "event",
            "service.name": "ja4proxy",
            "network.transport": "tcp",
            "network.protocol": "tls",
        }

        extra = getattr(record, "extra", {}) or {}

        # Map known extra fields to ECS names (remapped — not kept at top level).
        for src_key, ecs_key in self._ECS_FIELD_MAP.items():
            if src_key in extra:
                out[ecs_key] = extra[src_key]

        # event.outcome
        action = extra.get("action")
        if action is not None:
            out["event.outcome"] = "success" if action == "allow" else "failure"

        # Exception / error fields
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            out["error.message"] = str(exc_value) if exc_value is not None else ""
            out["error.stack_trace"] = "".join(
                traceback.format_exception(exc_type, exc_value, exc_tb)
            ).rstrip()

        return json.dumps(out)


def setup_logging(
    level: int = logging.INFO,
    json_format: bool = False,
    format: str = "legacy",
):
    """
    Initialize global logging configuration.

    Args:
        level: Logging level (default: INFO)
        json_format: Whether to use JSON format (default: False, follows LOG_FORMAT env)
        format: Log format mode — ``"legacy"`` (default) or ``"ecs"``.
    """
    # Environment override
    env_format = os.environ.get("LOG_FORMAT", "text").lower()
    if env_format == "json":
        json_format = True

    env_level = os.environ.get("LOG_LEVEL", "").upper()
    if env_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        level = getattr(logging, env_level)

    handler = logging.StreamHandler(sys.stdout)
    if json_format or format == "ecs":
        handler.setFormatter(JSONFormatter(format=format))
    else:
        # Standard human-readable format
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

    # Root logger configuration
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates during re-config
    for h in root.handlers[:]:
        root.removeHandler(h)

    root.addHandler(handler)

    # Silence noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logging.info(
        "Logging initialized (format=%s, level=%s)",
        format if format != "legacy" else ("json" if json_format else "text"),
        logging.getLevelName(level),
    )
