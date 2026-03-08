"""Hot-reloadable configuration loader for JA4proxy.

Trigger mechanisms:
  1. SIGHUP signal → reloads config/proxy.yml
  2. Redis pub/sub message {"type": "config_reload"} → same effect
  3. Management UI (Phase 13) sends pub/sub message

Keys that CANNOT be hot-reloaded (require process restart):
  proxy.bind_host    — requires socket rebind
  proxy.bind_port    — requires socket rebind
  redis.host         — requires Redis reconnection
  redis.port         — requires Redis reconnection
  redis.db           — requires Redis reconnection

Changes to any non-reloadable key are detected and rejected with a
ConfigError — the previous config remains active.

JSON log events emitted:
  reload_complete  — INFO  — on every successful hot reload
  reload_failed    — ERROR — when reload fails validation or file read
  startup          — INFO  — on initial load (emitted by caller)
"""

import asyncio
import json
import logging
import os
import re
import signal
from pathlib import Path
from typing import Any, Callable

import yaml
from prometheus_client import Counter

logger = logging.getLogger(__name__)

_CONFIG_RELOADS = Counter(
    "ja4proxy_config_reloads_total",
    "Successful hot config reloads",
)

# ---------------------------------------------------------------------------
# Keys that require a process restart — cannot be hot-reloaded.
# Documented here as the single source of truth.
# ---------------------------------------------------------------------------
_NON_RELOADABLE_KEYS: frozenset[str] = frozenset(
    [
        "proxy.bind_host",  # Requires socket rebind
        "proxy.bind_port",  # Requires socket rebind
        "redis.host",  # Requires Redis reconnection
        "redis.port",  # Requires Redis reconnection
        "redis.db",  # Requires Redis reconnection
    ]
)


class ConfigError(Exception):
    """Raised when config loading or validation fails."""


class ConfigLoader:
    """Load and hot-reload proxy.yml with env-var expansion.

    Usage::

        loader = ConfigLoader("config/proxy.yml")
        config = await loader.load()
        loader.setup_sighup(asyncio.get_event_loop())
        loader.on_reload(lambda cfg: cache.update(cfg))

    Args:
        config_path: Path to proxy.yml. Default: ``config/proxy.yml``.
    """

    def __init__(self, config_path: str = "config/proxy.yml") -> None:
        self._path = Path(config_path)
        self._config: dict = {}
        self._callbacks: list[Callable[[dict], None]] = []
        self._reload_count: int = 0

    async def load(self) -> dict:
        """Perform initial config load. Must be called once on startup.

        Returns:
            Parsed config dict.

        Raises:
            ConfigError: If the file cannot be read or parsed.
        """
        self._config = self._read_and_parse()
        logger.info(
            json.dumps(
                {
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "config",
                    "event": "initial_load",
                    "path": str(self._path),
                }
            )
        )
        return self._config

    def get(self) -> dict:
        """Return the current config dict (zero-copy read, never blocks)."""
        return self._config

    async def reload(self) -> None:
        """Hot reload: parse new config, validate, apply atomically.

        Non-reloadable key changes are rejected and the previous config
        remains active. Registered callbacks are called after a successful
        reload.

        Raises:
            ConfigError: If parsing fails or a non-reloadable key changed.
        """
        try:
            new_config = self._read_and_parse()
        except ConfigError as exc:
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "config",
                        "event": "reload_failed",
                        "error": str(exc),
                    }
                )
            )
            raise

        try:
            self._check_non_reloadable_unchanged(new_config)
        except ConfigError as exc:
            logger.error(
                json.dumps(
                    {
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "config",
                        "event": "reload_failed",
                        "error": str(exc),
                    }
                )
            )
            raise

        self._config = new_config
        self._reload_count += 1
        _CONFIG_RELOADS.inc()

        logger.info(
            json.dumps(
                {
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "config",
                    "event": "reload_complete",
                    "path": str(self._path),
                    "reload_count": self._reload_count,
                }
            )
        )

        for callback in self._callbacks:
            try:
                callback(new_config)
            except Exception as exc:  # noqa: BLE001
                logger.warning("config reload callback raised: %s", exc)

    def on_reload(self, callback: Callable[[dict], None]) -> None:
        """Register a callback invoked after every successful reload.

        The callback receives the new config dict. It must not block.
        """
        self._callbacks.append(callback)

    def setup_sighup(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register a SIGHUP handler that triggers hot reload.

        The handler schedules reload as an asyncio task — SIGHUP never
        blocks the event loop.
        """

        def _handle_sighup() -> None:
            try:
                asyncio.create_task(self._reload_and_log_error())
            except RuntimeError:
                pass  # No event loop available

        try:
            loop.add_signal_handler(signal.SIGHUP, _handle_sighup)
        except (OSError, NotImplementedError):
            # SIGHUP not available on Windows; harmless no-op
            logger.warning(
                json.dumps(
                    {
                        "type": "system",
                        "level": "WARN",
                        "subsystem": "config",
                        "event": "sighup_unavailable",
                        "reason": "platform does not support SIGHUP",
                    }
                )
            )

    @property
    def reload_count(self) -> int:
        """Number of successful hot reloads since startup."""
        return self._reload_count

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_and_parse(self) -> dict:
        """Read, expand env vars, and parse the YAML file.

        Raises:
            ConfigError: On file read or YAML parse failure.
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"Cannot read config file {self._path}: {exc}") from exc

        expanded = _expand_env_vars(raw)

        try:
            parsed = yaml.safe_load(expanded)
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML parse error in {self._path}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ConfigError(f"Config file {self._path} must be a YAML mapping")

        return parsed

    def _check_non_reloadable_unchanged(self, new_config: dict) -> None:
        """Reject the reload if any non-reloadable key has changed.

        Raises:
            ConfigError: Listing the first changed non-reloadable key.
        """
        for dotted_key in _NON_RELOADABLE_KEYS:
            old_val = _get_nested(self._config, dotted_key)
            new_val = _get_nested(new_config, dotted_key)
            if old_val != new_val:
                raise ConfigError(
                    f"Cannot hot-reload non-reloadable key '{dotted_key}' "
                    f"(old={old_val!r}, new={new_val!r}). "
                    "Restart the proxy to apply this change."
                )

    async def _reload_and_log_error(self) -> None:
        """Wrapper for SIGHUP handler — swallows ConfigError so it is logged."""
        try:
            await self.reload()
        except ConfigError:
            pass  # Already logged inside reload()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_ENV_VAR_RE = re.compile(r"\$\{(\w+)(?::-(.*?))?\}")


def _expand_env_vars(text: str) -> str:
    """Expand ``${VAR:-default}`` placeholders with environment variables.

    If the variable is not set and no default is provided, substitutes
    an empty string (same behaviour as shell ``${VAR:-}``).
    """

    def replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(2) if match.group(2) is not None else ""
        return os.environ.get(var_name, default)

    return _ENV_VAR_RE.sub(replace, text)


def _get_nested(config: dict, dotted_key: str) -> Any:
    """Return the value at a dotted-path key, or None if absent."""
    parts = dotted_key.split(".")
    node: Any = config
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node
