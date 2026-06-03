"""
Base classes and interfaces for Threat Intelligence providers (Phase 23).
"""

import abc
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .models import RiskSignal

logger = logging.getLogger(__name__)


async def retry_with_backoff(
    coro_fn: Callable[[], Any],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    feed_name: str = "unknown",
) -> Any:
    """
    Call coro_fn() up to max_attempts times with exponential backoff.

    Raises the last exception if all attempts fail.
    Logs each retry at WARNING level using the standard ti_feed log format.

    Backoff formula: min(base_delay * 2**attempt, max_delay)
    Uses asyncio.sleep — never blocks the event loop.
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(max_attempts):
        try:
            return await coro_fn()
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                delay = min(base_delay * (2**attempt), max_delay)
                logger.warning(
                    "ti_feed | event=retry | feed=%s | attempt=%d/%d | delay=%.1fs",
                    feed_name,
                    attempt + 1,
                    max_attempts,
                    delay,
                )
                await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


@dataclass
class TIProviderConfig:
    """Base configuration for TI providers."""

    enabled: bool = False
    api_key: str = ""
    cache_ttl_seconds: int = 86400  # 24h default
    lookup_timeout_seconds: int = 10
    score_cap: int = 40
    queue_size: int = 500
    worker_count: int = 3


class TIProvider(abc.ABC):
    """
    Abstract Base Class for Threat Intelligence providers.
    """

    @abc.abstractmethod
    async def start(self) -> None:
        """Initialize background workers."""
        pass

    @abc.abstractmethod
    async def stop(self) -> None:
        """Shutdown background workers."""
        pass

    @abc.abstractmethod
    def get_signal(self, ip: str) -> Optional[RiskSignal]:
        """
        Hot-path entry point. Returns cached signal or None.
        Should NEVER block on network I/O.
        """
        pass

    @abc.abstractmethod
    def on_config_reload(self, new_config: dict) -> None:
        """Handle hot-reloadable configuration changes."""
        pass
