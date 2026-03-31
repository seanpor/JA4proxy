"""
Base classes and interfaces for Threat Intelligence providers (Phase 23).
"""

import abc
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .models import RiskSignal

logger = logging.getLogger(__name__)


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
