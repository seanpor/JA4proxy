"""In-process cache layer for JA4proxy (Phase 0)."""

from .local_cache import LocalCache, LRUCache

__all__ = ["LRUCache", "LocalCache"]
