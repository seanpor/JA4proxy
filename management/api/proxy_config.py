"""Read-only accessor for config/proxy.yml (mounted at /config/proxy.yml in Docker).

Used by SSO role mapping to merge config-file group→role entries with env var overrides.
The env var always takes precedence over config file entries for the same group name.

Configuration
-------------
MANAGEMENT_PROXY_CONFIG_PATH  Path to proxy.yml (default: /config/proxy.yml).
                               Override in tests via a temp file path.

Cache
-----
Config is parsed at most once per minute.  Hot-reload of the proxy process is
handled by the proxy itself; the management container does not need to watch SIGHUP.
The 60s TTL is a reasonable balance between freshness and I/O overhead for a
file that changes rarely (typically only during operator-driven config updates).
"""

import logging
import os
import time
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_CONFIG_PATH = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH", "/config/proxy.yml")
_CACHE_TTL = 60.0  # reload at most once per minute

# Module-level cache: (parsed_dict, loaded_at_monotonic)
_cache: tuple[dict, float] | None = None


def _load_proxy_config() -> dict:
    """Load proxy.yml with 60-second caching.

    Returns an empty dict if the file is absent, unreadable, or yaml is not installed.
    Never raises — callers receive an empty dict on any failure.
    """
    global _cache
    # Re-read _CONFIG_PATH on every call so tests can change the env var
    config_path = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH", "/config/proxy.yml")

    now = time.monotonic()
    if _cache is not None and now - _cache[1] < _CACHE_TTL:
        return _cache[0]

    if yaml is None:  # pragma: no cover
        return {}

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        _cache = (data, now)
        return data
    except FileNotFoundError:
        logger.debug("proxy_config | config not found at %s", config_path)
        _cache = ({}, now)
        return {}
    except Exception as exc:
        logger.warning("proxy_config | load_failed | path=%s | error=%s", config_path, exc)
        _cache = ({}, now)
        return {}


def get_sso_role_mapping() -> dict[str, str]:
    """Return SSO group→role mapping from config/proxy.yml.

    Only the ``sso.role_mapping`` section is returned.  Callers are responsible
    for merging with env var overrides (env var takes precedence).

    Returns:
        Dict mapping group name strings to role name strings, e.g.
        ``{"SOC-Analysts": "analyst", "Security-Admins": "admin"}``.
        Returns an empty dict if the section is absent or the file is not loaded.
    """
    config = _load_proxy_config()
    base: Any = (config.get("sso") or {}).get("role_mapping") or {}
    return {str(k): str(v) for k, v in base.items()}


def _clear_cache() -> None:
    """Clear the internal config cache.  Used in tests to force a fresh read."""
    global _cache
    _cache = None
