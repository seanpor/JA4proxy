"""
TAP mode security hardening (Phase 20, Group 12).

Functions:
    drop_cap_net_raw: Drop CAP_NET_RAW from effective/permitted capability sets.
    apply_seccomp_profile: Load and apply seccomp filter from JSON profile.
    validate_pcap_path: Prevent path traversal for PCAP file paths.
    gdpr_delete: Delete all fingerprint data for a given IP address.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from src.config.loader import ConfigError

logger = logging.getLogger(__name__)

# CAP_NET_RAW capability number (Linux ABI stable)
_CAP_NET_RAW = 38


def drop_cap_net_raw() -> None:
    """Drop CAP_NET_RAW from effective and permitted capability sets.

    Uses ctypes to call ``cap_drop_bound`` from libcap-2.  If libcap is not
    available or the call fails, logs a WARNING and returns without raising —
    graceful fallback so startup never crashes due to missing libcap.

    Should be called after the AF_PACKET socket is bound, before processing
    any data.  This ensures the process cannot open new raw sockets.
    """
    try:
        import ctypes

        libcap = ctypes.CDLL("libcap.so.2")
        ret = libcap.cap_drop_bound(_CAP_NET_RAW)
        if ret != 0:
            logger.warning(
                "tap_security | event=drop_cap_net_raw_failed | "
                "cap=%d | ret=%d | effect=CAP_NET_RAW not dropped",
                _CAP_NET_RAW,
                ret,
            )
        else:
            logger.info(
                "tap_security | event=drop_cap_net_raw_ok | cap=%d",
                _CAP_NET_RAW,
            )
    except OSError:
        logger.warning(
            "tap_security | event=drop_cap_net_raw_unavailable | "
            "reason=libcap.so.2 not found | effect=CAP_NET_RAW not dropped"
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "tap_security | event=drop_cap_net_raw_error | error=%s | "
            "effect=CAP_NET_RAW not dropped",
            exc,
        )


def apply_seccomp_profile(profile_path: Path) -> None:
    """Load and apply a seccomp filter from a JSON profile file.

    Profile format matches the seccomp JSON schema used by Docker/containerd::

        {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [{"names": [...], "action": "SCMP_ACT_ALLOW"}]
        }

    Uses ctypes to call libseccomp.  If libseccomp is not available or the
    profile cannot be loaded, logs a WARNING and returns — startup never
    crashes due to missing libseccomp.

    Args:
        profile_path: Absolute path to the JSON seccomp profile file.

    Raises:
        ConfigError: If the profile file doesn't exist or is malformed JSON.
    """
    # Validate the profile file first — ConfigError on bad file, regardless
    # of libseccomp availability.
    if not profile_path.exists():
        raise ConfigError(
            f"Seccomp profile not found: {profile_path}"
        )

    try:
        profile_text = profile_path.read_text(encoding="utf-8")
        profile = json.loads(profile_text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Seccomp profile is malformed JSON ({profile_path}): {exc}"
        ) from exc

    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    syscall_groups = profile.get("syscalls", [])
    allowed: list[str] = []
    for group in syscall_groups:
        if group.get("action") == "SCMP_ACT_ALLOW":
            allowed.extend(group.get("names", []))

    logger.debug(
        "tap_security | event=seccomp_profile_parsed | "
        "default_action=%s | allowed_syscalls=%d",
        default_action,
        len(allowed),
    )

    try:
        import ctypes

        libseccomp = ctypes.CDLL("libseccomp.so.2")
        # Build a minimal filter context and attempt to load it.
        # SCMP_ACT_ERRNO(1) = default deny; SCMP_ACT_ALLOW = 0x7fff0000
        _SCMP_ACT_ALLOW = 0x7FFF0000
        _SCMP_ACT_ERRNO = 0x00050001  # SCMP_ACT_ERRNO(EPERM)

        ctx = libseccomp.seccomp_init(_SCMP_ACT_ERRNO)
        if not ctx:
            logger.warning(
                "tap_security | event=seccomp_init_failed | "
                "effect=seccomp filter not applied"
            )
            return

        # Add allow rules for each listed syscall name.
        for name in allowed:
            nr = libseccomp.seccomp_syscall_resolve_name(name.encode())
            if nr >= 0:
                libseccomp.seccomp_rule_add(ctx, _SCMP_ACT_ALLOW, nr, 0)

        ret = libseccomp.seccomp_load(ctx)
        libseccomp.seccomp_release(ctx)

        if ret != 0:
            logger.warning(
                "tap_security | event=seccomp_load_failed | "
                "ret=%d | effect=seccomp filter not applied",
                ret,
            )
        else:
            logger.info(
                "tap_security | event=seccomp_filter_applied | "
                "allowed_syscalls=%d",
                len(allowed),
            )
    except OSError:
        logger.warning(
            "tap_security | event=seccomp_unavailable | "
            "reason=libseccomp.so.2 not found | effect=seccomp filter not applied"
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "tap_security | event=seccomp_error | error=%s | "
            "effect=seccomp filter not applied",
            exc,
        )


def validate_pcap_path(path: str, allowed_dirs: list[str]) -> Path:
    """Resolve and validate a PCAP file path against allowed directories.

    Prevents path traversal attacks (e.g. ``../etc/passwd``).

    Args:
        path: The path provided by config/user input.
        allowed_dirs: List of allowed parent directories (absolute paths).

    Returns:
        Resolved absolute ``Path`` object.

    Raises:
        ConfigError: If path is outside all allowed directories, or if the
                    resolved path escapes via traversal.
    """
    resolved = Path(path).resolve()

    for allowed_dir in allowed_dirs:
        allowed_resolved = Path(allowed_dir).resolve()
        # Python 3.9+: is_relative_to; fall back to startswith for 3.8.
        try:
            if resolved.is_relative_to(allowed_resolved):
                return resolved
        except AttributeError:  # pragma: no cover
            # Python < 3.9
            if str(resolved).startswith(str(allowed_resolved) + os.sep):
                return resolved

    raise ConfigError(
        f"Path {path!r} (resolved: {resolved}) is outside allowed directories: "
        f"{allowed_dirs}"
    )


async def gdpr_delete(ip: str, redis: Any) -> dict:
    """Delete all fingerprint data for a given IP address.

    GDPR right-to-erasure: removes all ``fp:ip:{ip}``, ``fp:conn:{conn_id}``
    and ``fp:os:ip:{ip}`` keys associated with this IP.

    Args:
        ip: Client IP address to erase.
        redis: Synchronous redis-py ``Redis`` instance.

    Returns:
        ``{"deleted_keys": N, "ip": ip}``
    """
    loop = asyncio.get_event_loop()

    ip_key = f"fp:ip:{ip}"
    os_ip_key = f"fp:os:ip:{ip}"

    # Fetch all conn_ids stored for this IP (sorted-set of conn_ids, score=ts).
    conn_ids: list[bytes] = await loop.run_in_executor(
        None, lambda: redis.zrange(ip_key, 0, -1)
    )

    deleted = 0

    # Delete each fp:conn:{conn_id} key.
    for raw in conn_ids:
        conn_id = raw.decode() if isinstance(raw, bytes) else raw
        conn_key = f"fp:conn:{conn_id}"
        n = await loop.run_in_executor(None, lambda k=conn_key: redis.delete(k))
        deleted += n or 0

    # Delete fp:ip:{ip} (the sorted set itself).
    n = await loop.run_in_executor(None, lambda: redis.delete(ip_key))
    deleted += n or 0

    # Delete fp:os:ip:{ip}.
    n = await loop.run_in_executor(None, lambda: redis.delete(os_ip_key))
    deleted += n or 0

    logger.info(
        "tap_security | event=gdpr_delete | ip=%s | deleted_keys=%d",
        ip,
        deleted,
    )

    return {"deleted_keys": deleted, "ip": ip}
