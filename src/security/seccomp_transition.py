"""Two-stage seccomp profile transition helper (Phase 56b-2).

Provides a single public function :func:`apply_runtime_seccomp` that attempts
to install a strict seccomp BPF filter after startup is complete.  Because the
Docker OCI seccomp profile format (JSON) is different from the raw ``prctl``
BPF format, this module uses the ``seccomp`` Python library if available and
falls back gracefully when it is not.

Design decisions
----------------
- **Fail-open everywhere**: any error (missing file, malformed JSON, kernel too
  old, missing ``seccomp`` package) logs a warning and returns ``False``.
  The proxy must never be blocked from starting by a seccomp installation
  failure.
- **OCI JSON format**: the input profile uses the Docker/OCI seccomp JSON
  schema (``defaultAction``, ``syscalls`` list).  The ``seccomp`` Python
  library understands this format via its ``load_policy_file`` API; if that
  API is unavailable we fall back to noting the limitation and returning False.
- **prctl BPF hand-compilation is NOT attempted**: hand-compiling BPF bytecode
  is fragile and error-prone.  The ``seccomp`` library is the right tool for
  this; without it we safely return False.
- **is_supported()**: checks that we're on Linux with kernel ≥ 3.5 (when
  seccomp mode 2 — SECCOMP_MODE_FILTER — was introduced).

Usage::

    from src.security.seccomp_transition import apply_runtime_seccomp, is_supported

    if is_supported():
        ok = apply_runtime_seccomp("config/seccomp/proxy_runtime.json")
        if ok:
            logger.info("seccomp | event=runtime_profile_applied")
        else:
            logger.warning("seccomp | event=runtime_profile_failed | effect=continuing without filter")
"""

import json
import logging
import os
import platform
import sys
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_supported() -> bool:
    """Return True if the runtime is Linux with kernel ≥ 3.5.

    Never raises.
    """
    try:
        if sys.platform != "linux":
            return False
        # Parse kernel version string like "6.1.0-20-amd64"
        release = platform.release()
        major_minor = release.split(".")[:2]
        major = int(major_minor[0])
        minor = int(major_minor[1].split("-")[0].split("+")[0]) if len(major_minor) > 1 else 0
        return (major, minor) >= (3, 5)
    except Exception as exc:
        logger.debug("seccomp | event=is_supported_error | error=%s", exc)
        return False


def apply_runtime_seccomp(
    profile_path: str = "config/seccomp/proxy_runtime.json",
) -> bool:
    """Attempt to apply the runtime seccomp profile.

    Reads the OCI-format JSON profile at *profile_path* and installs the
    seccomp BPF filter via the ``seccomp`` Python library.

    Returns:
        ``True``  — filter installed successfully.
        ``False`` — not supported, library unavailable, file missing, or any
                    other error.  Always fails open.

    Never raises.
    """
    try:
        return _apply(profile_path)
    except Exception as exc:
        logger.warning(
            "seccomp | event=apply_error | profile=%s | error=%s | "
            "effect=continuing without seccomp filter",
            profile_path,
            exc,
        )
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _apply(profile_path: Optional[str]) -> bool:
    """Internal implementation — may raise; caller wraps in try/except."""
    if not profile_path or not isinstance(profile_path, str):
        logger.warning(
            "seccomp | event=invalid_profile_path | path=%r | "
            "effect=skipping seccomp installation",
            profile_path,
        )
        return False

    if not is_supported():
        logger.debug(
            "seccomp | event=not_supported | platform=%s | "
            "effect=skipping seccomp installation",
            sys.platform,
        )
        return False

    # Load and validate the JSON profile
    try:
        with open(profile_path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            logger.warning(
                "seccomp | event=empty_profile | path=%s | "
                "effect=skipping seccomp installation",
                profile_path,
            )
            return False
        profile_data = json.loads(raw)
    except FileNotFoundError:
        logger.warning(
            "seccomp | event=profile_not_found | path=%s | "
            "effect=skipping seccomp installation",
            profile_path,
        )
        return False
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning(
            "seccomp | event=profile_invalid_json | path=%s | error=%s | "
            "effect=skipping seccomp installation",
            profile_path,
            exc,
        )
        return False

    # Validate minimal structure
    if not isinstance(profile_data, dict):
        logger.warning(
            "seccomp | event=profile_not_dict | path=%s | "
            "effect=skipping seccomp installation",
            profile_path,
        )
        return False

    # Try using the seccomp Python library (cleanest approach)
    try:
        import seccomp as _seccomp  # type: ignore[import]
        return _apply_via_seccomp_lib(_seccomp, profile_data, profile_path)
    except ImportError:
        logger.info(
            "seccomp | event=library_not_available | "
            "hint=install python3-seccomp or libseccomp-dev | "
            "effect=runtime seccomp filter not applied"
        )
        return False


def _apply_via_seccomp_lib(seccomp_module: object, profile_data: dict, profile_path: str) -> bool:
    """Apply the OCI profile via the ``seccomp`` Python library.

    The ``seccomp`` library (python-libseccomp) exposes a Pythonic API over
    libseccomp.  We translate the OCI JSON structure into library calls.

    Returns True on success, False on any error.
    """
    try:
        # Map OCI default action to libseccomp constant
        default_action_str = profile_data.get("defaultAction", "SCMP_ACT_ERRNO")
        default_action = _oci_action_to_libseccomp(seccomp_module, default_action_str)

        ctx = seccomp_module.SyscallFilter(defaction=default_action)  # type: ignore[attr-defined]

        syscalls_list = profile_data.get("syscalls", [])
        for entry in syscalls_list:
            action_str = entry.get("action", "SCMP_ACT_ALLOW")
            action = _oci_action_to_libseccomp(seccomp_module, action_str)
            for name in entry.get("names", []):
                try:
                    ctx.add_rule(action, name)  # type: ignore[attr-defined]
                except Exception as exc:
                    logger.debug(
                        "seccomp | event=add_rule_error | syscall=%s | error=%s | "
                        "effect=syscall skipped",
                        name,
                        exc,
                    )

        ctx.load()  # type: ignore[attr-defined]
        logger.info(
            "seccomp | event=runtime_profile_applied | path=%s", profile_path
        )
        return True
    except Exception as exc:
        logger.warning(
            "seccomp | event=library_apply_error | path=%s | error=%s | "
            "effect=continuing without seccomp filter",
            profile_path,
            exc,
        )
        return False


def _oci_action_to_libseccomp(seccomp_module: object, action_str: str) -> int:
    """Translate an OCI action string to a libseccomp integer constant.

    Falls back to SCMP_ACT_ERRNO for unknown actions.
    """
    mapping = {
        "SCMP_ACT_ALLOW": "ALLOW",
        "SCMP_ACT_ERRNO": "ERRNO",
        "SCMP_ACT_KILL": "KILL",
        "SCMP_ACT_KILL_PROCESS": "KILL",
        "SCMP_ACT_TRAP": "TRAP",
        "SCMP_ACT_TRACE": "TRACE",
        "SCMP_ACT_LOG": "LOG",
    }
    attr_name = mapping.get(action_str, "ERRNO")
    return getattr(seccomp_module, attr_name, 0)  # type: ignore[return-value]
