"""Supply-chain and configuration integrity monitoring (Phase 35a).

Provides:
- :class:`IntegrityMonitor` — verifies Ed25519 signatures for config files,
  runs a background SHA-256 file-tree monitor, and appends to an
  append-only hash-chained audit log.

All public methods fail open: they log errors and return safe values
rather than propagating exceptions to callers.

Signature format
----------------
The signature file (``<config_path>.sig``) holds the raw 64-byte Ed25519
signature.  Base64-encoded forms are also accepted.

Public-key format
-----------------
PEM-encoded SubjectPublicKeyInfo is the canonical format (written by
``config-signer.py``).  Raw 32-byte keys and base64-encoded raw keys are
also accepted.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from prometheus_client import Counter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics — module-level singletons
# ---------------------------------------------------------------------------

# Simple total counter — accessible via monitor.violation_counter._value.get()
# for tests and dashboards that need a plain total.
_INTEGRITY_VIOLATIONS = Counter(
    "ja4proxy_integrity_violation_total",
    "Total file-integrity violations detected by the background monitor",
)

# Per-path labelled counter for finer-grained alerting.
_INTEGRITY_VIOLATIONS_BY_PATH = Counter(
    "ja4proxy_integrity_violation_by_path_total",
    "File-integrity violations by path",
    ["path"],
)

# Skipped-verification counter — fired when optional dependencies are absent.
_INTEGRITY_SKIP = Counter(
    "ja4proxy_integrity_skip_total",
    "Integrity checks skipped due to missing optional dependency",
    ["reason"],
)

# ---------------------------------------------------------------------------
# IntegrityMonitor
# ---------------------------------------------------------------------------


class _InstanceViolationCounter:
    """Thin wrapper around a simple float counter that mimics the
    ``prometheus_client.Counter._value.get()`` interface.

    Each :class:`IntegrityMonitor` instance gets its own counter so that
    tests that create fresh instances start from zero.  The global
    Prometheus counter is incremented in parallel for real metrics export.
    """

    def __init__(self) -> None:
        self._count: float = 0.0

    def get(self) -> float:
        return self._count

    def inc(self, amount: float = 1.0) -> None:
        self._count += amount
        # Also propagate to global Prometheus counter
        _INTEGRITY_VIOLATIONS.inc(amount)


class _ViolationCounterShim:
    """Shim that exposes ``._value`` compatible with prometheus ``Counter._value``."""

    def __init__(self) -> None:
        self._value = _InstanceViolationCounter()

    def inc(self, amount: float = 1.0) -> None:
        self._value.inc(amount)


class IntegrityMonitor:
    """Monitors the integrity of proxy source files and configuration.

    Args:
        config: The proxy configuration dict (top-level).  Optional — when
                omitted an empty dict is used (suitable for testing).
    """

    def __init__(self, config: Optional[Dict] = None) -> None:
        self._config = config or {}
        self._integrity_cfg = self._config.get("integrity", {})
        # SHA-256 baseline: path -> hex digest
        self._baseline: Dict[str, str] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._shutdown: bool = False
        # Per-instance counter shim: monitor.violation_counter._value.get()
        # starts at 0 for each new IntegrityMonitor instance.
        self.violation_counter = _ViolationCounterShim()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_config_signature(self, config_path: str, pubkey_path: str) -> bool:
        """Verify the Ed25519 signature of *config_path*.

        The expected signature file is ``<config_path>.sig``.  The signature
        may be stored as raw 64 bytes or base64-encoded.

        Returns:
            ``True``  — signature present and valid.
            ``False`` — signature file missing or signature invalid.
            ``True``  — also returned when the ``cryptography`` library is
                        unavailable (fail-open with a WARNING).

        Never raises.
        """
        try:
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            logger.warning(
                "WARN | integrity | event=cryptography_missing | "
                "effect=signature_verification_skipped"
            )
            _INTEGRITY_SKIP.labels(reason="cryptography_missing").inc()
            return True

        sig_path = config_path + ".sig"
        try:
            with open(config_path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            logger.error(
                "integrity | event=config_read_error | path=%s | error=%s",
                config_path,
                exc,
            )
            return False

        try:
            with open(sig_path, "rb") as fh:
                sig_raw = fh.read()
            signature = _decode_signature(sig_raw)
        except (OSError, ValueError) as exc:
            logger.warning(
                "integrity | event=sig_file_missing_or_invalid | "
                "path=%s | error=%s",
                sig_path,
                exc,
            )
            return False

        try:
            public_key = _load_pubkey(pubkey_path)
        except (OSError, ValueError) as exc:
            logger.error(
                "integrity | event=pubkey_read_error | path=%s | error=%s",
                pubkey_path,
                exc,
            )
            return False

        try:
            public_key.verify(signature, data)
            logger.info(
                "integrity | event=signature_valid | path=%s", config_path
            )
            return True
        except InvalidSignature:
            logger.error(
                "integrity | event=signature_invalid | path=%s", config_path
            )
            return False
        except Exception as exc:
            logger.error(
                "integrity | event=verify_error | path=%s | error=%s",
                config_path,
                exc,
            )
            return False

    async def start_background_monitor(
        self,
        paths: List[str],
        interval_s: float = 60,
    ) -> None:
        """Hash all files in *paths* (recursively for directories) every
        *interval_s* seconds.  On mismatch: increment
        ``ja4proxy_integrity_violation_total``, log at ERROR level.

        The first pass establishes the baseline; subsequent passes compare
        against it.  Shutdown by setting :attr:`_shutdown` to ``True`` or
        cancelling the current :class:`asyncio.Task`.

        Never raises.
        """
        self._shutdown = False
        try:
            # Establish baseline on first pass
            baseline = _hash_paths(paths)
            self._baseline = baseline
            logger.info(
                "integrity | event=baseline_established | files=%d",
                len(baseline),
            )

            while not self._shutdown:
                await asyncio.sleep(interval_s)
                if self._shutdown:
                    break
                current = _hash_paths(paths)
                _compare_and_alert(
                    self._baseline, current, self._integrity_cfg,
                    self.violation_counter,
                )
        except asyncio.CancelledError:
            logger.info("integrity | event=monitor_stopped")
            return
        except Exception as exc:
            logger.error(
                "integrity | event=monitor_error | error=%s", exc
            )

    def append_audit_log(
        self, log_path: str, status: str, detail: str
    ) -> None:
        """Append a JSON line to *log_path* forming a hash-chain.

        Each entry contains:
        - ``timestamp``  — ISO-8601 UTC
        - ``status``     — caller-supplied status string
        - ``detail``     — caller-supplied detail string
        - ``prev_hash``  — SHA-256 hex of the raw bytes of the previous entry
                           (empty string for the first entry)

        File opened in append mode.  Never raises.
        """
        try:
            prev_hash = _read_last_line_hash(log_path)
            entry = {
                "timestamp": _utc_now_iso(),
                "status": status,
                "detail": detail,
                "prev_hash": prev_hash,
            }
            line = json.dumps(entry, separators=(",", ":")) + "\n"
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
            with open(log_path, "a") as fh:
                fh.write(line)
        except Exception as exc:
            logger.error(
                "integrity | event=audit_log_error | path=%s | error=%s",
                log_path,
                exc,
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_signature(raw: bytes) -> bytes:
    """Return a raw 64-byte Ed25519 signature from *raw*.

    Accepts:
    - Raw 64-byte signature (stored directly as binary)
    - Base64-encoded 64-byte signature (with or without trailing newline/whitespace)

    Strategy: if the raw content is exactly 64 bytes, treat as raw signature.
    Otherwise attempt base64 decoding (stripping only ASCII whitespace first).
    """
    # Exact 64-byte raw signature — common when written by privkey.sign()
    if len(raw) == 64:
        return raw

    # Remove only trailing ASCII whitespace (newline, space, CR) for base64 input.
    # Do NOT use bytes.strip() on potential raw binary data as it removes \x09, \x20 etc.
    stripped = raw.rstrip(b" \t\r\n")
    if len(stripped) == 64:
        return stripped

    # Try base64 decode
    import base64
    try:
        decoded = base64.b64decode(stripped)
        if len(decoded) == 64:
            return decoded
        raise ValueError(f"Decoded signature is {len(decoded)} bytes, expected 64")
    except Exception as exc:
        raise ValueError(f"Cannot decode signature: {exc}") from exc


def _load_pubkey(pubkey_path: str):
    """Load an Ed25519 public key from *pubkey_path*.

    Accepts PEM (SubjectPublicKeyInfo), raw 32-byte, or base64-encoded raw key.

    Returns an Ed25519PublicKey instance.
    Raises OSError / ValueError on failure.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    with open(pubkey_path, "rb") as fh:
        raw = fh.read()

    stripped = raw.strip()

    # PEM
    if stripped.startswith(b"-----"):
        return load_pem_public_key(stripped)

    # Try base64 → 32 bytes raw key
    import base64
    try:
        decoded = base64.b64decode(stripped)
        if len(decoded) == 32:
            return Ed25519PublicKey.from_public_bytes(decoded)
    except Exception:
        pass

    # Raw 32-byte key
    if len(stripped) == 32:
        return Ed25519PublicKey.from_public_bytes(stripped)

    raise ValueError(
        f"Cannot parse public key from {pubkey_path}: "
        f"unrecognised format ({len(stripped)} bytes)"
    )


def _hash_file(path: str) -> str:
    """Return the SHA-256 hex digest of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_paths(paths: List[str]) -> Dict[str, str]:
    """Return a dict of ``{abs_path: sha256_hex}`` for all files in *paths*.

    Directories are expanded recursively.  Errors on individual files are
    logged and skipped.
    """
    result: Dict[str, str] = {}
    for raw_path in paths:
        p = Path(raw_path)
        try:
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    # Skip Python bytecode caches — they are regenerated automatically
                    # during normal interpreter operation and would cause false positives.
                    if "__pycache__" in child.parts or child.suffix in (".pyc", ".pyo"):
                        continue
                    if child.is_file():
                        try:
                            result[str(child)] = _hash_file(str(child))
                        except OSError as exc:
                            logger.warning(
                                "integrity | event=hash_error | path=%s | error=%s",
                                child,
                                exc,
                            )
            elif p.is_file():
                result[str(p)] = _hash_file(str(p))
            else:
                logger.debug(
                    "integrity | event=path_not_found | path=%s", raw_path
                )
        except Exception as exc:
            logger.warning(
                "integrity | event=path_error | path=%s | error=%s",
                raw_path,
                exc,
            )
    return result


def _compare_and_alert(
    baseline: Dict[str, str],
    current: Dict[str, str],
    integrity_cfg: Dict,
    violation_counter: "_ViolationCounterShim",
) -> None:
    """Compare *current* hashes against *baseline* and emit alerts."""
    for path, digest in current.items():
        baseline_digest = baseline.get(path)
        if baseline_digest is None:
            # New file — update baseline silently
            baseline[path] = digest
            logger.info(
                "integrity | event=new_file_detected | path=%s", path
            )
        elif baseline_digest != digest:
            violation_counter.inc()  # unlabelled total
            _INTEGRITY_VIOLATIONS_BY_PATH.labels(path=path).inc()
            logger.error(
                "integrity | event=file_tampered | path=%s | "
                "expected=%s | got=%s",
                path,
                baseline_digest,
                digest,
            )
            if integrity_cfg.get("shutdown_on_violation", False):
                logger.critical(
                    "integrity | event=shutdown_on_violation | path=%s", path
                )
                import sys
                sys.exit(1)

    # Report deleted files — and remove from baseline so we don't alert every cycle
    for path in list(baseline.keys()):
        if path not in current:
            violation_counter.inc()  # unlabelled total
            _INTEGRITY_VIOLATIONS_BY_PATH.labels(path=path).inc()
            logger.error(
                "integrity | event=file_deleted | path=%s", path
            )
            del baseline[path]  # stop alerting on every subsequent scan cycle


def _read_last_line_hash(log_path: str) -> str:
    """Return the SHA-256 hex of the last line (without trailing newline) in
    *log_path*, or ``""`` if the file is empty or does not exist.

    The hash is computed over the UTF-8 encoding of the line text without the
    trailing ``\\n`` — consistent with the test contract:
    ``hashlib.sha256(line.encode()).hexdigest()``.
    """
    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()  # strips trailing \n from each line
        if not lines:
            return ""
        last_line = lines[-1]
        return hashlib.sha256(last_line.encode("utf-8")).hexdigest()
    except FileNotFoundError:
        return ""
    except Exception as exc:
        logger.warning(
            "integrity | event=prev_hash_read_error | path=%s | error=%s",
            log_path,
            exc,
        )
        return ""


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
