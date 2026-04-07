"""Offline policy YAML validation for JA4proxy.

All validation runs entirely without network access or a running API.

Exported symbols
----------------
PolicySyntaxError     -- YAML not parseable
PolicySchemaError     -- unknown field / bad format (CIDR, JA4 regex)
PolicyTTLError        -- ``expires`` value is in the past
PolicyDuplicateError  -- duplicate JA4 fingerprints in the same list
PolicyValidationError -- dial increase rule (> 20 points without approval flag)

validate_policy(yaml_text, current_dial=0) -> dict
    Parse and validate policy YAML.  Returns the parsed dict on success.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

import cerberus
import yaml

from src.governance.policy_schema import POLICY_SCHEMA, _JA4_PATTERN

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class PolicySyntaxError(ValueError):
    """YAML is not parseable."""


class PolicySchemaError(ValueError):
    """Structure is invalid — unknown fields, bad formats, etc."""


class PolicyTTLError(ValueError):
    """An ``expires`` field is in the past."""


class PolicyDuplicateError(ValueError):
    """Duplicate JA4 fingerprints exist within the same list."""


class PolicyValidationError(ValueError):
    """Dial increase rule violated (> 20 points without shadow_mode_approved: true)."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_JA4_RE = re.compile(_JA4_PATTERN)


def _check_cidr(cidr: str, context: str) -> None:
    """Raise ``PolicySchemaError`` if *cidr* is not a valid CIDR notation.

    Args:
        cidr: The CIDR string to validate.
        context: Human-readable location string for the error message.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise PolicySchemaError(
            f"Invalid CIDR in {context}: {cidr!r} — {exc}"
        ) from exc


def _check_ja4(fingerprint: str, context: str) -> None:
    """Raise ``PolicySchemaError`` if *fingerprint* does not match the JA4 pattern.

    Args:
        fingerprint: The JA4 string to validate.
        context: Human-readable location string for the error message.
    """
    if not _JA4_RE.match(fingerprint):
        raise PolicySchemaError(
            f"Invalid JA4 fingerprint in {context}: {fingerprint!r} — "
            f"must match {_JA4_PATTERN}"
        )


def _parse_expires(value: str, context: str) -> datetime:
    """Return a timezone-aware datetime for *value*.

    Raises:
        PolicySchemaError: if the value cannot be parsed as ISO 8601.
    """
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicySchemaError(
            f"Cannot parse expires field in {context}: {value!r} — {exc}"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _check_expires(entries: list[dict], list_name: str) -> None:
    """Check all ``expires`` fields in *entries* are not in the past.

    Args:
        entries: List of policy entry dicts that may contain an ``expires`` key.
        list_name: Human-readable name for error messages.

    Raises:
        PolicyTTLError: if any entry has an expired ``expires`` value.
    """
    now = datetime.now(timezone.utc)
    for entry in entries:
        expires_raw = entry.get("expires")
        if not expires_raw:
            continue
        dt = _parse_expires(expires_raw, list_name)
        if dt <= now:
            identifier = entry.get("ja4") or entry.get("cidr") or entry.get("ip") or "?"
            raise PolicyTTLError(
                f"Expired entry in {list_name}: {identifier!r} expired at {expires_raw}"
            )


def _check_duplicates_ja4(entries: list[dict], list_name: str) -> None:
    """Raise ``PolicyDuplicateError`` if any JA4 fingerprint appears more than once.

    Args:
        entries: List of fingerprint entry dicts with a ``ja4`` key.
        list_name: Human-readable name for error messages.
    """
    seen: set[str] = set()
    for entry in entries:
        ja4 = entry.get("ja4", "")
        if ja4 in seen:
            raise PolicyDuplicateError(
                f"Duplicate JA4 fingerprint in {list_name}: {ja4!r}"
            )
        seen.add(ja4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_policy(yaml_text: str, current_dial: int = 0) -> dict:
    """Parse and validate policy YAML.

    Performs seven sequential checks:

    1. YAML parse — ``PolicySyntaxError`` on failure.
    2. Cerberus structural validation — ``PolicySchemaError`` on failure.
    3. CIDR field validation via ``ipaddress.ip_network()`` — ``PolicySchemaError``.
    4. JA4 regex validation — ``PolicySchemaError``.
    5. ``expires`` in the past — ``PolicyTTLError``.
    6. Duplicate JA4 fingerprints in the same list — ``PolicyDuplicateError``.
    7. Dial increase > 20 without ``shadow_mode_approved: true`` — ``PolicyValidationError``.

    Args:
        yaml_text: Raw YAML string to validate.
        current_dial: The current dial setting (default 0).  Used to detect
            an increase of more than 20 points.

    Returns:
        The parsed policy dict if all checks pass.

    Raises:
        PolicySyntaxError: if the YAML is not parseable.
        PolicySchemaError: if structure is invalid.
        PolicyTTLError: if any ``expires`` field is in the past.
        PolicyDuplicateError: if duplicate JA4 fingerprints exist in the same list.
        PolicyValidationError: if the dial increases by more than 20 without approval.
    """
    # ── 1. YAML parse ────────────────────────────────────────────────────────
    try:
        policy: Any = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise PolicySyntaxError(f"YAML parse error: {exc}") from exc

    if policy is None:
        policy = {}

    if not isinstance(policy, dict):
        raise PolicySyntaxError("Policy YAML must be a mapping at the top level")

    # ── 2. Cerberus structural validation ────────────────────────────────────
    validator = cerberus.Validator(POLICY_SCHEMA, allow_unknown=False)
    if not validator.validate(policy):
        raise PolicySchemaError(f"Policy schema validation failed: {validator.errors}")

    # ── 3. CIDR validation ───────────────────────────────────────────────────
    allowlist = policy.get("allowlist") or {}
    for ip_entry in allowlist.get("ips") or []:
        _check_cidr(ip_entry["cidr"], "allowlist.ips")

    blocklist = policy.get("blocklist") or {}
    for ip_entry in blocklist.get("ips") or []:
        _check_cidr(ip_entry["cidr"], "blocklist.ips")

    watchlist = policy.get("watchlist") or {}
    for ip_entry in watchlist.get("ips") or []:
        _check_cidr(ip_entry["ip"], "watchlist.ips")

    # ── 4. JA4 regex validation ──────────────────────────────────────────────
    # (Cerberus already applies the regex rule, but we run an explicit check
    # so that the error class is PolicySchemaError with a clear message.)
    for fp in allowlist.get("fingerprints") or []:
        _check_ja4(fp["ja4"], "allowlist.fingerprints")

    for fp in blocklist.get("fingerprints") or []:
        _check_ja4(fp["ja4"], "blocklist.fingerprints")

    # ── 5. expires in the past ───────────────────────────────────────────────
    _check_expires(allowlist.get("fingerprints") or [], "allowlist.fingerprints")
    _check_expires(allowlist.get("ips") or [], "allowlist.ips")
    _check_expires(blocklist.get("fingerprints") or [], "blocklist.fingerprints")
    _check_expires(blocklist.get("ips") or [], "blocklist.ips")
    _check_expires(watchlist.get("ips") or [], "watchlist.ips")

    # ── 6. Duplicate JA4 fingerprints ───────────────────────────────────────
    _check_duplicates_ja4(
        allowlist.get("fingerprints") or [], "allowlist.fingerprints"
    )
    _check_duplicates_ja4(
        blocklist.get("fingerprints") or [], "blocklist.fingerprints"
    )

    # ── 7. Dial increase > 20 without approval ───────────────────────────────
    dial = policy.get("dial") or {}
    new_dial: int | None = dial.get("setting")
    if new_dial is not None:
        increase = new_dial - current_dial
        shadow_approved: bool = dial.get("shadow_mode_approved", False) is True
        if increase > 20 and not shadow_approved:
            raise PolicyValidationError(
                f"Dial increase of {increase} points (from {current_dial} to "
                f"{new_dial}) requires shadow_mode_approved: true in the dial "
                f"section"
            )

    return policy
