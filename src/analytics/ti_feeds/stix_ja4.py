"""STIX 2.1 ``x-ja4-fingerprint`` extension helpers — hand-rolled parsers.

See PHASE_85.md §4 for the extension design and the rationale for keeping
``pattern_type: "stix"`` with a custom SCO rather than inventing a new
``pattern_type``.

The parse helpers are deliberately small:

* :func:`is_ja4_pattern` — True if a STIX pattern string references the
  ``x-ja4-fingerprint`` SCO.
* :func:`is_ip_pattern` — True if a STIX pattern references ``ipv4-addr`` or
  ``ipv6-addr`` value.
* :func:`parse_ja4_from_pattern` — Extracts the raw JA4 string.
* :func:`parse_ip_from_pattern` — Extracts the raw IP string.
* :func:`validate_ja4` — Returns True if the string looks like a JA4.

We intentionally accept only the narrow patterns the Phase 20 publisher emits
(``[x-ja4-fingerprint:value = '...']`` and ``[ipv4-addr:value = '...']``)
because round-tripping with our own publisher is the primary goal. Variants
with logical operators (``AND``, ``OR``, ``FOLLOWED BY``) are outside the
Phase 85 scope; they are logged and counted under ``unsupported_pattern``.
"""

from __future__ import annotations

import re
from typing import Optional

#: Permanent UUID for the ``x-ja4-fingerprint`` SCO extension definition.
#: See PHASE_85.md §4.1. Must not change post-publication.
JA4_SCO_EXTENSION_ID = "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e"

#: The STIX Cyber Observable Object ``type`` value used by this extension.
JA4_SCO_TYPE = "x-ja4-fingerprint"

# ── regexes ───────────────────────────────────────────────────────────────────

#: JA4 TLS ClientHello fingerprint. Format:
#: ``t{major}{minor}{alpn2}{cipher_count}_{cipher_hash}_{ext_hash}``.
#: Cipher and extension hashes are 12-character SHA-256 prefixes.
#: Example: ``t13d1516h2_8daaf6152771_b0da82dd1658``
JA4_REGEX = re.compile(
    r"""
    ^
    t                # literal 't' prefix
    \d{2}            # TLS version (e.g. 13 for TLS 1.3)
    [dq]             # 'd' for TCP, 'q' for QUIC (character class, not alternation)
    \d{4}            # cipher count + extension count + ALPN
    (?:h2|h1|00|[a-z0-9]{2})?  # ALPN (optional)
    _
    [0-9a-f]{12}     # cipher hash
    _
    [0-9a-f]{12}     # extension hash
    $
    """,
    re.VERBOSE,
)

# Permissive JA4 regex — matches anything starting with 't' followed by digits
# and two 12-char hex blocks separated by underscores. Used by the pattern
# extractor so we don't miss vendor-specific variants; validation is stricter
# via :func:`validate_ja4`.
_JA4_EXTRACT_REGEX = re.compile(r"^t[0-9a-z]{6,10}_[0-9a-f]{12}_[0-9a-f]{12}$")

#: ``[x-ja4-fingerprint:value = '...']`` — the only JA4 pattern we accept.
JA4_PATTERN_REGEX = re.compile(
    r"\[x-ja4-fingerprint:value\s*=\s*'([^']+)'\]",
    re.IGNORECASE,
)

#: ``[ipv4-addr:value = '...']`` or ``[ipv6-addr:value = '...']``.
IP_PATTERN_REGEX = re.compile(
    r"\[ipv[46]-addr:value\s*=\s*'([^']+)'\]",
    re.IGNORECASE,
)


def is_valid_ja4(candidate: str) -> bool:
    """Return True if ``candidate`` looks like a valid JA4 fingerprint.

    Bool variant for hot-path callers. See :func:`validate_ja4` for the
    raising variant used by config and seed-file loaders.
    """
    if not candidate or not isinstance(candidate, str):
        return False
    if len(candidate) > 128:
        return False
    if any(c in candidate for c in (" ", "\t", "\n", "\0", "`")):
        return False
    return bool(_JA4_EXTRACT_REGEX.match(candidate))


def validate_ja4(candidate: str) -> None:
    """Raise ``ValueError`` if ``candidate`` is not a syntactically valid JA4.

    Used by seed-file and config loaders where a malformed JA4 must abort
    parsing rather than be silently dropped. Hot-path callers should use
    :func:`is_valid_ja4` instead.
    """
    if not is_valid_ja4(candidate):
        raise ValueError(f"invalid JA4 fingerprint: {candidate!r}")


# ── parser aliases (test-facing names) ────────────────────────────────────────


def parse_ja4_pattern(pattern: Optional[str]) -> Optional[str]:
    """Alias of :func:`parse_ja4_from_pattern` (test-facing name)."""
    return parse_ja4_from_pattern(pattern)


def parse_ip_pattern(pattern: Optional[str]) -> Optional[str]:
    """Alias of :func:`parse_ip_from_pattern` (test-facing name)."""
    return parse_ip_from_pattern(pattern)


def parse_new_sco(sco: dict) -> dict:
    """Return the metadata fields from an ``x-ja4-fingerprint`` SCO.

    Reads the ``new-sco`` extension block at
    :data:`JA4_SCO_EXTENSION_ID` and surfaces ``value``, ``likely_category``,
    ``likely_tool``, ``ja4x``, and ``source`` as a flat dict.
    """
    ext = (sco.get("extensions") or {}).get(JA4_SCO_EXTENSION_ID, {})
    return {
        "value": sco.get("value"),
        "likely_category": ext.get("likely_category"),
        "likely_tool": ext.get("likely_tool"),
        "ja4x": ext.get("ja4x"),
        "source": ext.get("source"),
    }


def is_supported_indicator(indicator: dict) -> bool:
    """Return True if the indicator is one we know how to apply.

    Per PHASE_85.md §4: ``pattern_type`` MUST be the literal STIX value
    ``"stix"`` — feeds inventing a custom ``"x-ja4-fingerprint"``
    pattern_type are rejected.
    """
    if indicator.get("pattern_type") != "stix":
        return False
    pattern = indicator.get("pattern")
    return is_ja4_pattern(pattern) or is_ip_pattern(pattern)


def is_ja4_pattern(pattern: Optional[str]) -> bool:
    """Return True if ``pattern`` references the ``x-ja4-fingerprint`` SCO."""
    if not pattern:
        return False
    return bool(JA4_PATTERN_REGEX.search(pattern))


def is_ip_pattern(pattern: Optional[str]) -> bool:
    """Return True if ``pattern`` references an ``ipv4-addr`` or ``ipv6-addr``."""
    if not pattern:
        return False
    return bool(IP_PATTERN_REGEX.search(pattern))


def parse_ja4_from_pattern(pattern: Optional[str]) -> Optional[str]:
    """Return the JA4 string inside the pattern, or None if extraction fails.

    The caller is responsible for passing the returned value through
    :func:`validate_ja4` before using it.
    """
    if not pattern:
        return None
    match = JA4_PATTERN_REGEX.search(pattern)
    if match is None:
        return None
    return match.group(1)


def parse_ip_from_pattern(pattern: Optional[str]) -> Optional[str]:
    """Return the IP string inside the pattern, or None if extraction fails.

    IPv6 addresses retain their canonical string form. The caller should use
    ``ipaddress.ip_address(...)`` for validation before calling the bans
    endpoint so malformed IPs do not reach the Management API.
    """
    if not pattern:
        return None
    match = IP_PATTERN_REGEX.search(pattern)
    if match is None:
        return None
    return match.group(1)


# ── SCO / extension-object helpers ───────────────────────────────────────────


def sco_object_for_ja4(
    ja4_value: str,
    *,
    likely_category: Optional[str] = None,
    likely_tool: Optional[str] = None,
    ja4x: Optional[str] = None,
    source: str = "ja4proxy-community-feed",
) -> dict[str, object]:
    """Return a STIX 2.1 ``x-ja4-fingerprint`` SCO dict for ``ja4_value``.

    Emitted by the Phase 20 publisher (mirrored here so the consumer can
    round-trip its own format) — and by test fixtures the sibling test
    agent needs.
    """
    return {
        "type": JA4_SCO_TYPE,
        "spec_version": "2.1",
        "value": ja4_value,
        "extensions": {
            JA4_SCO_EXTENSION_ID: {
                "extension_type": "new-sco",
                "likely_category": likely_category,
                "likely_tool": likely_tool,
                "ja4x": ja4x,
                "source": source,
            }
        },
    }


def indicator_object_for_ja4(
    indicator_id: str,
    ja4_value: str,
    *,
    name: str,
    confidence: int,
    valid_from: str,
    valid_until: Optional[str] = None,
) -> dict[str, object]:
    """Return a STIX 2.1 ``indicator`` SDO pointing at an ``x-ja4-fingerprint``."""
    obj: dict[str, object] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "name": name,
        "pattern_type": "stix",
        "pattern": f"[x-ja4-fingerprint:value = '{ja4_value}']",
        "indicator_types": ["malicious-activity"],
        "confidence": confidence,
        "valid_from": valid_from,
    }
    if valid_until:
        obj["valid_until"] = valid_until
    return obj
