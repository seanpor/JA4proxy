"""
TLS Extension Value Fingerprint (Phase 20, Group 5-H).

Derives rich TLS extension detail from an already-parsed JA4Result.
No additional byte parsing required.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.tap.fingerprints.ja4 import JA4Result

_EXT_ALPS = 0x4469  # Application-Layer Protocol Settings (ALPS, Chrome)
_EXT_COMPRESS_CERT = 27  # RFC 8879
_EXT_PADDING = 21
_EXT_SESSION_TICKET = 35


@dataclass
class JA4TLSExtValues:
    """Rich TLS extension values derived from JA4Result."""

    supported_groups: list[int]
    key_share_groups: list[int]
    sig_algs: list[int]
    psk_modes: list[int]
    grease_values: list[int]
    has_compress_cert: bool
    has_alps: bool
    padding_len: Optional[int]
    session_ticket_len: int


def extract_tls_ext_values(ja4_result: JA4Result) -> JA4TLSExtValues:
    """Extract rich TLS extension values from an already-parsed JA4Result.

    Args:
        ja4_result: A JA4Result obtained from ``extract_ja4()``.

    Returns:
        JA4TLSExtValues (always; never raises).
    """
    try:
        has_alps = _EXT_ALPS in ja4_result.extensions
        has_compress_cert = ja4_result.compress_cert_present or (
            _EXT_COMPRESS_CERT in ja4_result.extensions
        )

        return JA4TLSExtValues(
            supported_groups=list(ja4_result.supported_groups),
            key_share_groups=list(ja4_result.key_share_groups),
            sig_algs=list(ja4_result.signature_algorithms),
            psk_modes=list(ja4_result.psk_modes),
            grease_values=list(ja4_result.grease_values),
            has_compress_cert=has_compress_cert,
            has_alps=has_alps,
            padding_len=ja4_result.padding_ext_len,
            session_ticket_len=ja4_result.session_ticket_len,
        )
    except Exception:
        return JA4TLSExtValues(
            supported_groups=[],
            key_share_groups=[],
            sig_algs=[],
            psk_modes=[],
            grease_values=[],
            has_compress_cert=False,
            has_alps=False,
            padding_len=None,
            session_ticket_len=0,
        )
