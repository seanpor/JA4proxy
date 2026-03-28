"""
Fingerprint extraction functions for TAP mode (Phase 20, Group 5).

Each module exposes one or more pure functions that accept raw bytes and return
typed dataclasses (or None on malformed / incomplete input).  No I/O, no async.
"""

from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.h2_fingerprint import (
    H2FingerprintResult,
    H2Signature,
    extract_h2_fingerprint,
)
from src.tap.fingerprints.ja4 import JA4Result, extract_ja4
from src.tap.fingerprints.ja4h import JA4HResult, extract_ja4h
from src.tap.fingerprints.ja4l import JA4LResult, extract_ja4l
from src.tap.fingerprints.ja4s import JA4SResult, extract_ja4s
from src.tap.fingerprints.ja4ssh import JA4SSHResult, extract_ja4ssh
from src.tap.fingerprints.ja4t import JA4TResult, extract_ja4t_from_syn
from src.tap.fingerprints.ja4x import JA4XResult, extract_ja4x
from src.tap.fingerprints.os_fingerprint import (
    OSFingerprintResult,
    OSSignature,
    load_os_database,
    match_os,
)
from src.tap.fingerprints.quic_fingerprint import (
    QUICFingerprintResult,
    extract_quic_fingerprint,
)
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues, extract_tls_ext_values

__all__ = [
    "JA4Result",
    "extract_ja4",
    "JA4SResult",
    "extract_ja4s",
    "JA4TResult",
    "extract_ja4t_from_syn",
    "JA4HResult",
    "extract_ja4h",
    "JA4LResult",
    "extract_ja4l",
    "JA4XResult",
    "extract_ja4x",
    "JA4SSHResult",
    "extract_ja4ssh",
    "JA4TLSExtValues",
    "extract_tls_ext_values",
    "OSFingerprintResult",
    "OSSignature",
    "load_os_database",
    "match_os",
    "H2FingerprintResult",
    "H2Signature",
    "extract_h2_fingerprint",
    "QUICFingerprintResult",
    "extract_quic_fingerprint",
    "ConnectionFingerprints",
]
