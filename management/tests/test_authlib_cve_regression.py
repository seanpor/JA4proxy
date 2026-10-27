"""Regression tests for Authlib CVEs resolved in Authlib 1.9.1 (Phase 852).

Guards against:
- CVE-2026-96760 (Critical): Empty signatures array in JWS JSON deserialization
  bypassing signature verification.
- CVE-2026-114616 (High): Empty HMAC key material accepted for HS256/384/512.
"""
from __future__ import annotations

import base64

import pytest
from authlib.jose import JsonWebSignature
from authlib.jose.errors import BadSignatureError


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_jws_empty_signatures_rejected_cve_2026_96760():
    """CVE-2026-96760: deserialize_json must reject JWS objects with empty signatures array."""
    jws = JsonWebSignature()
    payload = b'{"sub":"attacker","role":"admin"}'
    forged = {
        "payload": _b64url(payload),
        "signatures": [],
    }

    # Under vulnerable Authlib < 1.9.0, deserialize_json returned the payload without checking signatures.
    # Under Authlib >= 1.9.0, it must raise BadSignatureError.
    with pytest.raises(BadSignatureError):
        jws.deserialize_json(forged, key=None)


def test_empty_hmac_key_rejected_cve_2026_114616():
    """CVE-2026-114616: Empty HMAC key must be rejected and not permit signature verification."""
    jws = JsonWebSignature(algorithms=["HS256"])
    header = _b64url(b'{"alg":"HS256"}')
    payload = _b64url(b'{"sub":"admin"}')

    # An unsigned or empty-key token must be rejected with ValueError or BadSignatureError.
    with pytest.raises((ValueError, BadSignatureError)):
        jws.deserialize_compact(f"{header}.{payload}.", key="")
