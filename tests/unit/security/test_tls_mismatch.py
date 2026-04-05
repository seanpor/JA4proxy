"""Unit tests for check_ja4_tls_mismatch() in src/security/tls_enforcer.py.

The function detects when the TLS version claimed in the JA4 fingerprint prefix
(t13, t12, t10) differs from the version actually negotiated.  A mismatch is a
strong indicator of a spoofed or manipulated ClientHello.

JA4 version prefix mapping:
  t13 → TLS 1.3  ("TLSv1.3")
  t12 → TLS 1.2  ("TLSv1.2")
  t10 → TLS 1.0 or TLS 1.1  ("TLSv1", "TLSv1.1")

Expected behaviour:
  - Match  → returns None
  - Mismatch → returns RiskSignal(name="ja4_tls_mismatch", score=35)
  - Malformed / unknown input → returns None (fail open)
"""

import pytest

from src.security.tls_enforcer import check_ja4_tls_mismatch
from src.security.models import RiskSignal


# ---------------------------------------------------------------------------
# Matching cases — no mismatch, must return None
# ---------------------------------------------------------------------------


class TestNoMismatch:
    def test_t13_with_tlsv1_3(self):
        """JA4 prefix t13 with negotiated TLSv1.3 → no mismatch → None."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "TLSv1.3")
        assert result is None

    def test_t12_with_tlsv1_2(self):
        """JA4 prefix t12 with negotiated TLSv1.2 → no mismatch → None."""
        result = check_ja4_tls_mismatch("t12d040500_6826bf00caa0_8373daf1dfd8", "TLSv1.2")
        assert result is None

    def test_t10_with_tlsv1(self):
        """JA4 prefix t10 with negotiated TLSv1 → no mismatch → None."""
        result = check_ja4_tls_mismatch("t10d020100_aabbccddee11_112233445566", "TLSv1")
        assert result is None

    def test_t10_with_tlsv1_1(self):
        """JA4 prefix t10 covers TLS 1.0 and 1.1; TLSv1.1 should not be a mismatch."""
        result = check_ja4_tls_mismatch("t10d020100_aabbccddee11_112233445566", "TLSv1.1")
        assert result is None


# ---------------------------------------------------------------------------
# Mismatch cases — must return RiskSignal with correct fields
# ---------------------------------------------------------------------------


class TestMismatch:
    def test_t13_with_tlsv1_2_is_mismatch(self):
        """JA4 claims TLS 1.3 but connection used TLS 1.2 → mismatch signal."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "TLSv1.2")
        assert result is not None
        assert isinstance(result, RiskSignal)
        assert result.name == "ja4_tls_mismatch"
        assert result.score == 35

    def test_t12_with_tlsv1_3_is_mismatch(self):
        """JA4 claims TLS 1.2 but connection used TLS 1.3 → mismatch signal."""
        result = check_ja4_tls_mismatch("t12d040500_6826bf00caa0_8373daf1dfd8", "TLSv1.3")
        assert result is not None
        assert result.name == "ja4_tls_mismatch"
        assert result.score == 35

    def test_t10_with_tlsv1_3_is_mismatch(self):
        """JA4 claims TLS 1.0/1.1 but connection used TLS 1.3 → mismatch signal."""
        result = check_ja4_tls_mismatch("t10d020100_aabbccddee11_112233445566", "TLSv1.3")
        assert result is not None
        assert result.name == "ja4_tls_mismatch"
        assert result.score == 35

    def test_t10_with_tlsv1_2_is_mismatch(self):
        """JA4 claims TLS 1.0/1.1 but connection used TLS 1.2 → mismatch signal."""
        result = check_ja4_tls_mismatch("t10d020100_aabbccddee11_112233445566", "TLSv1.2")
        assert result is not None
        assert result.name == "ja4_tls_mismatch"
        assert result.score == 35

    def test_t13_with_tlsv1_is_mismatch(self):
        """JA4 claims TLS 1.3 but connection used legacy TLSv1 → mismatch signal."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "TLSv1")
        assert result is not None
        assert result.name == "ja4_tls_mismatch"
        assert result.score == 35

    def test_mismatch_signal_has_reason(self):
        """Mismatch RiskSignal must include a human-readable reason string."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "TLSv1.2")
        assert result is not None
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0


# ---------------------------------------------------------------------------
# Fail-open cases — malformed or unknown input, must return None
# ---------------------------------------------------------------------------


class TestFailOpen:
    def test_empty_ja4_returns_none(self):
        """Empty JA4 string → fail open → None."""
        result = check_ja4_tls_mismatch("", "TLSv1.3")
        assert result is None

    def test_none_ja4_returns_none(self):
        """None JA4 → fail open → None."""
        result = check_ja4_tls_mismatch(None, "TLSv1.3")  # type: ignore[arg-type]
        assert result is None

    def test_garbage_ja4_returns_none(self):
        """JA4 with unrecognised prefix (xyz) → fail open → None."""
        result = check_ja4_tls_mismatch("xyz_garbage_fingerprint", "TLSv1.3")
        assert result is None

    def test_unknown_tls_version_string_returns_none(self):
        """Unrecognised TLS version string → fail open → None (no mismatch emitted)."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "SSLv2")
        assert result is None

    def test_none_tls_version_returns_none(self):
        """None TLS version → fail open → None."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", None)  # type: ignore[arg-type]
        assert result is None

    def test_empty_tls_version_returns_none(self):
        """Empty TLS version string → fail open → None."""
        result = check_ja4_tls_mismatch("t13d030500_55b375c5d22e_a80244f201c9", "")
        assert result is None

    def test_ja4_too_short_returns_none(self):
        """JA4 shorter than 3 characters → fail open → None."""
        result = check_ja4_tls_mismatch("t1", "TLSv1.3")
        assert result is None
