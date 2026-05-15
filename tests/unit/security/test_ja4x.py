"""
tests/unit/security/test_ja4x.py
Phase 16g — JA4X Extended Fingerprinting tests.

Covers:
- JA4X hash computation with known cert inputs
- Missing cert → sentinel value (000000000000_...)
- ja4x field in ConnectionContext default (None)
- JA4X whitelist bypass in pipeline
- JA4X blacklist risk signal in pipeline
- ja4x disabled → ctx.ja4x = None; no signal emitted
- _extract_ja4x_from_cert with real DER-encoded certificate
"""

import asyncio
import hashlib
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.security.models import ConnectionContext, PipelineResult
from src.security.pipeline import Pipeline

# ---------------------------------------------------------------------------
# JA4X hash computation helpers
# ---------------------------------------------------------------------------


def _compute_ja4x_hash(data: str) -> str:
    """SHA-256 truncated to 12 hex chars. Empty → sentinel."""
    if not data:
        return "000000000000"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(extra_config: dict | None = None) -> Pipeline:
    """Create a minimal Pipeline for unit testing."""
    config: dict = {
        "security_policy": {},
        "static_allowlist": {"ips": []},
        "fingerprinting": {
            "ja4x": {
                "enabled": True,
                "blacklist_score": 80,
                "emit_in_logs": True,
            }
        },
    }
    if extra_config:
        config.update(extra_config)

    cache = MagicMock()
    cache.dial = 0
    cache.analytics_signals = MagicMock()
    cache.analytics_signals.get.return_value = None

    pipeline = Pipeline(config, cache, MagicMock())
    # Wire scorer/decider so signals produce actions
    scorer = MagicMock()
    scorer.score = MagicMock(
        side_effect=lambda sigs: MagicMock(
            total_score=sum(getattr(s, "score", 0) for s in sigs),
            signals=sigs,
        )
    )
    decider = MagicMock()
    decider.decide = MagicMock(
        side_effect=lambda score, dial: "block" if score >= 70 else "allow"
    )
    decider.counterfactuals = MagicMock(return_value={})
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _make_ctx(**kwargs) -> ConnectionContext:
    defaults = {
        "client_ip": "1.2.3.4",
        "ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff",
        "alpn": None,
    }
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


# ---------------------------------------------------------------------------
# Test: ConnectionContext ja4x field
# ---------------------------------------------------------------------------


class TestConnectionContextJA4X(unittest.TestCase):
    """ConnectionContext default and field behaviour."""

    def test_ja4x_defaults_to_none(self):
        """ctx.ja4x is None by default."""
        ctx = ConnectionContext(client_ip="1.2.3.4")
        self.assertIsNone(ctx.ja4x)

    def test_ja4x_can_be_set(self):
        """ctx.ja4x accepts a string value."""
        fingerprint = "aabbccddeeff_112233445566_aabbcc112233"
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4x=fingerprint)
        self.assertEqual(ctx.ja4x, fingerprint)


# ---------------------------------------------------------------------------
# Test: _extract_ja4x_from_cert
# ---------------------------------------------------------------------------


class TestExtractJA4XFromCert(unittest.TestCase):
    """Pipeline._extract_ja4x_from_cert edge cases."""

    def setUp(self):
        self.pipeline = _make_pipeline()

    def test_invalid_der_returns_none(self):
        """Garbage bytes → None (fail open, logged as WARNING)."""
        result = self.pipeline._extract_ja4x_from_cert(b"\x00\x01\x02\x03")
        self.assertIsNone(result)

    def test_empty_bytes_returns_none(self):
        """Empty bytes → None."""
        result = self.pipeline._extract_ja4x_from_cert(b"")
        self.assertIsNone(result)

    def test_real_der_cert_returns_three_part_hash(self):
        """Self-signed DER cert → three-part hash string."""
        # Generate a minimal self-signed cert using cryptography
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            cert_der = cert.public_bytes(serialization.Encoding.DER)

            result = self.pipeline._extract_ja4x_from_cert(cert_der)
            self.assertIsNotNone(result)
            parts = result.split("_")
            self.assertEqual(len(parts), 3)
            for part in parts:
                self.assertEqual(len(part), 12)
                # Must be hex
                int(part, 16)
        except ImportError:
            self.skipTest("cryptography not available")

    def test_cert_without_san_uses_empty_san(self):
        """Cert without SAN extension → san_hash is empty-string hash (000000000000)."""
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "nosantest"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .sign(key, hashes.SHA256())
            )
            cert_der = cert.public_bytes(serialization.Encoding.DER)

            result = self.pipeline._extract_ja4x_from_cert(cert_der)
            self.assertIsNotNone(result)
            # Third part (san_hash) should be sentinel since no SAN
            san_hash = result.split("_")[2]
            self.assertEqual(san_hash, "000000000000")
        except ImportError:
            self.skipTest("cryptography not available")

    def test_extract_logs_warning_on_failure(self):
        """Parse error is logged at WARNING, not raised."""
        with self.assertLogs("src.security.pipeline", level="WARNING") as cm:
            result = self.pipeline._extract_ja4x_from_cert(b"not a cert")
        self.assertIsNone(result)
        self.assertTrue(any("ja4x_extract_failed" in line for line in cm.output))


# ---------------------------------------------------------------------------
# Test: JA4X hash computation (same logic as generate_ja4x in proxy.py)
# ---------------------------------------------------------------------------


class TestJA4XHashComputation(unittest.TestCase):
    """JA4X hash properties and known-value assertions."""

    def test_empty_fields_produce_sentinel(self):
        """Empty issuer/subject/san → all-zeros sentinel."""
        for field in ("", None):
            value = field or ""
            h = _compute_ja4x_hash(value)
            self.assertEqual(h, "000000000000")

    def test_known_input_produces_known_hash(self):
        """Known input → deterministic 12-char hex hash."""
        issuer = "2.5.4.6=US,2.5.4.10=Example Corp,2.5.4.3=Root CA"
        expected = hashlib.sha256(issuer.encode("utf-8")).hexdigest()[:12]
        self.assertEqual(_compute_ja4x_hash(issuer), expected)
        self.assertEqual(len(expected), 12)

    def test_hash_is_hex(self):
        """Hash output is valid hex characters only."""
        h = _compute_ja4x_hash("some.issuer.string=value")
        int(h, 16)  # Raises ValueError if not valid hex

    def test_different_inputs_produce_different_hashes(self):
        """Different field values produce different hashes (collision resistance)."""
        h1 = _compute_ja4x_hash("issuer_a")
        h2 = _compute_ja4x_hash("issuer_b")
        self.assertNotEqual(h1, h2)

    def test_format_is_three_parts(self):
        """JA4X format is always {12hex}_{12hex}_{12hex}."""
        issuer_hash = _compute_ja4x_hash("issuer")
        subject_hash = _compute_ja4x_hash("subject")
        san_hash = _compute_ja4x_hash("san")
        ja4x = f"{issuer_hash}_{subject_hash}_{san_hash}"
        parts = ja4x.split("_")
        self.assertEqual(len(parts), 3)
        for part in parts:
            self.assertEqual(len(part), 12)


# ---------------------------------------------------------------------------
# Test: JA4X pipeline integration
# ---------------------------------------------------------------------------


class TestJA4XWhitelistBypass(unittest.TestCase):
    """JA4X whitelist → ALLOW bypass."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_ctx_in_ja4x_whitelist_is_allowed(self):
        """ctx.ja4x matching the JA4X whitelist returns ALLOW bypass."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(
            whitelist={"aabbccddeeff_112233445566_aabbcc112233"},
            blacklist=set(),
        )
        ctx = _make_ctx(ja4x="aabbccddeeff_112233445566_aabbcc112233")
        result = self._run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")
        self.assertTrue(result.bypassed)
        self.assertEqual(result.bypass_reason, "ja4x_whitelist")

    def test_ctx_not_in_whitelist_falls_through(self):
        """ctx.ja4x not in whitelist → falls through to scoring."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(whitelist={"other_fingerprint"}, blacklist=set())
        ctx = _make_ctx(ja4x="aabbccddeeff_112233445566_aabbcc112233")
        result = self._run(pipeline.process(ctx))
        # Not bypassed — falls through to allow (score=0)
        self.assertFalse(result.bypassed)

    def test_ja4x_none_skips_whitelist_check(self):
        """ctx.ja4x = None → whitelist check skipped; no bypass."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(whitelist={"anything"}, blacklist=set())
        ctx = _make_ctx(ja4x=None)
        result = self._run(pipeline.process(ctx))
        self.assertFalse(result.bypassed)

    def test_ja4x_disabled_skips_whitelist(self):
        """fingerprinting.ja4x.enabled=false → whitelist check skipped."""
        config = {
            "fingerprinting": {
                "ja4x": {"enabled": False, "blacklist_score": 80, "emit_in_logs": False}
            }
        }
        pipeline = _make_pipeline(config)
        pipeline.update_ja4x_sets(
            whitelist={"aabbccddeeff_112233445566_aabbcc112233"},
            blacklist=set(),
        )
        ctx = _make_ctx(ja4x="aabbccddeeff_112233445566_aabbcc112233")
        result = self._run(pipeline.process(ctx))
        # Disabled → whitelist not checked; no bypass
        self.assertFalse(result.bypassed)


class TestJA4XBlacklistSignal(unittest.TestCase):
    """JA4X blacklist → RiskSignal added to scoring."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_ctx_in_ja4x_blacklist_produces_risk_signal(self):
        """ctx.ja4x matching blacklist adds RiskSignal(score=80)."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(
            whitelist=set(),
            blacklist={"aabbccddeeff_112233445566_aabbcc112233"},
        )
        ctx = _make_ctx(
            ja4x="aabbccddeeff_112233445566_aabbcc112233",
            alpn="other",  # not h2/h1 so not bypassed
        )
        result = self._run(pipeline.process(ctx))
        signal_names = [s.name for s in result.signals if hasattr(s, "name")]
        self.assertIn("ja4x_blacklist", signal_names)

    def test_blacklist_signal_uses_configured_score(self):
        """blacklist_score config controls the signal score."""
        config = {
            "fingerprinting": {
                "ja4x": {"enabled": True, "blacklist_score": 60, "emit_in_logs": True}
            }
        }
        pipeline = _make_pipeline(config)
        pipeline.update_ja4x_sets(
            whitelist=set(),
            blacklist={"target_fingerprint"},
        )
        ctx = _make_ctx(ja4x="target_fingerprint", alpn="other")
        result = self._run(pipeline.process(ctx))
        blacklist_signals = [
            s for s in result.signals if getattr(s, "name", "") == "ja4x_blacklist"
        ]
        self.assertEqual(len(blacklist_signals), 1)
        self.assertEqual(blacklist_signals[0].score, 60)

    def test_ja4x_none_skips_blacklist_signal(self):
        """ctx.ja4x = None → no blacklist signal emitted."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(whitelist=set(), blacklist={"anything"})
        ctx = _make_ctx(ja4x=None, alpn="other")
        result = self._run(pipeline.process(ctx))
        signal_names = [s.name for s in result.signals if hasattr(s, "name")]
        self.assertNotIn("ja4x_blacklist", signal_names)

    def test_ja4x_disabled_skips_blacklist_signal(self):
        """fingerprinting.ja4x.enabled=false → blacklist signal skipped."""
        config = {
            "fingerprinting": {
                "ja4x": {"enabled": False, "blacklist_score": 80, "emit_in_logs": False}
            }
        }
        pipeline = _make_pipeline(config)
        pipeline.update_ja4x_sets(whitelist=set(), blacklist={"target"})
        ctx = _make_ctx(ja4x="target", alpn="other")
        result = self._run(pipeline.process(ctx))
        signal_names = [s.name for s in result.signals if hasattr(s, "name")]
        self.assertNotIn("ja4x_blacklist", signal_names)


class TestJA4XCertExtraction(unittest.TestCase):
    """JA4X extracted from client cert in pipeline."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_client_cert_populates_ja4x(self):
        """ctx.client_certificate (DER bytes) → ctx.ja4x populated during collect_signals."""
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .sign(key, hashes.SHA256())
            )
            cert_der = cert.public_bytes(serialization.Encoding.DER)
        except ImportError:
            self.skipTest("cryptography not available")

        pipeline = _make_pipeline()
        ctx = _make_ctx(ja4x=None, client_certificate=cert_der, alpn="other")
        self._run(pipeline.process(ctx))
        # ctx.ja4x should be populated by _collect_signals
        self.assertIsNotNone(ctx.ja4x)
        parts = ctx.ja4x.split("_")
        self.assertEqual(len(parts), 3)

    def test_no_client_cert_leaves_ja4x_none(self):
        """ctx.client_certificate = None → ctx.ja4x unchanged (stays None)."""
        pipeline = _make_pipeline()
        ctx = _make_ctx(ja4x=None, client_certificate=None, alpn="other")
        self._run(pipeline.process(ctx))
        self.assertIsNone(ctx.ja4x)

    def test_already_set_ja4x_not_overwritten(self):
        """ctx.ja4x already set → _extract_ja4x_from_cert not called."""
        pipeline = _make_pipeline()
        existing = "aabbccddeeff_112233445566_aabbcc112233"
        ctx = _make_ctx(
            ja4x=existing,
            client_certificate=b"\x00\x01bad_cert",
            alpn="other",
        )
        self._run(pipeline.process(ctx))
        # Pre-existing ja4x preserved even though cert bytes are garbage
        self.assertEqual(ctx.ja4x, existing)


class TestJA4XUpdateSets(unittest.TestCase):
    """update_ja4x_sets() method."""

    def test_update_ja4x_sets_replaces_both(self):
        """update_ja4x_sets replaces whitelist and blacklist atomically."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(
            whitelist={"w1", "w2"},
            blacklist={"b1"},
        )
        self.assertEqual(pipeline._ja4x_whitelist, {"w1", "w2"})
        self.assertEqual(pipeline._ja4x_blacklist, {"b1"})

    def test_update_ja4x_sets_with_empty_sets(self):
        """Empty sets clear the lists."""
        pipeline = _make_pipeline()
        pipeline.update_ja4x_sets(whitelist={"existing"}, blacklist={"existing"})
        pipeline.update_ja4x_sets(whitelist=set(), blacklist=set())
        self.assertEqual(pipeline._ja4x_whitelist, set())
        self.assertEqual(pipeline._ja4x_blacklist, set())


if __name__ == "__main__":
    unittest.main()
