"""Integration tests for Phase 16g — JA4X Extended Fingerprinting.

Tests the full pipeline integration:
- JA4X populated in ConnectionContext from mTLS client cert (DER bytes)
- JA4X whitelist bypass fires end-to-end
- JA4X blacklist signal integrates into scorer → action
- JA4X emitted in structured JSON log
- Disabled config path produces no ja4x side-effects

These tests use real X.509 certificates generated in-process via the
``cryptography`` library. No network or Docker stack required.
"""

import asyncio
import hashlib
import json
import logging
from unittest.mock import MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.security.risk_scorer import RiskScorer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _make_pipeline(extra_config: dict | None = None, dial: int = 100) -> Pipeline:
    config: dict = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True, "ips": []},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        },
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

    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _make_cert_der() -> bytes:
    """Generate a minimal self-signed DER certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("client.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _expected_ja4x(cert_der: bytes) -> str:
    """Compute expected JA4X from DER cert (mirrors Pipeline._extract_ja4x_from_cert)."""
    from cryptography import x509

    cert = x509.load_der_x509_certificate(cert_der)

    def _sorted_attrs(name) -> str:
        return ",".join(
            sorted(f"{attr.oid.dotted_string}={attr.value}" for attr in name)
        )

    issuer = _sorted_attrs(cert.issuer)
    subject = _sorted_attrs(cert.subject)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ",".join(sorted(str(n) for n in san_ext.value))
    except x509.ExtensionNotFound:
        san = ""

    def _hash(s: str) -> str:
        if not s:
            return "000000000000"
        return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]

    return f"{_hash(issuer)}_{_hash(subject)}_{_hash(san)}"


# ---------------------------------------------------------------------------
# Test: JA4X populated in pipeline from client cert
# ---------------------------------------------------------------------------


class TestJA4XPopulatedFromClientCert:
    """Pipeline._collect_signals extracts ja4x from ctx.client_certificate."""

    @pytest.fixture(autouse=True)
    def skip_if_no_cryptography(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

    @pytest.mark.asyncio
    async def test_client_cert_populates_ja4x_in_pipeline(self):
        """ctx.client_certificate (DER) → ctx.ja4x set during pipeline.process()."""
        cert_der = _make_cert_der()
        pipeline = _make_pipeline()
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            client_certificate=cert_der,
        )
        await pipeline.process(ctx)
        assert ctx.ja4x is not None
        parts = ctx.ja4x.split("_")
        assert len(parts) == 3
        assert all(len(p) == 12 for p in parts)

    @pytest.mark.asyncio
    async def test_ja4x_matches_expected_hash(self):
        """ja4x value matches independently computed hash of same cert."""
        cert_der = _make_cert_der()
        expected = _expected_ja4x(cert_der)
        pipeline = _make_pipeline()
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            client_certificate=cert_der,
        )
        await pipeline.process(ctx)
        assert ctx.ja4x == expected

    @pytest.mark.asyncio
    async def test_no_client_cert_leaves_ja4x_none(self):
        """ctx.client_certificate = None → ctx.ja4x remains None."""
        pipeline = _make_pipeline()
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            client_certificate=None,
        )
        await pipeline.process(ctx)
        assert ctx.ja4x is None

    @pytest.mark.asyncio
    async def test_pre_set_ja4x_not_overwritten_by_cert(self):
        """If ctx.ja4x is already set, _collect_signals must not overwrite it."""
        cert_der = _make_cert_der()
        pipeline = _make_pipeline()
        preset = "aabbccddeeff_112233445566_aabbcc112233"
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x=preset,
            client_certificate=cert_der,
        )
        await pipeline.process(ctx)
        assert ctx.ja4x == preset  # pre-set value preserved

    @pytest.mark.asyncio
    async def test_invalid_cert_bytes_leaves_ja4x_none(self):
        """Garbage cert bytes → extraction fails gracefully; ja4x stays None."""
        pipeline = _make_pipeline()
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            client_certificate=b"\x00\xde\xad\xbe\xef",
        )
        await pipeline.process(ctx)
        assert ctx.ja4x is None


# ---------------------------------------------------------------------------
# Test: JA4X whitelist bypass — full pipeline integration
# ---------------------------------------------------------------------------


class TestJA4XWhitelistBypassIntegration:
    """JA4X whitelist bypass fires before scoring when ja4x matches."""

    @pytest.fixture(autouse=True)
    def skip_if_no_cryptography(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

    @pytest.mark.asyncio
    async def test_ja4x_whitelist_bypasses_scoring(self):
        """ctx.ja4x in whitelist → ALLOW bypass; scorer never called."""
        cert_der = _make_cert_der()
        expected_ja4x = _expected_ja4x(cert_der)

        pipeline = _make_pipeline(dial=100)
        pipeline.update_ja4x_sets(whitelist={expected_ja4x}, blacklist=set())

        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            client_certificate=cert_der,
            ja4x=expected_ja4x,  # pre-set so whitelist fires in _check_allow_bypasses
        )
        result = await pipeline.process(ctx)
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4x_whitelist"

    @pytest.mark.asyncio
    async def test_ja4x_not_in_whitelist_falls_through_to_scoring(self):
        """ctx.ja4x not in whitelist → falls through to full scoring."""
        pipeline = _make_pipeline(dial=100)
        pipeline.update_ja4x_sets(whitelist={"different_fp_______"}, blacklist=set())

        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x="aabbccddeeff_112233445566_aabbcc112233",
        )
        result = await pipeline.process(ctx)
        assert not result.bypassed


# ---------------------------------------------------------------------------
# Test: JA4X blacklist signal — full pipeline integration
# ---------------------------------------------------------------------------


class TestJA4XBlacklistSignalIntegration:
    """JA4X blacklist adds RiskSignal that integrates into final score."""

    @pytest.mark.asyncio
    async def test_ja4x_in_blacklist_contributes_to_score(self):
        """ja4x in blacklist → RiskSignal(+80) → score ≥ 80 → block at dial=100."""
        pipeline = _make_pipeline(dial=100)
        pipeline.update_ja4x_sets(
            whitelist=set(),
            blacklist={"aabbccddeeff_112233445566_aabbcc112233"},
        )
        ctx = ConnectionContext(
            client_ip="5.6.7.8",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x="aabbccddeeff_112233445566_aabbcc112233",
        )
        result = await pipeline.process(ctx)
        # Score 80 ≥ block threshold 70 → blocked
        assert result.action in ("block", "ban")
        assert result.score is not None and result.score >= 70

    @pytest.mark.asyncio
    async def test_ja4x_signal_name_in_result(self):
        """RiskSignal named 'ja4x_blacklist' appears in result.signals."""
        pipeline = _make_pipeline(dial=100)
        fingerprint = "aabbccddeeff_112233445566_aabbcc112233"
        pipeline.update_ja4x_sets(whitelist=set(), blacklist={fingerprint})

        ctx = ConnectionContext(
            client_ip="5.6.7.8",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x=fingerprint,
        )
        result = await pipeline.process(ctx)
        signal_names = {s.name for s in result.signals if hasattr(s, "name")}
        assert "ja4x_blacklist" in signal_names

    @pytest.mark.asyncio
    async def test_ja4x_blacklist_score_matches_config(self):
        """blacklist_score config drives the actual signal score."""
        pipeline = _make_pipeline(
            extra_config={
                "fingerprinting": {
                    "ja4x": {"enabled": True, "blacklist_score": 55, "emit_in_logs": True}
                }
            },
            dial=100,
        )
        fingerprint = "aabbccddeeff_112233445566_aabbcc112233"
        pipeline.update_ja4x_sets(whitelist=set(), blacklist={fingerprint})

        ctx = ConnectionContext(
            client_ip="5.6.7.8",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x=fingerprint,
        )
        result = await pipeline.process(ctx)
        bl_signals = [
            s for s in result.signals
            if getattr(s, "name", "") == "ja4x_blacklist"
        ]
        assert len(bl_signals) == 1
        assert bl_signals[0].score == 55

    @pytest.mark.asyncio
    async def test_ja4x_disabled_no_blacklist_signal(self):
        """fingerprinting.ja4x.enabled=false → blacklist not consulted; no signal."""
        pipeline = _make_pipeline(
            extra_config={
                "fingerprinting": {
                    "ja4x": {"enabled": False, "blacklist_score": 80, "emit_in_logs": False}
                }
            },
            dial=100,
        )
        pipeline.update_ja4x_sets(whitelist=set(), blacklist={"any_fingerprint_here"})

        ctx = ConnectionContext(
            client_ip="5.6.7.8",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x="any_fingerprint_here",
        )
        result = await pipeline.process(ctx)
        signal_names = {s.name for s in result.signals if hasattr(s, "name")}
        assert "ja4x_blacklist" not in signal_names


# ---------------------------------------------------------------------------
# Test: JA4X emitted in structured JSON log
# ---------------------------------------------------------------------------


class TestJA4XEmittedInLog:
    """Pipeline._emit_log includes ja4x in JSON when enabled."""

    @pytest.mark.asyncio
    async def test_ja4x_appears_in_json_log(self, caplog):
        """JSON log line contains ja4x field when ctx.ja4x is set."""
        pipeline = _make_pipeline()
        fingerprint = "aabbccddeeff_112233445566_aabbcc112233"
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x=fingerprint,
        )
        with caplog.at_level(logging.DEBUG, logger="src.security.pipeline"):
            await pipeline.process(ctx)

        json_lines = [
            line for line in caplog.messages
            if line.startswith("{") and '"type": "connection"' in line
        ]
        assert json_lines, "No JSON log lines found"
        doc = json.loads(json_lines[0])
        assert "ja4x" in doc
        assert doc["ja4x"] == fingerprint

    @pytest.mark.asyncio
    async def test_ja4x_absent_from_log_when_none(self, caplog):
        """JSON log omits ja4x key when ctx.ja4x is None."""
        pipeline = _make_pipeline()
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x=None,
        )
        with caplog.at_level(logging.DEBUG, logger="src.security.pipeline"):
            await pipeline.process(ctx)

        json_lines = [
            line for line in caplog.messages
            if line.startswith("{") and '"type": "connection"' in line
        ]
        assert json_lines
        doc = json.loads(json_lines[0])
        assert "ja4x" not in doc

    @pytest.mark.asyncio
    async def test_ja4x_absent_from_log_when_emit_disabled(self, caplog):
        """JSON log omits ja4x when fingerprinting.ja4x.emit_in_logs=false."""
        pipeline = _make_pipeline(
            extra_config={
                "fingerprinting": {
                    "ja4x": {"enabled": True, "blacklist_score": 80, "emit_in_logs": False}
                }
            }
        )
        ctx = ConnectionContext(
            client_ip="1.2.3.4",
            ja4="t13d1516h2_aabbccddeeff_aabbccddeeff",
            ja4x="aabbccddeeff_112233445566_aabbcc112233",
        )
        with caplog.at_level(logging.DEBUG, logger="src.security.pipeline"):
            await pipeline.process(ctx)

        json_lines = [
            line for line in caplog.messages
            if line.startswith("{") and '"type": "connection"' in line
        ]
        assert json_lines
        doc = json.loads(json_lines[0])
        assert "ja4x" not in doc
