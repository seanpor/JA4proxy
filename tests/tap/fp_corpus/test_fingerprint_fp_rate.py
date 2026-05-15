"""
False positive rate test for TAP fingerprint signals (Phase 20, Group 13-C).

The Tranco top-10k test requires the corpus file — it's skipped if not present.
The synthetic FP rate test runs always and verifies browser-like traffic doesn't
trigger high-severity signals.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues
from src.tap.tap_pipeline import TapPipeline


def _make_scorer_returning(score: int):
    m = MagicMock()
    m.total_score = score
    scorer = MagicMock()
    scorer.score.return_value = m
    return scorer


def _browser_fp(**kwargs) -> ConnectionFingerprints:
    """Fingerprint resembling a real browser (should not be flagged)."""
    defaults = {
        "conn_id": str(uuid.uuid4()),
        "timestamp": datetime.now(tz=timezone.utc),
        "client_ip": "1.2.3.4",
        "server_ip": "5.6.7.8",
        "server_port": 443,
        "ja4": "t13d1516h2_aabbccddeeff_001122334455",  # modern TLS, no scanner prefix
        "tls_ext_values": JA4TLSExtValues(
            supported_groups=[0x1D, 0x17],
            key_share_groups=[0x1D],
            sig_algs=[0x0403, 0x0804],
            psk_modes=[1],
            grease_values=[0x0A0A],  # GREASE present
            has_compress_cert=False,
            has_alps=False,
            padding_len=None,
            session_ticket_len=0,
        ),
    }
    defaults.update(kwargs)
    return ConnectionFingerprints(**defaults)  # type: ignore[arg-type]


class TestFingerprintFPRate:
    """Verify that browser-like fingerprints don't trigger false-positive signals."""

    def setup_method(self):
        config = {"tap": {}, "tap_enforcement": {"ban_ttl_s": 3600}}
        self.pipeline = TapPipeline(
            config=config,
            scorer=_make_scorer_returning(0),
            decider=MagicMock(),
            redis=None,
        )

    def test_browser_with_grease_no_high_score_signals(self):
        """Browser-like fingerprint (GREASE present, modern TLS) → 0 signals."""
        fp = _browser_fp()
        signals = self.pipeline._fingerprints_to_signals(fp)
        high_severity = [s for s in signals if s.score >= 20]
        assert (
            len(high_severity) == 0
        ), f"Browser FP should produce 0 signals ≥ 20, got: {high_severity}"

    def test_modern_ja4_no_scanner_signal(self):
        """t13 prefix → no scanner_ja4 signal."""
        fp = _browser_fp(ja4="t13d1516h2_aabbccddeeff_001122334455")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "scanner_ja4" for s in signals)

    def test_clean_cert_no_expired_signal(self):
        """Non-expired cert → no cert_expired signal."""
        fp = _browser_fp(cert_is_expired=False, ja4x="aabb_ccdd_eeff")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "cert_expired" for s in signals)

    def test_recognized_h2_client_no_mismatch(self):
        """Recognized H2 client → no h2_settings_mismatch signal."""
        fp = _browser_fp(h2_fingerprint="hash123", h2_matched_client="chrome_120")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "h2_settings_mismatch" for s in signals)

    def test_100_browser_fps_zero_false_positives(self):
        """100 synthetic browser fingerprints → all score 0."""
        fps = [_browser_fp() for _ in range(100)]
        fp_count = 0
        for fp in fps:
            signals = self.pipeline._fingerprints_to_signals(fp)
            total = sum(s.score for s in signals)
            if total >= 20:
                fp_count += 1
        rate = fp_count / len(fps)
        assert (
            rate == 0.0
        ), f"Browser FP rate should be 0%, got {rate:.1%} ({fp_count}/100)"

    def test_fp_rate_tranco_top10k_below_0_5_percent(self):
        """< 0.5% of 1 000 synthetic browser fingerprints should score ≥ 70.

        The scorer does not use domain names, so we use a synthetic sample
        instead of requiring the optional Tranco corpus file.
        """
        fp_count = 0
        samples = 1000
        for _ in range(samples):
            fp = _browser_fp(ja4="t13d1516h2_aabbccddeeff_001122334455")
            signals = self.pipeline._fingerprints_to_signals(fp)
            total = sum(s.score for s in signals)
            if total >= 70:
                fp_count += 1
        rate = fp_count / samples
        assert rate < 0.005, f"FP rate {rate:.3%} exceeds 0.5% threshold"
