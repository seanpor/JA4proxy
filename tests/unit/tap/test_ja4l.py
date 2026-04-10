"""
Unit tests for src/tap/fingerprints/ja4l.py (Phase 20 Group 5-E).
"""
import pytest

from src.tap.fingerprints.ja4l import _C_FIBRE_KM_S, JA4LResult, extract_ja4l


class TestJA4L:
    def test_known_rtt_produces_expected_distance(self):
        """10ms RTT → ~1000 km one-way distance (speed of light in fibre)."""
        # SYN at t=0, SYN-ACK at t=0.010 (10ms RTT), ACK at t=0.020
        result = extract_ja4l(syn_ts=0.0, synack_ts=0.010, ack_ts=0.020)
        assert result is not None
        expected_km = (0.010 / 2.0) * _C_FIBRE_KM_S  # 1000 km
        assert abs(result.client_distance_km - expected_km) < 1.0

    def test_zero_rtt_produces_zero_distance(self):
        result = extract_ja4l(syn_ts=0.0, synack_ts=0.0, ack_ts=0.0)
        assert result is not None
        assert result.client_distance_km == 0.0
        assert result.server_distance_km == 0.0
        assert result.rtt_client_ms == 0.0

    def test_distance_mismatch_false_when_within_500km(self):
        # ~1000 km RTT, GeoIP says 800 km → within 500 km threshold
        result = extract_ja4l(
            syn_ts=0.0,
            synack_ts=0.010,
            ack_ts=0.020,
            geoip_distance_km=800.0,
            mismatch_threshold_km=500.0,
        )
        assert result is not None
        assert result.distance_mismatch is False

    def test_distance_mismatch_true_when_exceeds_500km(self):
        # 1000 km timing, 50 km GeoIP → mismatch > 500 km
        result = extract_ja4l(
            syn_ts=0.0,
            synack_ts=0.010,
            ack_ts=0.020,
            geoip_distance_km=50.0,
            mismatch_threshold_km=500.0,
        )
        assert result is not None
        assert result.distance_mismatch is True

    def test_negative_rtt_handled_gracefully(self):
        """Reversed timestamps (clock jitter) must not raise."""
        result = extract_ja4l(syn_ts=1.0, synack_ts=0.9, ack_ts=0.8)
        assert result is not None
        # Distance should be clamped to 0
        assert result.client_distance_km == 0.0

    def test_fingerprint_format(self):
        result = extract_ja4l(syn_ts=0.0, synack_ts=0.020, ack_ts=0.040)
        assert result is not None
        assert result.fingerprint.startswith("ja4l_")
        parts = result.fingerprint.split("_")
        assert len(parts) == 3
        assert parts[1].isdigit()
        assert parts[2].isdigit()

    def test_geoip_none_no_mismatch(self):
        result = extract_ja4l(
            syn_ts=0.0, synack_ts=0.5, ack_ts=1.0, geoip_distance_km=None
        )
        assert result is not None
        assert result.distance_mismatch is False
        assert result.geoip_distance_km is None

    def test_large_rtt_clamped(self):
        """RTT > 10s should be clamped to avoid nonsensical distances."""
        result = extract_ja4l(syn_ts=0.0, synack_ts=100.0, ack_ts=200.0)
        assert result is not None
        assert result.client_distance_km <= (_C_FIBRE_KM_S * 10.0 / 2.0)


# ── Missing-coverage additions ────────────────────────────────────────────────

class TestJA4LCoverageGaps:
    """Cover lines 55-56 and 104 in ja4l.py.

    So what: these exception paths guarantee that the capture loop always
    receives a valid JA4LResult even when timestamps are garbage — a crash
    here would drop all light-distance signals for that connection.
    """

    def test_exception_in_compute_returns_zero(self):
        """_compute() raising → _zero() returned (lines 55-56, 104).
        So what: any crash in distance math must return a zero-result, not propagate."""
        from unittest.mock import patch

        import src.tap.fingerprints.ja4l as _mod
        with patch.object(_mod, "_compute", side_effect=RuntimeError("injected")):
            result = _mod.extract_ja4l(syn_ts=0.0, synack_ts=0.1, ack_ts=0.2)
        assert result is not None
        assert result.fingerprint == "ja4l_0_0"
        assert result.client_distance_km == 0.0
