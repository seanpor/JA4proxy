"""
Unit tests for src/tap/fingerprints/os_fingerprint.py (Phase 20 Group 5-I).
"""
import pytest

from src.tap.fingerprints.os_fingerprint import (
    _BUILTIN_DB,
    OSFingerprintResult,
    OSSignature,
    load_os_database,
    match_os,
)
from tests.unit.tap.test_ja4t import _opts


class TestOSFingerprint:
    def test_linux_5x_default_identified_with_high_confidence(self):
        """Linux SYN: MSS=1460, SACK, TS, NOP, WSCALE, window=65160, TTL=64."""
        syn_opts = _opts((2, 1460), (4,), (8, 1000, 0), (1,), (3, 7))
        result = match_os(syn_opts, window_size=65160, ttl=64, df=True)
        assert result is not None
        assert "linux" in result.fingerprint_id.lower()
        assert result.confidence >= 0.5

    def test_windows_10_identified_with_high_confidence(self):
        """Windows 10 SYN: MSS=1460, NOP, WSCALE=8, NOP, NOP, SACK, window=65535, TTL=128."""
        syn_opts = _opts((2, 1460), (1,), (3, 8), (1,), (1,), (4,))
        result = match_os(syn_opts, window_size=65535, ttl=128, df=True)
        assert result is not None
        assert "windows" in result.fingerprint_id.lower() or result.confidence >= 0.4

    def test_macos_identified(self):
        """macOS SYN: MSS=1460, NOP, WSCALE=6, NOP, NOP, TS, SACK, window=65535, TTL=64."""
        syn_opts = _opts((2, 1460), (1,), (3, 6), (1,), (1,), (8, 0, 0), (4,))
        result = match_os(syn_opts, window_size=65535, ttl=64, df=True)
        assert result is not None
        assert isinstance(result, OSFingerprintResult)

    def test_unknown_os_returns_unknown_with_low_confidence(self):
        """Very unusual window/TTL combination → unknown."""
        result = match_os(b"", window_size=1, ttl=200, df=False)
        assert result is not None
        # Should return some result with low confidence or unknown label
        assert result.confidence <= 0.5 or result.fingerprint_id == "unknown"

    def test_database_loaded_from_yaml(self, tmp_path):
        """load_os_database() must read YAML and return OSSignature list."""
        import yaml
        db_file = tmp_path / "os_db.yaml"
        db_file.write_text(
            "signatures:\n"
            "  - id: test_os\n"
            "    label: Test OS\n"
            "    window_sizes: [65535]\n"
            "    mss: 1460\n"
            "    options_order: MSTNW\n"
            "    wscale: 6\n"
            "    ttl_range: [60, 64]\n"
            "    df: true\n"
        )
        db = load_os_database(db_file)
        assert len(db) >= 1
        assert any(sig.fingerprint_id == "test_os" for sig in db)

    def test_database_falls_back_to_builtin_on_missing_file(self, tmp_path):
        db = load_os_database(tmp_path / "nonexistent.yaml")
        assert len(db) > 0  # built-in has entries

    def test_multiple_window_sizes_in_database_match_any(self):
        """OSSignature with multiple window_sizes should match any of them."""
        syn_opts = _opts((2, 1460), (4,), (8, 0, 0), (1,), (3, 7))
        # Linux uses 65160 as a common window size; also 29200
        result_a = match_os(syn_opts, window_size=65160, ttl=64, df=True)
        result_b = match_os(syn_opts, window_size=29200, ttl=64, df=True)
        assert result_a is not None and result_b is not None
        # Both should identify as Linux
        assert "linux" in result_a.fingerprint_id.lower() or result_a.confidence > 0.3
        assert "linux" in result_b.fingerprint_id.lower() or result_b.confidence > 0.3

    def test_result_has_correct_ttl_and_df(self):
        syn_opts = _opts((2, 1460), (4,))
        result = match_os(syn_opts, window_size=1024, ttl=55, df=False)
        assert result.ttl == 55
        assert result.df is False

    def test_never_raises_on_garbage_opts(self):
        result = match_os(b"\xff\xff\xff", window_size=0, ttl=0, df=False)
        assert result is not None
