"""
Unit tests for src/tap/fingerprints/ja4t.py (Phase 20 Group 5-C).
"""
import struct

import pytest

from src.tap.fingerprints.ja4t import JA4TResult, extract_ja4t_from_syn


# ---------------------------------------------------------------------------
# Helpers — build raw TCP options bytes
# ---------------------------------------------------------------------------


def _opts(*args: tuple) -> bytes:
    """Build TCP options bytes from a list of (kind, value?) tuples.

    Usage:
        _opts((2, 1460), (4,), (8, 0, 0), (1,), (3, 6))  # MSS, SACK, TS, NOP, WSCALE
    """
    out = b""
    for item in args:
        kind = item[0]
        if kind == 0:   # EOL
            out += bytes([0])
        elif kind == 1:  # NOP
            out += bytes([1])
        elif kind == 2:  # MSS (4 bytes total)
            mss = item[1] if len(item) > 1 else 1460
            out += struct.pack("!BBH", 2, 4, mss)
        elif kind == 3:  # WSCALE (3 bytes total)
            ws = item[1] if len(item) > 1 else 6
            out += struct.pack("!BBB", 3, 3, ws)
        elif kind == 4:  # SACK_PERMITTED (2 bytes total)
            out += bytes([4, 2])
        elif kind == 8:  # TIMESTAMP (10 bytes total)
            ts_val = item[1] if len(item) > 1 else 0
            ts_echo = item[2] if len(item) > 2 else 0
            out += struct.pack("!BBII", 8, 10, ts_val, ts_echo)
        else:
            out += bytes([kind, 2])  # minimal unknown option
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJA4T:
    def test_linux_default_syn_options(self):
        """Linux 5.x: MSS, SACK, TS, NOP, WSCALE."""
        opts = _opts((2, 1460), (4,), (8, 123, 0), (1,), (3, 7))
        result = extract_ja4t_from_syn(opts, window_size=29200)
        assert result is not None
        assert result.mss == 1460
        assert result.sack_permitted is True
        assert result.timestamps is True
        assert result.window_scale == 7
        assert "M" in result.options_order
        assert "S" in result.options_order
        assert "T" in result.options_order
        assert "W" in result.options_order
        assert result.fingerprint.startswith("29200_")

    def test_windows_10_syn_options(self):
        """Windows 10: MSS, NOP, WSCALE, NOP, NOP, SACK."""
        opts = _opts((2, 1460), (1,), (3, 8), (1,), (1,), (4,))
        result = extract_ja4t_from_syn(opts, window_size=65535)
        assert result is not None
        assert result.window_size == 65535
        assert result.mss == 1460
        assert result.window_scale == 8

    def test_macos_syn_options(self):
        """macOS: MSS, NOP, WSCALE, NOP, NOP, TS, SACK."""
        opts = _opts((2, 1460), (1,), (3, 6), (1,), (1,), (8, 0, 0), (4,))
        result = extract_ja4t_from_syn(opts, window_size=65535)
        assert result is not None
        assert result.mss == 1460
        assert result.window_scale == 6

    def test_no_options_produces_valid_fingerprint(self):
        result = extract_ja4t_from_syn(b"", window_size=512)
        assert result is not None
        assert result.fingerprint.startswith("512_")
        assert result.mss is None
        assert result.window_scale is None

    def test_unknown_option_type_included_as_decimal(self):
        # Kind 254 is an unknown option
        opts = bytes([254, 2]) + _opts((2, 1460))
        result = extract_ja4t_from_syn(opts, window_size=65535)
        assert result is not None
        # Unknown kind 254 should appear as a decimal string in options_order
        assert "254" in result.options_order

    def test_fingerprint_format(self):
        opts = _opts((2, 1460), (4,), (8, 0, 0), (1,), (3, 6))
        result = extract_ja4t_from_syn(opts, window_size=65535)
        parts = result.fingerprint.split("_")
        assert len(parts) == 4
        assert parts[0] == "65535"

    def test_nop_padding_included(self):
        opts = _opts((1,), (1,), (2, 1460))
        result = extract_ja4t_from_syn(opts, window_size=1024)
        assert "N" in result.options_order

    def test_raw_options_hex_present(self):
        opts = _opts((2, 1460))
        result = extract_ja4t_from_syn(opts, window_size=8192)
        assert result.raw_options_hex == opts.hex()

    def test_returns_result_on_corrupt_options(self):
        """Corrupt options must not raise — return a valid JA4TResult."""
        result = extract_ja4t_from_syn(b"\xff\x00\xff", window_size=1024)
        assert result is not None
        assert isinstance(result, JA4TResult)
