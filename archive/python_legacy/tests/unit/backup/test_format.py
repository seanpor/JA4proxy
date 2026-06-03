"""
Unit tests for src/backup/format.py.

Validates the binary encode/decode round-trip, edge cases (empty data,
truncated entries, multiple entries, non-ASCII keys), and that the format
is stable across calls.
"""

import struct

import pytest
from src.backup.format import decode_entries, encode_entry


class TestEncodeEntry:
    def test_produces_bytes(self) -> None:
        result = encode_entry("ban:1.2.3.4", b"dump_data")
        assert isinstance(result, bytes)

    def test_length_prefix_correct(self) -> None:
        key = "config:dial"
        val = b"\x00\x01\x02"
        result = encode_entry(key, val)
        key_bytes = key.encode("utf-8")
        # First 4 bytes = key length
        (key_len,) = struct.unpack(">I", result[:4])
        assert key_len == len(key_bytes)
        # Then key_len bytes = key
        assert result[4 : 4 + key_len] == key_bytes
        # Then 4 bytes = value length
        (val_len,) = struct.unpack(">I", result[4 + key_len : 8 + key_len])
        assert val_len == len(val)
        # Then value bytes
        assert result[8 + key_len :] == val

    def test_empty_value_allowed(self) -> None:
        """Redis DUMP can return empty bytes for some key types."""
        result = encode_entry("tor:exit:ips", b"")
        assert len(result) == 4 + len("tor:exit:ips") + 4 + 0

    def test_non_ascii_value(self) -> None:
        """Dump data is raw bytes and may contain any byte values."""
        val = bytes(range(256))
        result = encode_entry("ja4:blacklist", val)
        assert result is not None

    def test_deterministic(self) -> None:
        """Same inputs always produce same output."""
        a = encode_entry("ban:10.0.0.1", b"data")
        b = encode_entry("ban:10.0.0.1", b"data")
        assert a == b


class TestDecodeEntries:
    def test_round_trip_single_entry(self) -> None:
        key, val = "ban:1.2.3.4", b"dump_value"
        data = encode_entry(key, val)
        entries = list(decode_entries(data))
        assert entries == [(key, val)]

    def test_round_trip_multiple_entries(self) -> None:
        pairs = [
            ("ban:1.2.3.4", b"dump1"),
            ("config:dial", b"dump2"),
            ("ja4:blacklist", b"dump3"),
        ]
        data = b"".join(encode_entry(k, v) for k, v in pairs)
        assert list(decode_entries(data)) == pairs

    def test_empty_input_yields_nothing(self) -> None:
        assert list(decode_entries(b"")) == []

    def test_truncated_key_length_field_yields_nothing(self) -> None:
        """Only 3 bytes for key-length prefix — can't read uint32."""
        assert list(decode_entries(b"\x00\x00\x01")) == []

    def test_truncated_key_bytes_yields_nothing(self) -> None:
        """Key length says 10 but only 5 bytes follow."""
        data = struct.pack(">I", 10) + b"hello"
        assert list(decode_entries(data)) == []

    def test_truncated_value_length_field_yields_nothing(self) -> None:
        """After key there are only 3 bytes for value-length prefix."""
        key = "x"
        data = struct.pack(">I", 1) + b"x" + b"\x00\x00\x01"
        assert list(decode_entries(data)) == []

    def test_truncated_value_bytes_yields_nothing(self) -> None:
        """Value length says 20 but only 5 bytes follow."""
        key = "k"
        data = struct.pack(">I", 1) + b"k" + struct.pack(">I", 20) + b"short"
        assert list(decode_entries(data)) == []

    def test_garbage_data_yields_nothing_without_error(self) -> None:
        """Raw text that doesn't match the format is silently ignored."""
        garbage = b"this is not a valid backup artifact at all"
        result = list(decode_entries(garbage))
        # First 4 bytes as big-endian uint32 = 0x74686973 = 1952999795
        # That many bytes aren't available → clean stop.
        assert result == []

    def test_partial_second_entry_returns_first(self) -> None:
        """One complete entry followed by truncated second entry yields only first."""
        good = encode_entry("ban:1.2.3.4", b"v1")
        truncated = struct.pack(">I", 5) + b"ab"  # key says 5 bytes but only 2 follow
        entries = list(decode_entries(good + truncated))
        assert entries == [("ban:1.2.3.4", b"v1")]

    def test_unicode_key_round_trip(self) -> None:
        """Keys may contain any UTF-8 characters."""
        key = "rdap:org:Cloudflare\u2122"
        val = b"\xde\xad\xbe\xef"
        data = encode_entry(key, val)
        assert list(decode_entries(data)) == [(key, val)]
