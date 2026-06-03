"""
Unit tests for the Phase 57a 9-byte format header in src/backup/format.py.

Covers:
- encode_header() produces exactly 9 bytes with correct magic, version, and flags
- decode_header() correctly round-trips encode→decode
- is_legacy_format() distinguishes old-format (no magic) from new-format
- decode_entries() transparently handles both new-format (with header) and
  legacy-format (no header) data (backward compatibility)
- Full round-trip: encode_entry() + encode_header() + decode_entries() = same entries
"""

import struct

import pytest

from src.backup.format import (
    FLAG_ENCRYPTED,
    FLAG_FULL,
    FLAG_INCREMENTAL,
    FORMAT_VERSION,
    MAGIC,
    decode_entries,
    decode_header,
    encode_entry,
    encode_header,
    is_legacy_format,
)

# ---------------------------------------------------------------------------
# encode_header
# ---------------------------------------------------------------------------


class TestEncodeHeader:
    def test_returns_bytes(self) -> None:
        result = encode_header("full", FLAG_FULL)
        assert isinstance(result, bytes)

    def test_returns_exactly_9_bytes(self) -> None:
        result = encode_header("full", FLAG_FULL)
        assert len(result) == 9

    def test_magic_bytes_present(self) -> None:
        """First 4 bytes must be the ASCII string 'JA4B'."""
        result = encode_header("full", FLAG_FULL)
        assert result[:4] == b"JA4B"
        assert result[:4] == MAGIC

    def test_version_byte_is_format_version(self) -> None:
        """Byte 4 carries the format version (currently 1)."""
        result = encode_header("full", FLAG_FULL)
        assert result[4] == FORMAT_VERSION
        assert result[4] == 1

    def test_flags_full_backup(self) -> None:
        """Full backup: flags last 4 bytes = FLAG_FULL = 0x01."""
        result = encode_header("full", FLAG_FULL)
        (flags,) = struct.unpack(">I", result[5:9])
        assert flags == FLAG_FULL
        assert flags == 0x01

    def test_flags_incremental_backup(self) -> None:
        """Incremental backup: flags = FLAG_INCREMENTAL = 0x02."""
        result = encode_header("incremental", FLAG_INCREMENTAL)
        (flags,) = struct.unpack(">I", result[5:9])
        assert flags == FLAG_INCREMENTAL
        assert flags == 0x02

    def test_flags_combined_full_encrypted(self) -> None:
        """FULL | ENCRYPTED combined flags = 0x05."""
        combined = FLAG_FULL | FLAG_ENCRYPTED
        result = encode_header("full", combined)
        assert len(result) == 9
        (flags,) = struct.unpack(">I", result[5:9])
        assert flags == combined
        assert flags == 0x05

    def test_flags_combined_incremental_encrypted(self) -> None:
        """INCREMENTAL | ENCRYPTED combined flags = 0x06."""
        combined = FLAG_INCREMENTAL | FLAG_ENCRYPTED
        result = encode_header("incremental", combined)
        (flags,) = struct.unpack(">I", result[5:9])
        assert flags == combined
        assert flags == 0x06

    def test_deterministic(self) -> None:
        """Same inputs always produce identical output."""
        a = encode_header("full", FLAG_FULL)
        b = encode_header("full", FLAG_FULL)
        assert a == b

    def test_flags_zero_allowed(self) -> None:
        """flags=0 is a valid (unset) flags value."""
        result = encode_header("full", 0)
        assert len(result) == 9
        (flags,) = struct.unpack(">I", result[5:9])
        assert flags == 0


# ---------------------------------------------------------------------------
# decode_header
# ---------------------------------------------------------------------------


class TestDecodeHeader:
    def test_round_trip_full(self) -> None:
        """encode_header → decode_header preserves backup_type and flags."""
        header = encode_header("full", FLAG_FULL)
        backup_type, flags = decode_header(header)
        assert backup_type == "full"
        assert flags == FLAG_FULL

    def test_round_trip_incremental(self) -> None:
        header = encode_header("incremental", FLAG_INCREMENTAL)
        backup_type, flags = decode_header(header)
        assert backup_type == "incremental"
        assert flags == FLAG_INCREMENTAL

    def test_round_trip_combined_flags(self) -> None:
        combined = FLAG_FULL | FLAG_ENCRYPTED
        header = encode_header("full", combined)
        backup_type, flags = decode_header(header)
        assert backup_type == "full"
        assert flags == combined
        # ENCRYPTED flag should be detectable independently
        assert flags & FLAG_ENCRYPTED == FLAG_ENCRYPTED
        assert flags & FLAG_FULL == FLAG_FULL

    def test_returns_tuple_of_two(self) -> None:
        header = encode_header("full", FLAG_FULL)
        result = decode_header(header)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_backup_type_is_str(self) -> None:
        header = encode_header("full", FLAG_FULL)
        backup_type, flags = decode_header(header)
        assert isinstance(backup_type, str)

    def test_flags_is_int(self) -> None:
        header = encode_header("full", FLAG_FULL)
        backup_type, flags = decode_header(header)
        assert isinstance(flags, int)

    def test_raises_on_wrong_magic(self) -> None:
        """Passing non-JA4B magic must raise ValueError."""
        bad_header = b"XXXX" + bytes([1]) + struct.pack(">I", FLAG_FULL)
        with pytest.raises((ValueError, Exception)):
            decode_header(bad_header)

    def test_raises_on_too_short(self) -> None:
        """Less than 9 bytes must raise an error."""
        with pytest.raises(Exception):
            decode_header(b"JA4B")


# ---------------------------------------------------------------------------
# is_legacy_format
# ---------------------------------------------------------------------------


class TestIsLegacyFormat:
    def test_legacy_format_returns_true_for_old_data(self) -> None:
        """Old-format data starts with 4-byte key-length, not 'JA4B'."""
        old_data = encode_entry("ban:1.2.3.4", b"dump_data")
        assert is_legacy_format(old_data) is True

    def test_new_format_returns_false(self) -> None:
        """New-format data starts with 'JA4B' magic."""
        header = encode_header("full", FLAG_FULL)
        entry = encode_entry("ban:1.2.3.4", b"dump_data")
        new_data = header + entry
        assert is_legacy_format(new_data) is False

    def test_empty_data_returns_true(self) -> None:
        """Empty data has no magic bytes — treat as legacy (no entries)."""
        assert is_legacy_format(b"") is True

    def test_short_data_without_magic_returns_true(self) -> None:
        """Less than 4 bytes that don't match magic → legacy."""
        assert is_legacy_format(b"\x00\x00") is True

    def test_exactly_magic_bytes_returns_false(self) -> None:
        """Exactly the 4 magic bytes → NOT legacy (new format, even if truncated)."""
        assert is_legacy_format(b"JA4B" + b"\x00" * 5) is False

    def test_multiple_entries_no_header_is_legacy(self) -> None:
        """Multiple entries with no header = legacy format."""
        data = encode_entry("k1", b"v1") + encode_entry("k2", b"v2")
        assert is_legacy_format(data) is True


# ---------------------------------------------------------------------------
# decode_entries — backward compatibility with new header
# ---------------------------------------------------------------------------


class TestDecodeEntriesWithHeader:
    def test_new_format_entries_decoded_correctly(self) -> None:
        """decode_entries skips 9-byte header and yields correct entries."""
        header = encode_header("full", FLAG_FULL)
        entry1 = encode_entry("ban:1.2.3.4", b"dump1")
        entry2 = encode_entry("config:dial", b"dump2")
        data = header + entry1 + entry2

        entries = list(decode_entries(data))
        assert entries == [("ban:1.2.3.4", b"dump1"), ("config:dial", b"dump2")]

    def test_legacy_format_still_works(self) -> None:
        """decode_entries on data without header still yields entries (backward compat)."""
        entry1 = encode_entry("ban:1.2.3.4", b"dump1")
        entry2 = encode_entry("config:dial", b"dump2")
        data = entry1 + entry2

        entries = list(decode_entries(data))
        assert entries == [("ban:1.2.3.4", b"dump1"), ("config:dial", b"dump2")]

    def test_new_format_single_entry(self) -> None:
        header = encode_header("incremental", FLAG_INCREMENTAL)
        entry = encode_entry("ja4:blacklist", b"\xde\xad\xbe\xef")
        data = header + entry

        entries = list(decode_entries(data))
        assert entries == [("ja4:blacklist", b"\xde\xad\xbe\xef")]

    def test_new_format_no_entries_yields_nothing(self) -> None:
        """Header only, no entries — should yield nothing."""
        header = encode_header("full", FLAG_FULL)
        entries = list(decode_entries(header))
        assert entries == []

    def test_legacy_format_empty_data_yields_nothing(self) -> None:
        """Legacy: empty data — should yield nothing (unchanged behaviour)."""
        entries = list(decode_entries(b""))
        assert entries == []


# ---------------------------------------------------------------------------
# Full round-trip with header
# ---------------------------------------------------------------------------


class TestFullRoundTripWithHeader:
    def test_encode_decode_round_trip_new_format(self) -> None:
        """encode_header + encode_entry × N → decode_entries reproduces entries."""
        pairs = [
            ("ban:1.2.3.4", b"dumpval1"),
            ("config:dial", b"dumpval2"),
            ("ja4:blacklist", b"dumpval3"),
        ]
        header = encode_header("full", FLAG_FULL)
        body = b"".join(encode_entry(k, v) for k, v in pairs)
        data = header + body

        result = list(decode_entries(data))
        assert result == pairs

    def test_encode_decode_round_trip_legacy(self) -> None:
        """Legacy round-trip unchanged: no header, decode_entries still works."""
        pairs = [
            ("ban:5.6.7.8", b"d1"),
            ("rdap:ip:1.2.3.4", b"d2"),
        ]
        data = b"".join(encode_entry(k, v) for k, v in pairs)
        result = list(decode_entries(data))
        assert result == pairs

    def test_encrypted_flag_survives_header_round_trip(self) -> None:
        """FULL | ENCRYPTED flag combination is preserved through encode/decode."""
        combined = FLAG_FULL | FLAG_ENCRYPTED
        header = encode_header("full", combined)
        backup_type, flags = decode_header(header)
        assert backup_type == "full"
        assert bool(flags & FLAG_ENCRYPTED)
        assert bool(flags & FLAG_FULL)

    def test_header_does_not_corrupt_entry_bytes(self) -> None:
        """The 9 magic bytes are not confused with entry data."""
        key = "test:key"
        val = b"some dump bytes"
        header = encode_header("full", FLAG_FULL)
        entry = encode_entry(key, val)
        data = header + entry

        entries = list(decode_entries(data))
        assert len(entries) == 1
        assert entries[0] == (key, val)
