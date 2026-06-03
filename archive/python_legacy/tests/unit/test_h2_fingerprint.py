"""
Unit tests for src/tap/fingerprints/h2_fingerprint.py (Phase 20 Group 5-J).
"""

import struct

import pytest
from src.tap.fingerprints.h2_fingerprint import (
    _BUILTIN_DB,
    _H2_PREFACE,
    H2FingerprintResult,
    H2Signature,
    extract_h2_fingerprint,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_h2_preface_plus_settings(settings: dict, window_update: int = None) -> bytes:
    """Build HTTP/2 client connection preface + SETTINGS frame + optional WINDOW_UPDATE."""
    data = _H2_PREFACE

    # SETTINGS frame
    settings_payload = b""
    for ident, value in settings.items():
        settings_payload += struct.pack("!HI", ident, value)
    data += _h2_frame(0x4, 0x0, 0, settings_payload)

    if window_update is not None:
        wu_payload = struct.pack("!I", window_update)
        data += _h2_frame(0x8, 0x0, 0, wu_payload)

    return data


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    header = struct.pack("!I", length)[1:]  # 3-byte length
    header += struct.pack("!BBi", frame_type, flags, stream_id)
    return header + payload


def _chrome_120_stream() -> bytes:
    """Chrome 120 SETTINGS (from real capture)."""
    return _build_h2_preface_plus_settings(
        {
            0x1: 65536,  # HEADER_TABLE_SIZE
            0x2: 0,  # ENABLE_PUSH
            0x4: 6291456,  # INITIAL_WINDOW_SIZE
            0x6: 262144,  # MAX_HEADER_LIST_SIZE
        },
        window_update=15663105,
    )


def _firefox_121_stream() -> bytes:
    """Firefox 121 SETTINGS."""
    return _build_h2_preface_plus_settings(
        {
            0x1: 65536,  # HEADER_TABLE_SIZE
            0x4: 131072,  # INITIAL_WINDOW_SIZE
            0x5: 16384,  # MAX_FRAME_SIZE
        },
        window_update=12517377,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestH2Fingerprint:
    def test_chrome_120_settings_match_database_entry(self):
        result = extract_h2_fingerprint(_chrome_120_stream())
        assert result is not None
        assert result.matched_client == "chrome_120"
        assert result.confidence > 0.5

    def test_firefox_121_settings_identified(self):
        result = extract_h2_fingerprint(_firefox_121_stream())
        assert result is not None
        assert result.matched_client == "firefox_121"

    def test_settings_values_extracted(self):
        result = extract_h2_fingerprint(_chrome_120_stream())
        assert result is not None
        assert result.settings.get("INITIAL_WINDOW_SIZE") == 6291456
        assert result.settings.get("ENABLE_PUSH") == 0

    def test_window_update_increment_extracted(self):
        result = extract_h2_fingerprint(_chrome_120_stream())
        assert result is not None
        assert result.window_update_increment == 15663105

    def test_no_window_update_gives_none(self):
        stream = _build_h2_preface_plus_settings({0x1: 65536}, window_update=None)
        result = extract_h2_fingerprint(stream)
        assert result is not None
        assert result.window_update_increment is None

    def test_returns_none_on_non_http2_bytes(self):
        result = extract_h2_fingerprint(b"\x16\x03\x03\x00\x00")
        assert result is None

    def test_returns_none_on_empty_input(self):
        assert extract_h2_fingerprint(b"") is None

    def test_fingerprint_is_deterministic(self):
        stream = _chrome_120_stream()
        r1 = extract_h2_fingerprint(stream)
        r2 = extract_h2_fingerprint(stream)
        assert r1 is not None and r2 is not None
        assert r1.fingerprint == r2.fingerprint

    def test_settings_order_preserved(self):
        stream = _build_h2_preface_plus_settings({0x1: 100, 0x4: 200, 0x6: 300})
        result = extract_h2_fingerprint(stream)
        assert result is not None
        # Order: HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE
        assert result.settings_order == [
            "HEADER_TABLE_SIZE",
            "INITIAL_WINDOW_SIZE",
            "MAX_HEADER_LIST_SIZE",
        ]

    def test_fingerprint_starts_with_h2(self):
        result = extract_h2_fingerprint(_chrome_120_stream())
        assert result is not None
        assert result.fingerprint.startswith("h2_")

    def test_custom_database_used_when_provided(self):
        custom_sig = H2Signature(
            client_id="test_client",
            settings_order=["HEADER_TABLE_SIZE"],
            settings={"HEADER_TABLE_SIZE": 99999},
            window_update=None,
        )
        stream = _build_h2_preface_plus_settings({0x1: 99999})
        result = extract_h2_fingerprint(stream, database=[custom_sig])
        assert result is not None
        assert result.matched_client == "test_client"


# ── Missing-coverage tests ────────────────────────────────────────────────────


class TestH2FingerprintMissingCoverage:
    """Cover load_h2_database(), exception in extract_h2_fingerprint(), and
    zero-settings signature (line 216).

    So what: h2_fingerprint.py parses attacker-controlled HTTP/2 frames —
    every unhandled exception in this path is a potential proxy DoS vector.
    """

    def test_load_h2_database_from_yaml_file(self, tmp_path):
        """load_h2_database reads YAML and returns H2Signature list (lines 99-117).
        So what: if database loading fails, ALL h2 fingerprints are unmatched —
        no bot identification, no blocklist lookups based on h2 fingerprint."""
        from src.tap.fingerprints.h2_fingerprint import H2Signature, load_h2_database

        yaml_content = """
signatures:
  - id: TestBrowser/1.0
    settings_order:
      - HEADER_TABLE_SIZE
    settings:
      HEADER_TABLE_SIZE: 65536
    window_update: 1048576
"""
        p = tmp_path / "h2db.yaml"
        p.write_text(yaml_content)
        sigs = load_h2_database(p)
        assert len(sigs) == 1
        assert sigs[0].client_id == "TestBrowser/1.0"
        assert sigs[0].settings.get("HEADER_TABLE_SIZE") == 65536
        assert sigs[0].window_update == 1048576

    def test_load_h2_database_malformed_yaml_returns_builtin(self, tmp_path):
        """load_h2_database with malformed YAML → returns builtin DB (line 116-117).
        So what: a corrupt database file must not crash fingerprinting — built-in
        signatures must still be available for known-bad bot detection."""
        from src.tap.fingerprints.h2_fingerprint import load_h2_database

        p = tmp_path / "bad.yaml"
        p.write_text("not: valid: yaml: content: [unclosed")
        sigs = load_h2_database(p)
        # Must return builtin signatures, not empty list
        assert len(sigs) > 0

    def test_load_h2_database_nonexistent_returns_builtin(self, tmp_path):
        """load_h2_database with missing file → returns builtin DB.
        So what: missing YAML on first deploy must not crash the fingerprinter."""
        from src.tap.fingerprints.h2_fingerprint import load_h2_database

        sigs = load_h2_database(tmp_path / "nonexistent.yaml")
        assert len(sigs) > 0

    def test_load_h2_database_empty_signatures_returns_builtin(self, tmp_path):
        """load_h2_database with empty signatures list → returns builtin (line 115).
        So what: an empty YAML must not silently disable all client identification."""
        from src.tap.fingerprints.h2_fingerprint import load_h2_database

        p = tmp_path / "empty.yaml"
        p.write_text("signatures: []\n")
        sigs = load_h2_database(p)
        assert len(sigs) > 0

    def test_extract_h2_fingerprint_exception_returns_none(self):
        """_parse() raising → extract_h2_fingerprint returns None (lines 136-137).
        So what: unexpected parse error on malformed H2 frame must not crash the tap."""
        from unittest.mock import patch

        import src.tap.fingerprints.h2_fingerprint as _mod

        with patch.object(_mod, "_parse", side_effect=RuntimeError("injected")):
            result = _mod.extract_h2_fingerprint(b"\x00" * 20)
        assert result is None

    def test_match_db_skips_zero_settings_signature(self):
        """Signature with empty settings → continue (line 216).
        So what: zero-settings signature must not be matched against any client,
        which would produce a false 'unknown' identity."""
        from src.tap.fingerprints.h2_fingerprint import H2Signature, _match_db

        empty_sig = H2Signature(
            client_id="empty_sig",
            settings_order=[],
            settings={},
            window_update=None,  # total = 0 → must be skipped
        )
        real_sig = H2Signature(
            client_id="real_client",
            settings_order=["HEADER_TABLE_SIZE"],
            settings={"HEADER_TABLE_SIZE": 65536},
            window_update=None,
        )
        client, score = _match_db(
            {"HEADER_TABLE_SIZE": 65536},
            ["HEADER_TABLE_SIZE"],
            None,
            [empty_sig, real_sig],  # empty_sig must be skipped
        )
        # Should match real_sig, not empty_sig
        assert client == "real_client"
        assert score > 0
