"""
Unit tests for src/tap/fingerprints/ja4ssh.py (Phase 20 Group 5-G).
"""
import struct

import pytest

from src.tap.fingerprints.ja4ssh import JA4SSHResult, extract_ja4ssh

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_kexinit(
    kex: list = None,
    host_key: list = None,
    enc_c2s: list = None,
    enc_s2c: list = None,
    mac_c2s: list = None,
    mac_s2c: list = None,
    comp_c2s: list = None,
    comp_s2c: list = None,
    lang_c2s: list = None,
    lang_s2c: list = None,
) -> bytes:
    """Build a minimal SSH_MSG_KEXINIT payload (starts with message type 0x14)."""
    lists = [
        kex or ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        host_key or ["rsa-sha2-256", "ssh-rsa"],
        enc_c2s or ["aes128-ctr", "aes256-ctr"],
        enc_s2c or ["aes128-ctr", "aes256-ctr"],
        mac_c2s or ["hmac-sha2-256", "hmac-sha1"],
        mac_s2c or ["hmac-sha2-256", "hmac-sha1"],
        comp_c2s or ["none"],
        comp_s2c or ["none"],
        lang_c2s or [],
        lang_s2c or [],
    ]

    payload = bytes([0x14])             # MSG_KEXINIT
    payload += b"\xaa" * 16            # cookie
    for lst in lists:
        s = ",".join(lst).encode("ascii")
        payload += struct.pack("!I", len(s)) + s
    # first_kex_packet_follows (1 byte) + reserved (4 bytes)
    payload += struct.pack("!BI", 0, 0)
    return payload


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJA4SSH:
    def test_openssh_8x_client_fingerprint(self):
        """OpenSSH 8.x client: curve25519+chacha20+hmac-sha2-256."""
        data = _build_kexinit(
            kex=["curve25519-sha256", "ecdh-sha2-nistp256"],
            enc_c2s=["chacha20-poly1305@openssh.com", "aes128-ctr"],
            mac_c2s=["umac-64-etm@openssh.com", "hmac-sha2-256"],
        )
        result = extract_ja4ssh(data, direction="client")
        assert result is not None
        assert isinstance(result, JA4SSHResult)
        assert result.direction == "client"
        assert "curve25519-sha256" in result.kex_algorithms
        assert result.fingerprint.startswith("ja4ssh_c")

    def test_paramiko_client_fingerprint(self):
        """Paramiko (Python SSH library) pattern."""
        data = _build_kexinit(
            kex=["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
            enc_c2s=["aes128-ctr", "aes192-ctr", "aes256-ctr"],
            mac_c2s=["hmac-sha2-256", "hmac-sha1"],
        )
        result = extract_ja4ssh(data, direction="client")
        assert result is not None
        assert result.fingerprint.startswith("ja4ssh_c")

    def test_server_direction_produces_different_fingerprint(self):
        data = _build_kexinit()
        client_result = extract_ja4ssh(data, direction="client")
        server_result = extract_ja4ssh(data, direction="server")
        assert client_result is not None
        assert server_result is not None
        assert client_result.fingerprint[7] == "c"  # ja4ssh_[c]NN...
        assert server_result.fingerprint[7] == "s"

    def test_returns_none_on_truncated_kexinit(self):
        data = _build_kexinit()
        result = extract_ja4ssh(data[:5], direction="client")
        assert result is None

    def test_returns_none_on_wrong_message_type(self):
        data = bytes([0x15]) + b"\xaa" * 16  # Wrong type
        result = extract_ja4ssh(data, direction="client")
        assert result is None

    def test_algorithm_counts_in_fingerprint(self):
        data = _build_kexinit(
            kex=["a", "b", "c"],  # 3 kex algorithms
            enc_c2s=["aes128-ctr", "aes256-ctr"],  # 2 enc algorithms
        )
        result = extract_ja4ssh(data, direction="client")
        assert result is not None
        # Fingerprint should encode kex_count (03) and enc_count (02)
        assert "03" in result.fingerprint
        assert "02" in result.fingerprint

    def test_kex_algorithms_list_populated(self):
        data = _build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group14-sha256"])
        result = extract_ja4ssh(data, direction="client")
        assert result is not None
        assert result.kex_algorithms == ["curve25519-sha256", "diffie-hellman-group14-sha256"]

    def test_encryption_lists_populated(self):
        data = _build_kexinit(
            enc_c2s=["chacha20-poly1305@openssh.com"],
            enc_s2c=["aes256-gcm@openssh.com"],
        )
        result = extract_ja4ssh(data, direction="client")
        assert result is not None
        assert "chacha20-poly1305@openssh.com" in result.encryption_client_to_server


# ── Missing-coverage tests ────────────────────────────────────────────────────

class TestJA4SSHEdgeCases:
    """Cover boundary paths in _parse() and helpers (lines 47-48, 53, 72, 118, 122, 131).

    So what: every unchecked parse path is a crash vector when the SSH fingerprinter
    receives attacker-controlled bytes from the network capture pipeline.
    """

    def test_exception_in_parse_returns_none(self):
        """_parse() raising → None (lines 47-48).
        So what: an unexpected internal error must not crash the tap capture loop."""
        from unittest.mock import patch

        import src.tap.fingerprints.ja4ssh as _mod
        with patch.object(_mod, "_parse", side_effect=RuntimeError("injected")):
            result = _mod.extract_ja4ssh(_build_kexinit(), "client")
        assert result is None

    def test_empty_bytes_returns_none(self):
        """Empty input → None from _parse() (line 53).
        So what: zero-length payload arrives when the reassembler captures a
        truncated SSH banner; must not IndexError on data[0]."""
        result = extract_ja4ssh(b"", "client")
        assert result is None

    def test_truncated_after_cookie_returns_none(self):
        """Payload truncated mid-name-list → None (line 72).
        So what: a partial KEXINIT frame must not cause partial list construction
        that yields wrong algorithm counts in the fingerprint."""
        # 1 byte msg type + 16 byte cookie = 17 bytes — no room for any name-list
        data = bytes([0x14]) + b"\xaa" * 16
        result = extract_ja4ssh(data, "client")
        assert result is None

    def test_read_name_list_too_short_for_length_field(self):
        """_read_name_list() with < 4 bytes remaining → (None, pos) (line 118).
        So what: a crafted packet with a length field straddling a boundary must
        not cause struct.unpack_from to overread."""
        from src.tap.fingerprints.ja4ssh import _read_name_list
        data = b"\x00\x00"  # Only 2 bytes — too short for uint32
        result, pos = _read_name_list(data, 0)
        assert result is None

    def test_read_name_list_length_overruns_data(self):
        """_read_name_list() when stated length > available bytes → (None, pos) (line 122).
        So what: an oversized length field must not cause a slice overread that
        returns garbage algorithm names and corrupts the fingerprint."""
        from src.tap.fingerprints.ja4ssh import _read_name_list
        data = struct.pack("!I", 9999) + b"short"
        result, pos = _read_name_list(data, 0)
        assert result is None

    def test_hash12_empty_string_returns_zero_hash(self):
        """_hash12('') → '000000000000' (line 131).
        So what: an empty algorithm list must produce a deterministic zero hash
        rather than a SHA-256 of an empty string, ensuring cross-implementation
        fingerprint compatibility."""
        from src.tap.fingerprints.ja4ssh import _hash12
        assert _hash12("") == "000000000000"
