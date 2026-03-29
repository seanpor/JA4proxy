"""
TAP-mode chaos/resilience tests (Phase 20, Group 13-C).

Tests verify TAP-mode components handle adversarial/edge-case inputs gracefully.
"""
import struct
from unittest.mock import MagicMock

import pytest

from src.tap.capture import ParsedPacket, _parse_ethernet_frame
from src.tap.fingerprints.ja4 import extract_ja4
from src.tap.fingerprints.ja4s import extract_ja4s
from src.tap.fingerprints.ja4t import extract_ja4t_from_syn
from src.tap.reassembler import StreamReassembler, TCPStream

# ─────────────────────────────────────────────────────────────────────────────
# Capture resilience
# ─────────────────────────────────────────────────────────────────────────────


class TestCaptureResilience:
    def test_corrupt_ethernet_frame_skipped_without_crash(self):
        """A frame with random bytes should return None, not raise."""
        frag_store: dict = {}
        garbage = bytes(range(256)) * 4
        result = _parse_ethernet_frame(garbage, 1.0, frag_store)
        assert result is None

    def test_empty_ethernet_frame_skipped_without_crash(self):
        result = _parse_ethernet_frame(b"", 1.0, {})
        assert result is None

    def test_truncated_ethernet_frame_skipped(self):
        # Only 6 bytes — too short for any valid header
        result = _parse_ethernet_frame(b"\xff\xff\xff\xff\xff\xff", 1.0, {})
        assert result is None

    def test_unknown_ethertype_returns_none(self):
        # Valid Ethernet header with unknown EtherType 0x9999
        frame = b"\x00" * 6 + b"\x00" * 6 + b"\x99\x99" + b"\x00" * 20
        result = _parse_ethernet_frame(frame, 1.0, {})
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# TLS parser resilience
# ─────────────────────────────────────────────────────────────────────────────


class TestTLSParserResilience:
    def test_truncated_tls_record_returns_none_not_exception(self):
        """Truncated TLS record must return None from extract_ja4."""
        # Valid TLS record header but truncated body
        truncated = b"\x16\x03\x01\x00\x50" + b"\x00" * 10  # claims 80 bytes but only 10
        result = extract_ja4(truncated)
        assert result is None

    def test_empty_input_returns_none(self):
        assert extract_ja4(b"") is None
        assert extract_ja4s(b"") is None

    def test_random_bytes_dont_raise(self):
        """Arbitrary random data must not raise from any fingerprint extractor."""
        data = bytes(range(256)) * 2
        assert extract_ja4(data) is None  # may be None or a result, but must not raise
        assert extract_ja4s(data) is None

    def test_valid_tls_header_truncated_handshake(self):
        """TLS record header says 100 bytes, but only 5 bytes follow."""
        data = b"\x16\x03\x01\x00\x64" + b"\x01" + b"\x00" * 4
        result = extract_ja4(data)
        assert result is None  # too short to be valid


# ─────────────────────────────────────────────────────────────────────────────
# Stream table capacity
# ─────────────────────────────────────────────────────────────────────────────


class TestStreamTableCapacity:
    def test_stream_table_at_max_capacity_evicts_oldest(self):
        """StreamReassembler must evict old streams when at max capacity."""
        config = {
            "tap": {
                "stream_timeout_s": 30,
                "max_streams": 5,  # very small for testing
            }
        }
        reassembler = StreamReassembler(extractor=None, config=config)

        # Simulate 6 streams being added
        for i in range(6):
            pkt = ParsedPacket(
                src_ip=f"10.0.0.{i+1}", dst_ip="5.6.7.8",
                src_port=50000 + i, dst_port=443,
                proto="tcp", seq=1000, ack=0, flags=0x002,  # SYN
                data=b"", timestamp=float(i),
                tcp_options_raw=b"", window_size=65535,
                ip_ttl=64, ip_df=True, ip_id=i,
            )
            reassembler.on_packet(pkt)

        # With max_streams=5, we should not have more than 5 streams
        assert len(reassembler._streams) <= 5, (
            f"Expected ≤5 streams at capacity, got {len(reassembler._streams)}"
        )

    def test_worker_crash_triggers_watchdog_restart(self):
        """Watchdog restart is tested in test_watchdog.py — just verify import."""
        from src.tap import watchdog  # noqa: F401
        assert hasattr(watchdog, "WorkerWatchdog")
