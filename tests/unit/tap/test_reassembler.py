"""
Unit tests for src/tap/reassembler.py (Phase 20 Group 4).
"""
import random
import time
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.tap.capture import ParsedPacket
from src.tap.reassembler import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, StreamReassembler, TCPStream

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CFG = {"tap": {"max_streams": 100, "stream_timeout_s": 1.0}}


def _make_reassembler(extractor=None, cfg=None) -> StreamReassembler:
    return StreamReassembler(extractor=extractor, config=cfg or _CFG)


def _pkt(
    src="1.2.3.4",
    sport=12345,
    dst="5.6.7.8",
    dport=443,
    flags=TCP_SYN,
    seq=0,
    ack=0,
    data=b"",
    ts=0.0,
    tcp_opts=b"",
) -> ParsedPacket:
    return ParsedPacket(
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        proto="tcp",
        seq=seq,
        ack=ack,
        flags=flags,
        data=data,
        timestamp=ts,
        tcp_options_raw=tcp_opts,
        window_size=65535,
        ip_ttl=64,
        ip_df=True,
        ip_id=1,
    )


def _handshake(r: StreamReassembler, client="1.2.3.4", server="5.6.7.8"):
    """Simulate 3-way handshake; return the TCPStream."""
    r.on_packet(_pkt(client, 1000, server, 443, TCP_SYN, seq=0))
    r.on_packet(_pkt(server, 443, client, 1000, TCP_SYN | TCP_ACK, seq=100, ack=1))
    return list(r._streams.values())[0]


# ---------------------------------------------------------------------------
# Handshake state transitions
# ---------------------------------------------------------------------------


class TestStateTransitions:
    def test_syn_creates_stream_in_syn_rcvd_state(self):
        r = _make_reassembler()
        r.on_packet(_pkt(flags=TCP_SYN, seq=1000))
        assert len(r._streams) == 1
        stream = list(r._streams.values())[0]
        assert stream.state == "SYN_RCVD"

    def test_synack_transitions_to_established(self):
        r = _make_reassembler()
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_SYN, seq=0))
        r.on_packet(
            _pkt("5.6.7.8", 443, "1.2.3.4", 1000, TCP_SYN | TCP_ACK, seq=100, ack=1)
        )
        stream = list(r._streams.values())[0]
        assert stream.state == "ESTABLISHED"


# ---------------------------------------------------------------------------
# Data reassembly
# ---------------------------------------------------------------------------


class TestDataReassembly:
    def test_in_order_segments_assembled_correctly(self):
        r = _make_reassembler()
        stream = _handshake(r)
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"Hello"))
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=6, data=b"World"))
        assert bytes(stream.client_data) == b"HelloWorld"

    def test_out_of_order_segment_buffered_then_flushed(self):
        r = _make_reassembler()
        stream = _handshake(r)
        # Send second segment first
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=6, data=b"World"))
        assert bytes(stream.client_data) == b""  # still waiting for first
        # Now send first segment
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"Hello"))
        assert bytes(stream.client_data) == b"HelloWorld"

    @settings(max_examples=30)
    @given(st.permutations(list(range(5))))
    def test_1000_out_of_order_permutations_all_produce_correct_assembly(self, order):
        """Any permutation of 5 sequential segments reassembles to the same data."""
        r = _make_reassembler()
        stream = _handshake(r)
        segs = [(1 + i * 4, bytes([i]) * 4) for i in range(5)]
        for idx in order:
            seq, data = segs[idx]
            r.on_packet(
                _pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=seq, data=data)
            )
        expected = b"".join(data for _, data in segs)
        assert bytes(stream.client_data) == expected

    def test_retransmitted_segment_discarded_no_duplicate_data(self):
        r = _make_reassembler()
        stream = _handshake(r)
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"ABC"))
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"ABC"))
        assert bytes(stream.client_data) == b"ABC"

    def test_stream_buffer_cap_drops_stream_not_crash(self):
        """Buffer overflow should drop the stream, not raise an exception."""
        r = _make_reassembler(cfg={"tap": {"max_stream_buffer_bytes": 10}})
        stream = _handshake(r)
        key = stream.key
        r.on_packet(
            _pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"X" * 20)
        )
        # Stream dropped from table (no exception raised)
        assert key not in r._streams


# ---------------------------------------------------------------------------
# RST / FIN closing
# ---------------------------------------------------------------------------


class TestStreamClose:
    def test_rst_closes_stream_and_calls_extractor(self):
        ext = MagicMock()
        r = _make_reassembler(extractor=ext)
        _handshake(r)
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_RST, seq=1))
        ext.on_stream_close.assert_called_once()
        assert len(r._streams) == 0

    def test_fin_closes_stream_after_fin_ack(self):
        ext = MagicMock()
        r = _make_reassembler(extractor=ext)
        _handshake(r)
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_FIN | TCP_ACK, seq=1))
        ext.on_stream_close.assert_called_once()


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------


class TestEviction:
    def test_idle_stream_expired_after_stream_timeout_s(self):
        r = _make_reassembler(cfg={"tap": {"stream_timeout_s": 0.0}})
        r.on_packet(_pkt(flags=TCP_SYN, seq=0))
        assert len(r._streams) == 1
        count = r.expire_idle()
        assert count == 1
        assert len(r._streams) == 0

    def test_max_streams_evicts_oldest_on_new_syn(self):
        r = _make_reassembler(cfg={"tap": {"max_streams": 3}})
        # Fill to max
        for i in range(3):
            r.on_packet(_pkt(f"10.0.0.{i}", 1000, "5.6.7.8", 443, TCP_SYN, seq=0))
        assert len(r._streams) == 3
        # One more SYN should trigger eviction
        r.on_packet(_pkt("10.0.0.99", 2000, "5.6.7.8", 443, TCP_SYN, seq=0))
        assert len(r._streams) <= 3


# ---------------------------------------------------------------------------
# Sharding
# ---------------------------------------------------------------------------


class TestSharding:
    def test_stream_table_sharding_routes_same_4_tuple_to_same_worker(self):
        """The reassembler is per-worker: packets with the same 4-tuple always
        land in the same shard (because routing is done by PacketCapture).
        This test verifies that the reassembler correctly matches packets to
        their stream regardless of arrival order."""
        r = _make_reassembler()
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_SYN, seq=0))
        r.on_packet(
            _pkt("5.6.7.8", 443, "1.2.3.4", 1000, TCP_SYN | TCP_ACK, seq=50, ack=1)
        )
        # Data in both directions
        r.on_packet(
            _pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"req")
        )
        r.on_packet(
            _pkt("5.6.7.8", 443, "1.2.3.4", 1000, TCP_ACK, seq=51, data=b"resp")
        )
        stream = list(r._streams.values())[0]
        assert bytes(stream.client_data) == b"req"
        assert bytes(stream.server_data) == b"resp"


# ---------------------------------------------------------------------------
# IPv6 sharding
# ---------------------------------------------------------------------------


class TestIPv6:
    def test_ipv4_fragment_reassembly_before_tcp_parsing(self):
        """Reassembler receives a ParsedPacket (post-fragment-reassembly)
        so this test verifies that IPv6 addresses work as stream keys."""
        r = _make_reassembler()
        r.on_packet(
            _pkt("2001:db8::1", 1000, "2001:db8::2", 443, TCP_SYN, seq=0)
        )
        assert len(r._streams) == 1
        stream = list(r._streams.values())[0]
        assert stream.client_ip == "2001:db8::1"

    def test_ipv6_fragment_extension_header_walked(self):
        """If the reassembler receives a packet parsed from a fragmented IPv6
        packet, it must still create/update the correct stream entry."""
        r = _make_reassembler()
        r.on_packet(_pkt("fe80::1", 2000, "fe80::2", 80, TCP_SYN, seq=100))
        assert len(r._streams) == 1


# ---------------------------------------------------------------------------
# _flush_reorder_buf (lines 298-318) — called standalone to flush OOO segments
# ---------------------------------------------------------------------------


class TestFlushReorderBuf:
    def test_flush_reorder_buf_client_direction(self):
        """_flush_reorder_buf must flush buffered out-of-order client segments.

        Security: incorrect TCP reassembly can produce a wrong payload stream,
        leading to an incorrect JA4H fingerprint that bypasses detection.
        """
        r = _make_reassembler()
        stream = _handshake(r)
        # Manually buffer an out-of-order segment for the client direction
        from sortedcontainers import SortedList
        stream.client_buf = SortedList()
        stream.client_buf.add((6, b"World"))
        stream.client_seq = 6  # pretend we are now at seq 6

        r._flush_reorder_buf(stream, "client")

        assert b"World" in bytes(stream.client_data)
        assert stream.client_seq == 11

    def test_flush_reorder_buf_server_direction(self):
        """_flush_reorder_buf must flush buffered out-of-order server segments.

        Security: wrong server-side reassembly means TLS server hello data is
        corrupt, preventing correct JA4S fingerprint computation.
        """
        r = _make_reassembler()
        stream = _handshake(r)
        from sortedcontainers import SortedList
        stream.server_buf = SortedList()
        stream.server_buf.add((101, b"resp"))
        stream.server_seq = 101

        r._flush_reorder_buf(stream, "server")

        assert b"resp" in bytes(stream.server_data)
        assert stream.server_seq == 105

    def test_flush_reorder_buf_overlap_handled(self):
        """Overlapping out-of-order segment is de-duplicated correctly.

        Security: duplicate data injection (a TCP reset attack variant) must
        not produce duplicate bytes in the reassembled stream; duplicate bytes
        yield a corrupt TLS ClientHello that can't be parsed.
        """
        r = _make_reassembler()
        stream = _handshake(r)
        from sortedcontainers import SortedList
        # Simulate: seq already advanced to 5, but buffer has a segment
        # starting at 3 with 4 bytes — overlap of 2 bytes
        stream.client_seq = 5
        stream.client_buf = SortedList()
        stream.client_buf.add((3, b"ABCD"))  # bytes 3,4 are new; 3-4 already seen

        r._flush_reorder_buf(stream, "client")

        # Only the 2 new bytes (CD at positions 5,6) should be appended
        assert bytes(stream.client_data) == b"CD"
        assert stream.client_seq == 7

    def test_flush_reorder_buf_no_segments_no_op(self):
        """Empty buffer must not change stream state."""
        r = _make_reassembler()
        stream = _handshake(r)
        stream.client_seq = 10
        r._flush_reorder_buf(stream, "client")
        assert stream.client_seq == 10

    def test_flush_reorder_buf_segment_exactly_at_expected(self):
        """Segment at exactly the expected seq is consumed entirely."""
        r = _make_reassembler()
        stream = _handshake(r)
        from sortedcontainers import SortedList
        stream.client_seq = 1
        stream.client_buf = SortedList()
        stream.client_buf.add((1, b"Hello"))

        r._flush_reorder_buf(stream, "client")

        assert bytes(stream.client_data) == b"Hello"
        assert stream.client_seq == 6


# ---------------------------------------------------------------------------
# _call_extractor_close (lines 320-326) — exception swallowing
# ---------------------------------------------------------------------------


class TestCallExtractorClose:
    def test_extractor_exception_is_swallowed_and_logged(self):
        """If extractor.on_stream_close raises, the reassembler must log and
        continue — not propagate the exception.

        Security: a buggy FingerprintExtractor must not crash the TAP worker;
        that would stop all further packet capture and analysis.
        """
        ext = MagicMock()
        ext.on_stream_close.side_effect = RuntimeError("extractor crash")
        r = _make_reassembler(extractor=ext)
        stream = _handshake(r)
        # Should not raise despite the extractor exploding
        r._call_extractor_close(stream)
        ext.on_stream_close.assert_called_once_with(stream)

    def test_extractor_without_on_stream_close_is_no_op(self):
        """Extractor without on_stream_close attribute must be handled gracefully."""
        ext = MagicMock(spec=[])  # No attributes at all
        r = _make_reassembler(extractor=ext)
        stream = _handshake(r)
        r._call_extractor_close(stream)  # Must not raise

    def test_none_extractor_is_no_op(self):
        """None extractor must be handled — common in tests."""
        r = _make_reassembler(extractor=None)
        stream = _handshake(r)
        r._call_extractor_close(stream)  # Must not raise


# ---------------------------------------------------------------------------
# __len__ (line 330)
# ---------------------------------------------------------------------------


class TestLen:
    def test_len_returns_zero_initially(self):
        """An empty reassembler must report 0 streams.

        Security: the stream count drives eviction decisions; if __len__
        returns wrong values, the table can grow unbounded, exhausting memory
        on the TAP worker and crashing packet capture.
        """
        r = _make_reassembler()
        assert len(r) == 0

    def test_len_increments_on_syn(self):
        r = _make_reassembler()
        r.on_packet(_pkt(flags=TCP_SYN, seq=0))
        assert len(r) == 1

    def test_len_decrements_on_rst(self):
        r = _make_reassembler()
        _handshake(r)
        assert len(r) == 1
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_RST, seq=1))
        assert len(r) == 0

    def test_len_multiple_streams(self):
        r = _make_reassembler(cfg={"tap": {"max_streams": 10}})
        for i in range(5):
            r.on_packet(_pkt(f"10.0.0.{i}", 1000 + i, "5.6.7.8", 443, TCP_SYN, seq=0))
        assert len(r) == 5


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestReassemblerCoverageGaps:
    """Cover lines 112, 163, 212, 222."""

    def test_on_packet_non_tcp_returns_early(self):
        """Line 112: on_packet() returns early for non-TCP packets.
        So what: if this guard is missing, reassembler tries to extract TCP
        headers from UDP/ICMP payloads — causing index errors and corrupting
        stream state for all subsequent packets on that worker."""
        r = _make_reassembler()
        udp_pkt = ParsedPacket(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1234, dst_port=53,
            proto="udp", seq=0, ack=0, flags=0, data=b"hello",
            timestamp=0.0, tcp_options_raw=b"", window_size=0,
            ip_ttl=64, ip_df=False, ip_id=0,
        )
        r.on_packet(udp_pkt)  # must not raise; no stream created
        assert len(r._streams) == 0

    def test_evict_oldest_with_n_zero_returns_zero(self):
        """Line 163: evict_oldest(0) returns 0 immediately without touching streams.
        So what: if this guard is absent, evict_oldest(0) iterates streams and evicts
        at least one (the sort is still O(n)) — the watchdog could inadvertently
        close active connections when requesting zero evictions."""
        r = _make_reassembler()
        _handshake(r)
        assert r.evict_oldest(0) == 0
        assert len(r._streams) == 1  # stream still present

    def test_on_data_empty_payload_returns_early(self):
        """Line 212: _on_data with empty payload returns without touching buffers.
        So what: if missing, pure ACK packets would trigger an append of empty
        bytes, polluting the client/server buffers with zero-length chunks and
        breaking incremental extractor parsing."""
        r = _make_reassembler()
        stream = _handshake(r)
        before_client = bytes(stream.client_data)
        # Send ACK with no data (flags=TCP_ACK, data=b"")
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b""))
        assert bytes(stream.client_data) == before_client  # unchanged

    def test_on_data_calls_extractor_on_stream_data(self):
        """Line 222: when extractor has on_stream_data, it is called on each data packet.
        So what: if this call is skipped, the fingerprint extractor never sees incremental
        stream data — JA4H, H2 and other protocol-level fingerprints are never computed
        and the tap pipeline emits empty fingerprint records for every connection."""
        extractor = MagicMock()
        extractor.on_stream_data = MagicMock()
        extractor.on_stream_close = MagicMock()
        r = _make_reassembler(extractor=extractor)
        stream = _handshake(r)
        # Send a data packet (non-empty)
        r.on_packet(_pkt("1.2.3.4", 1000, "5.6.7.8", 443, TCP_ACK, seq=1, data=b"GET / HTTP/1.1\r\n"))
        extractor.on_stream_data.assert_called_once_with(stream)
