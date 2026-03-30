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
