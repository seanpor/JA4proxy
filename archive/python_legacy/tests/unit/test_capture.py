"""
Unit tests for src/tap/capture.py (Phase 20 Group 3).

Uses PcapReplay and synthetic Ethernet frames — no live AF_PACKET socket required.
"""

import asyncio
import socket as _socket
import struct
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config.loader import ConfigError
from src.tap.capture import (
    ETH_P_8021AD,
    ETH_P_8021Q,
    ETH_P_8021Q_ALT,
    ETH_P_IP,
    ETH_P_IPV6,
    GENEVE_PORT,
    IPPROTO_FRAGMENT,
    VXLAN_PORT,
    PacketCapture,
    ParsedPacket,
    PcapReplay,
    _parse_ethernet_frame,
    _parse_ipv4,
    _parse_ipv6,
    _parse_tcp,
    _parse_udp,
    _try_vxlan_or_geneve,
)

# ---------------------------------------------------------------------------
# Frame-builder helpers
# ---------------------------------------------------------------------------

_ZERO_MAC = b"\x00" * 6
_TS = 1_700_000_000.0


def _eth_hdr(ethertype: int) -> bytes:
    return _ZERO_MAC + _ZERO_MAC + struct.pack("!H", ethertype)


def _ipv4_hdr(
    proto: int,
    src: str = "1.2.3.4",
    dst: str = "5.6.7.8",
    ttl: int = 64,
    df: bool = False,
    ip_id: int = 0x1234,
    frag_offset: int = 0,
    more_frags: bool = False,
) -> bytes:
    # IHL=5, DSCP=0, TOS=0, total_length filled later
    flags = (0x4000 if df else 0) | (0x2000 if more_frags else 0)
    flags_frag = flags | (frag_offset // 8)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # ver=4, ihl=5
        0,  # DSCP/ECN
        0,  # total_length (not used by parser)
        ip_id,
        flags_frag,
        ttl,
        proto,
        0,  # checksum
        _socket.inet_aton(src),
        _socket.inet_aton(dst),
    )
    return hdr


def _tcp_hdr(
    sport: int = 12345,
    dport: int = 443,
    seq: int = 100,
    ack: int = 0,
    flags: int = 0x002,  # SYN
    window: int = 65535,
    options: bytes = b"",
) -> bytes:
    # Pad options to 4-byte boundary
    options = options.ljust((len(options) + 3) // 4 * 4, b"\x00")
    # data_offset in 32-bit words: base TCP header is 20 bytes = 5 words
    data_offset = 5 + len(options) // 4
    dof_flags = (data_offset << 12) | (flags & 0x1FF)
    # TCP header: sport, dport, seq, ack, data_offset+flags, window, checksum, urgent
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, dof_flags, window, 0, 0)
    return hdr + options


def _udp_hdr(sport: int = 54321, dport: int = 80) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8, 0)


def _build_ipv4_tcp(
    src: str = "1.2.3.4",
    dst: str = "5.6.7.8",
    sport: int = 12345,
    dport: int = 443,
    seq: int = 100,
    ack: int = 200,
    flags: int = 0x002,
    options: bytes = b"",
    payload: bytes = b"",
    ttl: int = 64,
    df: bool = True,
    ip_id: int = 0x1234,
) -> bytes:
    tcp = _tcp_hdr(sport, dport, seq, ack, flags, 65535, options) + payload
    ip = _ipv4_hdr(6, src, dst, ttl=ttl, df=df, ip_id=ip_id)
    eth = _eth_hdr(ETH_P_IP)
    return eth + ip + tcp


def _build_ipv4_udp(
    src: str = "1.2.3.4",
    dst: str = "5.6.7.8",
    sport: int = 54321,
    dport: int = 53,
    payload: bytes = b"\x00" * 4,
) -> bytes:
    udp = _udp_hdr(sport, dport) + payload
    ip = _ipv4_hdr(17, src, dst)
    eth = _eth_hdr(ETH_P_IP)
    return eth + ip + udp


def _build_ipv6_tcp(
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    sport: int = 12345,
    dport: int = 443,
) -> bytes:
    tcp = _tcp_hdr(sport, dport, seq=1, ack=0)
    # IPv6 header: version(4)=6, TC(8)=0, FL(20)=0, payload_len(16), next_hdr(8), hop_limit(8), src(128), dst(128)
    src_b = _socket.inet_pton(_socket.AF_INET6, src)
    dst_b = _socket.inet_pton(_socket.AF_INET6, dst)
    ip6 = struct.pack("!IHBB", 0x60000000, len(tcp), 6, 64) + src_b + dst_b
    eth = _eth_hdr(ETH_P_IPV6)
    return eth + ip6 + tcp


# ---------------------------------------------------------------------------
# Plain Ethernet / VLAN tests
# ---------------------------------------------------------------------------


class TestFrameParsing:
    def test_parse_plain_ethernet_ipv4_tcp(self):
        frame = _build_ipv4_tcp(src="1.2.3.4", dst="5.6.7.8", sport=11111, dport=443)
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.src_ip == "1.2.3.4"
        assert pkt.dst_ip == "5.6.7.8"
        assert pkt.src_port == 11111
        assert pkt.dst_port == 443
        assert pkt.proto == "tcp"

    def test_parse_802_1q_vlan_tag_stripped(self):
        # Insert a 4-byte 802.1q tag before the ethertype
        base = _build_ipv4_tcp()
        # base[12:14] = ETH_P_IP — insert VLAN tag before it
        frame = base[:12] + struct.pack("!HH", ETH_P_8021Q, 0x0001) + base[12:]
        # Now ethertype at offset 12 is 0x8100; inner ethertype at 16 is 0x0800
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "tcp"

    def test_parse_qinq_double_tag_stripped(self):
        base = _build_ipv4_tcp()
        # Double tag: outer 0x88a8, inner 0x8100, then 0x0800
        frame = (
            base[:12]
            + struct.pack("!HH", ETH_P_8021AD, 0x0001)
            + struct.pack("!HH", ETH_P_8021Q, 0x0001)
            + base[12:]
        )
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "tcp"

    def test_parse_vxlan_encapsulated_ipv4(self):
        # Inner: Ethernet + IPv4 + TCP
        inner = _build_ipv4_tcp(src="10.0.0.1", dst="10.0.0.2", sport=55555, dport=80)
        # VxLAN header: 8 bytes (flags + vni)
        vxlan_hdr = struct.pack("!II", 0x08000000, 100 << 8)
        # Outer UDP header pointing to VxLAN port
        outer_udp = struct.pack("!HHHH", 12345, VXLAN_PORT, 8 + 8 + len(inner), 0)
        outer_payload = outer_udp + vxlan_hdr + inner
        outer_ip = _ipv4_hdr(17, src="192.168.1.1", dst="192.168.1.2")
        frame = _eth_hdr(ETH_P_IP) + outer_ip + outer_payload
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_port == 80

    def test_parse_geneve_encapsulated_ipv4(self):
        inner = _build_ipv4_tcp(src="10.1.0.1", dst="10.1.0.2", sport=44444, dport=443)
        # GENEVE header: 4-byte fixed (opt_len=0) + 0 option bytes
        geneve_hdr = struct.pack(
            "!BBH", 0x00, 0x00, 0x6558
        )  # opt_len=0, proto=Ethernet
        outer_udp = struct.pack("!HHHH", 12345, GENEVE_PORT, 8 + 4 + len(inner), 0)
        outer_payload = outer_udp + geneve_hdr + inner
        outer_ip = _ipv4_hdr(17, src="192.168.2.1", dst="192.168.2.2")
        frame = _eth_hdr(ETH_P_IP) + outer_ip + outer_payload
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.src_ip == "10.1.0.1"
        assert pkt.dst_port == 443

    def test_parse_ipv6_tcp(self):
        frame = _build_ipv6_tcp(
            src="2001:db8::1", dst="2001:db8::2", sport=33333, dport=443
        )
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.src_ip == "2001:db8::1"
        assert pkt.dst_ip == "2001:db8::2"
        assert pkt.src_port == 33333
        assert pkt.proto == "tcp"

    def test_parse_ipv4_fragment_first_and_last(self):
        """First fragment → None; last fragment → assembled ParsedPacket."""
        frag_store: dict = {}
        tcp = _tcp_hdr(sport=5000, dport=80, seq=1, ack=0, flags=0x002)

        # First fragment (MF=1, offset=0) — TCP header only, no payload after
        ip_frag1 = _ipv4_hdr(
            proto=6,
            src="1.1.1.1",
            dst="2.2.2.2",
            ip_id=0xABCD,
            frag_offset=0,
            more_frags=True,
        )
        frame1 = _eth_hdr(ETH_P_IP) + ip_frag1 + tcp
        result1 = _parse_ethernet_frame(memoryview(frame1), _TS, frag_store)
        assert result1 is None  # Not yet complete

        # Last fragment (MF=0, offset=len(tcp))
        ip_frag2 = _ipv4_hdr(
            proto=6,
            src="1.1.1.1",
            dst="2.2.2.2",
            ip_id=0xABCD,
            frag_offset=len(tcp),
            more_frags=False,
        )
        extra_payload = b"hello"
        frame2 = _eth_hdr(ETH_P_IP) + ip_frag2 + extra_payload
        result2 = _parse_ethernet_frame(memoryview(frame2), _TS, frag_store)
        assert result2 is not None  # Reassembled
        assert result2.proto == "tcp"

    def test_parse_truncated_ethernet_frame_returns_none(self):
        frame = b"\x00\x01\x02"  # too short
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_parse_unknown_ethertype_returns_none(self):
        frame = _eth_hdr(0x1234)  # 14 bytes, unknown ethertype
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None


# ---------------------------------------------------------------------------
# Dedup tests
# ---------------------------------------------------------------------------


class TestDedup:
    def _make_capture(self, dedup_window: float = 1.0) -> PacketCapture:
        return PacketCapture(
            config={"tap": {"interface": "lo", "dedup_window_s": dedup_window}},
            workers=[],
        )

    def test_dedup_filters_identical_packet_within_window(self):
        cap = self._make_capture(dedup_window=60.0)
        pkt = ParsedPacket(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=2,
            proto="tcp",
            seq=10,
            ack=0,
            flags=2,
            data=b"hello",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=65535,
            ip_ttl=64,
            ip_df=True,
            ip_id=1,
        )
        first = cap._dedup_check(pkt)
        second = cap._dedup_check(pkt)
        assert first is False  # first time: not a duplicate
        assert second is True  # second time: duplicate

    def test_dedup_allows_identical_packet_after_window_expires(self):
        cap = self._make_capture(dedup_window=0.0)  # expires immediately
        pkt = ParsedPacket(
            src_ip="3.3.3.3",
            dst_ip="4.4.4.4",
            src_port=10,
            dst_port=20,
            proto="tcp",
            seq=99,
            ack=0,
            flags=2,
            data=b"x",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=8192,
            ip_ttl=64,
            ip_df=False,
            ip_id=5,
        )
        cap._dedup_check(pkt)
        # After a 0-second window, the entry immediately expires
        result = cap._dedup_check(pkt)
        assert result is False  # allowed again after expiry


# ---------------------------------------------------------------------------
# BPF filter test
# ---------------------------------------------------------------------------


class TestBpfFilter:
    def test_bpf_filter_compilation_error_raises_config_error(self):
        cap = PacketCapture(
            config={"tap": {"interface": "lo"}},
            workers=[],
        )
        mock_sock = MagicMock()
        with pytest.raises(ConfigError, match="Invalid BPF filter"):
            cap._set_bpf_filter(mock_sock, "not_valid[[[")


# ---------------------------------------------------------------------------
# Dispatch / sharding tests
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_dispatch_same_stream_always_goes_to_same_worker(self):
        """Packets sharing a 4-tuple always route to the same worker shard."""
        workers = [MagicMock() for _ in range(4)]
        cap = PacketCapture(
            config={"tap": {"interface": "lo"}},
            workers=workers,
        )
        # 5 packets with the same 4-tuple but different seq numbers (realistic TCP)
        frames = [
            _build_ipv4_tcp(
                src="1.2.3.4",
                dst="5.6.7.8",
                sport=9000,
                dport=443,
                seq=i * 1000,
                payload=bytes([i]) * 10,
            )
            for i in range(1, 6)
        ]
        for frame in frames:
            cap._dispatch(memoryview(frame))

        called = [i for i, w in enumerate(workers) if w.on_packet.called]
        assert len(called) == 1  # only one worker received packets

        total_calls = sum(w.on_packet.call_count for w in workers)
        assert total_calls == 5


# ---------------------------------------------------------------------------
# PcapReplay tests
# ---------------------------------------------------------------------------


class TestPcapReplay:
    def _write_pcap(self, frames: list[bytes], tmp_path: Path) -> Path:
        """Write raw Ethernet frames into a PCAP file using scapy."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]
        from scapy.packet import Raw  # type: ignore[import]

        pcap_path = tmp_path / "test.pcap"
        pkts = [Ether(f) for f in frames]
        wrpcap(str(pcap_path), pkts)
        return pcap_path

    @pytest.mark.asyncio
    async def test_pcap_replay_emits_all_packets_from_file(self, tmp_path):
        frame1 = _build_ipv4_tcp(src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=443)
        frame2 = _build_ipv4_tcp(src="10.0.0.3", dst="10.0.0.4", sport=2000, dport=80)
        pcap = self._write_pcap([frame1, frame2], tmp_path)

        received = []

        class MockWorker:
            def on_packet(self, pkt):
                received.append(pkt)

        replay = PcapReplay(pcap, [MockWorker()], realtime=False)
        await replay.start()
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_pcap_replay_fast_mode_no_inter_packet_delay(self, tmp_path):
        """Fast mode (realtime=False) must complete quickly even with big gaps."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]
        from scapy.packet import Packet  # type: ignore[import]

        frame = _build_ipv4_tcp(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=80)
        pcap_path = tmp_path / "gap.pcap"

        # Two packets 10 seconds apart
        pkt1 = Ether(frame)
        pkt1.time = 1_000_000.0
        pkt2 = Ether(frame)
        pkt2.time = 1_000_010.0  # 10s later
        wrpcap(str(pcap_path), [pkt1, pkt2])

        worker = MagicMock()
        replay = PcapReplay(pcap_path, [worker], realtime=False)
        start = time.monotonic()
        await replay.start()
        elapsed = time.monotonic() - start
        # Should complete in well under 1 second (no sleeps in fast mode)
        assert elapsed < 2.0


# ---------------------------------------------------------------------------
# _parse_ipv4 — direct edge-case tests
# ---------------------------------------------------------------------------


class TestParseIPv4Direct:
    def test_truncated_ipv4_header_returns_none(self):
        """Buffer too short to hold a full IPv4 header."""
        buf = _eth_hdr(ETH_P_IP) + b"\x00" * 10  # only 10 bytes of IP header
        result = _parse_ipv4(buf, 14, _TS, {})
        assert result is None

    def test_invalid_ihl_less_than_20_returns_none(self):
        """IHL=3 means 12-byte header — invalid (must be >= 5 words = 20 bytes)."""
        # Byte 0 of IP header: version=4, ihl=3 → 12 bytes — invalid
        bad_hdr = bytes([0x43]) + b"\x00" * 19  # ver=4, ihl=3
        buf = _eth_hdr(ETH_P_IP) + bad_hdr + b"\x00" * 20
        result = _parse_ipv4(buf, 14, _TS, {})
        assert result is None

    def test_ihl_truncated_beyond_buffer_returns_none(self):
        """IHL claims 60 bytes but buffer only has 30 bytes."""
        # Byte 0: version=4, ihl=15 (60 bytes) but provide only 30 bytes
        bad_hdr = bytes([0x4F]) + b"\x00" * 29  # ihl=15=60 bytes, but short
        buf = _eth_hdr(ETH_P_IP) + bad_hdr
        result = _parse_ipv4(buf, 14, _TS, {})
        assert result is None

    def test_unknown_protocol_returns_none(self):
        """Proto=0xFF — not TCP or UDP → must return None."""
        tcp_like = _tcp_hdr() + b"data"
        ip = _ipv4_hdr(0xFF)  # proto=255
        frame = _eth_hdr(ETH_P_IP) + ip + tcp_like
        result = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert result is None

    def test_udp_non_tunnel_port_parsed_as_udp(self):
        """UDP to port 53 (DNS) — not a tunnel — must be parsed as UDP."""
        frame = _build_ipv4_udp(sport=12345, dport=53, payload=b"\xca\xfe" * 4)
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "udp"
        assert pkt.dst_port == 53


# ---------------------------------------------------------------------------
# _parse_tcp — direct edge-case tests
# ---------------------------------------------------------------------------


class TestParseTcpDirect:
    def test_truncated_tcp_header_returns_none(self):
        """Payload less than 20 bytes — cannot be a valid TCP header."""
        result = _parse_tcp(b"\x00" * 15, "1.1.1.1", "2.2.2.2", _TS, 64, True, 0)
        assert result is None

    def test_data_offset_less_than_20_returns_none(self):
        """data_offset=4 (16 bytes) is less than the minimum 20 — invalid."""
        dof_flags = (4 << 12) | 0x002
        payload = struct.pack("!HHIIHHHH", 1234, 80, 0, 0, dof_flags, 65535, 0, 0)
        payload += b"\x00" * 20  # padding
        result = _parse_tcp(payload, "1.1.1.1", "2.2.2.2", _TS, 64, True, 0)
        assert result is None

    def test_data_offset_beyond_payload_returns_none(self):
        """data_offset points past end of payload — invalid."""
        # Set data_offset=15 (60 bytes) but payload is only 20 bytes
        dof_flags = (15 << 12) | 0x002
        payload = struct.pack("!HHIIHHHH", 1234, 80, 0, 0, dof_flags, 65535, 0, 0)
        result = _parse_tcp(payload, "1.1.1.1", "2.2.2.2", _TS, 64, True, 0)
        assert result is None

    def test_valid_tcp_with_options(self):
        """TCP header with 4 bytes of options must be parsed correctly."""
        options = b"\x02\x04\x05\xb4"  # MSS option: kind=2, len=4, val=1460
        pkt = _tcp_hdr(sport=9999, dport=443, options=options)
        result = _parse_tcp(pkt, "1.1.1.1", "2.2.2.2", _TS, 64, False, 0)
        assert result is not None
        assert result.src_port == 9999
        assert result.tcp_options_raw == options


# ---------------------------------------------------------------------------
# _parse_udp — direct tests
# ---------------------------------------------------------------------------


class TestParseUdpDirect:
    def test_truncated_udp_header_returns_none(self):
        result = _parse_udp(b"\x00" * 5, "1.1.1.1", "2.2.2.2", _TS, 64, False, 0)
        assert result is None

    def test_valid_udp_parsed(self):
        payload = _udp_hdr(sport=54321, dport=53) + b"\xde\xad\xbe\xef"
        result = _parse_udp(payload, "1.1.1.1", "2.2.2.2", _TS, 64, False, 0)
        assert result is not None
        assert result.proto == "udp"
        assert result.src_port == 54321
        assert result.dst_port == 53
        assert result.data == b"\xde\xad\xbe\xef"
        assert result.seq == 0
        assert result.flags == 0


# ---------------------------------------------------------------------------
# _try_vxlan_or_geneve — direct edge-case tests
# ---------------------------------------------------------------------------


class TestTryVxlanOrGeneve:
    def test_too_short_udp_payload_returns_none(self):
        result = _try_vxlan_or_geneve(b"", b"\x00" * 4, _TS, {}, 64, False, 0)
        assert result is None

    def test_vxlan_inner_too_short_returns_none(self):
        """VxLAN UDP data is < 8 bytes — inner frame header is truncated."""
        udp_hdr = struct.pack("!HHHH", 12345, VXLAN_PORT, 8 + 7, 0)
        udp_data = udp_hdr + b"\x00" * 7  # only 7 bytes after UDP header
        result = _try_vxlan_or_geneve(b"", udp_data, _TS, {}, 64, False, 0)
        assert result is None

    def test_geneve_inner_too_short_returns_none(self):
        """GENEVE UDP data is < 4 bytes — cannot read opt_len."""
        udp_hdr = struct.pack("!HHHH", 12345, GENEVE_PORT, 8 + 3, 0)
        udp_data = udp_hdr + b"\x00" * 3  # only 3 bytes, need >= 4
        result = _try_vxlan_or_geneve(b"", udp_data, _TS, {}, 64, False, 0)
        assert result is None

    def test_non_tunnel_port_returns_none(self):
        """UDP to port 9999 — neither VxLAN nor GENEVE — must return None."""
        udp_hdr = struct.pack("!HHHH", 12345, 9999, 12, 0)
        udp_data = udp_hdr + b"\x00" * 20
        result = _try_vxlan_or_geneve(b"", udp_data, _TS, {}, 64, False, 0)
        assert result is None


# ---------------------------------------------------------------------------
# _parse_ipv6 — direct edge-case tests
# ---------------------------------------------------------------------------


def _build_ipv6_udp(
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    sport: int = 54321,
    dport: int = 53,
) -> bytes:
    udp = _udp_hdr(sport, dport) + b"\xca\xfe" * 4
    src_b = _socket.inet_pton(_socket.AF_INET6, src)
    dst_b = _socket.inet_pton(_socket.AF_INET6, dst)
    ip6 = struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src_b + dst_b
    return _eth_hdr(ETH_P_IPV6) + ip6 + udp


class TestParseIPv6Direct:
    def test_truncated_ipv6_header_returns_none(self):
        """Buffer too short for a full IPv6 header (need 40 bytes)."""
        short_ip6 = b"\x60" + b"\x00" * 20  # only 21 bytes of IP6 header
        frame = _eth_hdr(ETH_P_IPV6) + short_ip6
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_parse_ipv6_udp(self):
        frame = _build_ipv6_udp(sport=9999, dport=53)
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "udp"
        assert pkt.src_port == 9999

    def test_parse_ipv6_with_hop_by_hop_extension_header(self):
        """IPv6 with a Hop-by-Hop extension header (next_hdr=0) before TCP."""
        tcp = _tcp_hdr(sport=1234, dport=443)
        # Hop-by-Hop: next_hdr=6(TCP), length_field=0 → ext_len=(0+1)*8=8
        hop_by_hop = struct.pack("!BB", 6, 0) + b"\x00" * 6  # next=TCP, len=0
        src_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::2")
        # next_hdr=0 (Hop-by-Hop) in IPv6 base header
        ip6 = (
            struct.pack("!IHBB", 0x60000000, len(hop_by_hop) + len(tcp), 0, 64)
            + src_b
            + dst_b
        )
        frame = _eth_hdr(ETH_P_IPV6) + ip6 + hop_by_hop + tcp
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "tcp"
        assert pkt.src_port == 1234

    def test_parse_ipv6_hop_by_hop_truncated_returns_none(self):
        """Hop-by-Hop header where payload too short to read ext_len."""
        src_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::2")
        # Only 1 byte of extension header — need at least 2 to read length
        hop_by_hop = b"\x06"  # just next_hdr byte, no length byte
        ip6 = struct.pack("!IHBB", 0x60000000, len(hop_by_hop), 0, 64) + src_b + dst_b
        frame = _eth_hdr(ETH_P_IPV6) + ip6 + hop_by_hop
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_parse_ipv6_hop_by_hop_ext_len_beyond_payload_returns_none(self):
        """Hop-by-Hop claims ext_len > remaining payload — truncated."""
        src_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "2001:db8::2")
        # len_field=10 → ext_len=(10+1)*8=88 bytes, but payload is only 4 bytes
        hop_by_hop = struct.pack("!BB", 6, 10) + b"\x00" * 2
        ip6 = struct.pack("!IHBB", 0x60000000, len(hop_by_hop), 0, 64) + src_b + dst_b
        frame = _eth_hdr(ETH_P_IPV6) + ip6 + hop_by_hop
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_parse_ipv6_fragment_header_skipped(self):
        """IPv6 fragment extension header (next=44) — skip 8 bytes and parse TCP."""
        tcp = _tcp_hdr(sport=7777, dport=80)
        # Fragment header: next_hdr=6(TCP), reserved=0, frag_offset+flags=0, id=0
        frag_hdr = struct.pack("!BBHI", 6, 0, 0, 0)  # 8 bytes
        src_b = _socket.inet_pton(_socket.AF_INET6, "::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "::2")
        # next_hdr=44 (Fragment) in IPv6 base header
        ip6 = (
            struct.pack("!IHBB", 0x60000000, len(frag_hdr) + len(tcp), 44, 64)
            + src_b
            + dst_b
        )
        frame = _eth_hdr(ETH_P_IPV6) + ip6 + frag_hdr + tcp
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "tcp"
        assert pkt.src_port == 7777

    def test_parse_ipv6_fragment_header_too_short_returns_none(self):
        """IPv6 fragment header with < 8 bytes in payload."""
        src_b = _socket.inet_pton(_socket.AF_INET6, "::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "::2")
        frag_short = b"\x06\x00\x00"  # only 3 bytes, need 8
        ip6 = struct.pack("!IHBB", 0x60000000, len(frag_short), 44, 64) + src_b + dst_b
        frame = _eth_hdr(ETH_P_IPV6) + ip6 + frag_short
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_parse_ipv6_unrecognised_next_hdr_stops_walking(self):
        """Unknown extension header type — stop walking, not TCP/UDP → return None."""
        src_b = _socket.inet_pton(_socket.AF_INET6, "::1")
        dst_b = _socket.inet_pton(_socket.AF_INET6, "::2")
        # next_hdr=59 (No Next Header) — unrecognized, should break loop → None
        ip6 = struct.pack("!IHBB", 0x60000000, 0, 59, 64) + src_b + dst_b
        frame = _eth_hdr(ETH_P_IPV6) + ip6
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None


# ---------------------------------------------------------------------------
# PacketCapture lifecycle — mocked socket
# ---------------------------------------------------------------------------


class TestPacketCaptureLifecycle:
    def _make_capture(self, workers=None) -> PacketCapture:
        return PacketCapture(
            config={"tap": {"interface": "lo", "bpf_filter": "tcp"}},
            workers=workers or [],
        )

    @pytest.mark.asyncio
    async def test_start_raises_config_error_on_socket_error(self):
        """_setup_socket raising OSError must be wrapped in ConfigError."""
        cap = self._make_capture()
        with patch.object(cap, "_setup_socket", side_effect=OSError("EPERM")):
            with pytest.raises(ConfigError, match="Cannot bind AF_PACKET socket"):
                await cap.start()

    @pytest.mark.asyncio
    async def test_stop_closes_socket_and_sets_flag(self):
        """stop() must close the socket and set _stop=True."""
        cap = self._make_capture()
        mock_sock = MagicMock()
        cap._sock = mock_sock
        cap._stop = False
        await cap.stop()
        assert cap._stop is True
        mock_sock.close.assert_called_once()
        assert cap._sock is None

    @pytest.mark.asyncio
    async def test_stop_when_no_socket_is_safe(self):
        """stop() with _sock=None must not raise."""
        cap = self._make_capture()
        cap._sock = None
        await cap.stop()
        assert cap._stop is True

    @pytest.mark.asyncio
    async def test_start_sets_stop_false_and_calls_executor(self):
        """start() must set _stop=False and schedule the reader thread."""
        cap = self._make_capture()
        mock_sock = MagicMock()
        fut = asyncio.get_event_loop().create_future()
        fut.set_result(None)
        mock_loop = MagicMock()
        mock_loop.run_in_executor.return_value = fut
        with patch.object(cap, "_setup_socket", return_value=mock_sock), patch.object(
            cap, "_set_bpf_filter"
        ), patch("src.tap.capture.asyncio.get_running_loop", return_value=mock_loop):
            cap._stop = True
            await cap.start()
        assert cap._stop is False
        assert cap._sock is mock_sock
        mock_loop.run_in_executor.assert_called_once()


# ---------------------------------------------------------------------------
# PacketCapture._setup_socket
# ---------------------------------------------------------------------------


class TestSetupSocket:
    def test_setup_socket_binds_to_interface(self):
        """_setup_socket must bind to the configured interface."""
        cap = PacketCapture(
            config={"tap": {"interface": "lo"}},
            workers=[],
        )
        mock_sock = MagicMock()
        # The method does 'import socket as _socket' locally, so patch socket.socket
        with patch("socket.socket", return_value=mock_sock):
            result = cap._setup_socket()
        mock_sock.bind.assert_called_once_with(("lo", 0))
        assert result is mock_sock


# ---------------------------------------------------------------------------
# PacketCapture._poll_ring — reader thread
# ---------------------------------------------------------------------------


class TestPollRing:
    def test_poll_ring_exits_when_stop_set(self):
        """_poll_ring must exit immediately when _stop is True."""
        cap = PacketCapture(config={"tap": {}}, workers=[])
        cap._stop = True
        cap._sock = MagicMock()
        cap._poll_ring()
        cap._sock.recv.assert_not_called()

    def test_poll_ring_exits_on_os_error(self):
        """_poll_ring must exit cleanly on OSError (socket closed)."""
        cap = PacketCapture(config={"tap": {}}, workers=[])
        cap._stop = False
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("closed")
        cap._sock = mock_sock
        cap._poll_ring()
        mock_sock.recv.assert_called_once()

    def test_poll_ring_dispatches_valid_frame(self):
        """_poll_ring must call _dispatch for each received frame."""
        cap = PacketCapture(config={"tap": {}}, workers=[])
        cap._stop = False
        frame = _build_ipv4_tcp(src="1.2.3.4", dst="5.6.7.8", sport=1111, dport=443)
        call_count = [0]

        def fake_recv(size):
            call_count[0] += 1
            if call_count[0] == 1:
                return frame
            raise OSError("done")

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = fake_recv
        cap._sock = mock_sock

        dispatched = []

        def fake_dispatch(mv):
            dispatched.append(bytes(mv))

        cap._dispatch = fake_dispatch
        cap._poll_ring()
        assert len(dispatched) == 1


# ---------------------------------------------------------------------------
# PacketCapture._route_to_worker
# ---------------------------------------------------------------------------


class TestRouteToWorker:
    def _make_pkt(self) -> ParsedPacket:
        return ParsedPacket(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=2,
            proto="tcp",
            seq=0,
            ack=0,
            flags=2,
            data=b"",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=0,
            ip_ttl=64,
            ip_df=False,
            ip_id=0,
        )

    def test_no_workers_is_safe(self):
        """_route_to_worker with empty workers list must not raise."""
        cap = PacketCapture(config={"tap": {}}, workers=[])
        cap._route_to_worker(self._make_pkt())

    def test_worker_with_put_nowait_used_when_no_on_packet(self):
        """Worker without on_packet attribute must use put_nowait."""
        worker = MagicMock(spec=["put_nowait"])
        cap = PacketCapture(config={"tap": {}}, workers=[worker])
        pkt = self._make_pkt()
        cap._route_to_worker(pkt)
        worker.put_nowait.assert_called_once_with(pkt)

    def test_put_nowait_exception_is_swallowed(self):
        """put_nowait raising must not propagate."""
        worker = MagicMock(spec=["put_nowait"])
        worker.put_nowait.side_effect = Exception("queue full")
        cap = PacketCapture(config={"tap": {}}, workers=[worker])
        cap._route_to_worker(self._make_pkt())


# ---------------------------------------------------------------------------
# PacketCapture dedup — cache eviction
# ---------------------------------------------------------------------------


class TestDedupEviction:
    def test_dedup_cache_evicts_expired_entries_when_over_10000(self):
        """When cache exceeds 10000 entries, expired ones are evicted."""
        import time as _time

        cap = PacketCapture(
            config={"tap": {"interface": "lo", "dedup_window_s": 0.0}},
            workers=[],
        )
        # Fill the cache with 10001 entries using already-expired timestamps
        past = _time.monotonic() - 100
        for i in range(10001):
            cap._dedup_cache[f"key_{i}"] = past

        pkt = ParsedPacket(
            src_ip="9.9.9.9",
            dst_ip="8.8.8.8",
            src_port=100,
            dst_port=200,
            proto="tcp",
            seq=42,
            ack=0,
            flags=2,
            data=b"evict_test",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=1024,
            ip_ttl=64,
            ip_df=True,
            ip_id=99,
        )
        cap._dedup_check(pkt)
        # All expired entries must have been evicted (plus the new one added)
        assert len(cap._dedup_cache) <= 2


# ---------------------------------------------------------------------------
# VLAN edge cases
# ---------------------------------------------------------------------------


class TestVlanEdgeCases:
    def test_vlan_tag_truncated_before_inner_ethertype_returns_none(self):
        """VLAN tag at end of buffer — no room for inner ethertype."""
        frame = _eth_hdr(ETH_P_8021Q) + b"\x00\x01"  # TCI only, no inner ethertype
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is None

    def test_9100_qinq_alt_ethertype_stripped(self):
        """0x9100 alternate QinQ ethertype must also be stripped."""
        base = _build_ipv4_tcp()
        frame = base[:12] + struct.pack("!HH", ETH_P_8021Q_ALT, 0x0001) + base[12:]
        pkt = _parse_ethernet_frame(memoryview(frame), _TS, {})
        assert pkt is not None
        assert pkt.proto == "tcp"


# ---------------------------------------------------------------------------
# PcapReplay — stop flag and route_to_worker
# ---------------------------------------------------------------------------


class TestPcapReplayExtras:
    @pytest.mark.asyncio
    async def test_stop_sets_flag(self):
        replay = PcapReplay(Path("/dev/null"), [], realtime=False)
        assert not replay._stop
        await replay.stop()
        assert replay._stop

    @pytest.mark.asyncio
    async def test_replay_stops_early_when_stop_set(self, tmp_path):
        """If _stop is already True when start() is called, replay emits nothing."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]

        frame = _build_ipv4_tcp()
        pcap_path = tmp_path / "early_stop.pcap"
        wrpcap(str(pcap_path), [Ether(frame), Ether(frame), Ether(frame)])

        received = []

        class MockWorker:
            def on_packet(self, pkt):
                received.append(pkt)

        replay = PcapReplay(pcap_path, [MockWorker()], realtime=False)
        replay._stop = True  # Set before start
        await replay.start()
        assert len(received) == 0

    def test_route_to_worker_no_workers_is_safe(self):
        replay = PcapReplay(Path("/dev/null"), [], realtime=False)
        pkt = ParsedPacket(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=2,
            proto="tcp",
            seq=0,
            ack=0,
            flags=0,
            data=b"",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=0,
            ip_ttl=64,
            ip_df=False,
            ip_id=0,
        )
        replay._route_to_worker(pkt)

    def test_route_to_worker_put_nowait_exception_swallowed(self):
        worker = MagicMock(spec=["put_nowait"])
        worker.put_nowait.side_effect = RuntimeError("queue full")
        replay = PcapReplay(Path("/dev/null"), [worker], realtime=False)
        pkt = ParsedPacket(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=2,
            proto="tcp",
            seq=0,
            ack=0,
            flags=0,
            data=b"",
            timestamp=_TS,
            tcp_options_raw=b"",
            window_size=0,
            ip_ttl=64,
            ip_df=False,
            ip_id=0,
        )
        replay._route_to_worker(pkt)

    def test_scapy_to_parsed_returns_none_on_bad_packet(self):
        """_scapy_to_parsed must return None if bytes() conversion raises."""
        replay = PcapReplay(Path("/dev/null"), [], realtime=False)
        bad_pkt = MagicMock()
        bad_pkt.__bytes__ = MagicMock(side_effect=Exception("cannot convert"))
        # bytes(bad_pkt) calls __bytes__, patch it to raise
        with patch("builtins.bytes", side_effect=Exception("cannot convert")):
            result = replay._scapy_to_parsed(bad_pkt, _TS)
        assert result is None

    @pytest.mark.asyncio
    async def test_pcap_replay_realtime_skips_zero_or_negative_delay(self, tmp_path):
        """Realtime mode: delay <= 0 must not sleep (coverage for delay > 0 branch)."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]

        frame = _build_ipv4_tcp(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=80)
        pcap_path = tmp_path / "realtime_negative.pcap"
        pkt1 = Ether(frame)
        pkt1.time = 1_000_010.0
        pkt2 = Ether(frame)
        pkt2.time = 1_000_000.0  # earlier timestamp — delay will be negative
        wrpcap(str(pcap_path), [pkt1, pkt2])

        worker = MagicMock()
        replay = PcapReplay(pcap_path, [worker], realtime=True)
        import time as _time

        start = _time.monotonic()
        await replay.start()
        elapsed = _time.monotonic() - start
        # Negative delay → no sleep → should complete quickly
        assert elapsed < 2.0

    @pytest.mark.asyncio
    async def test_pcap_replay_realtime_with_positive_delay(self, tmp_path):
        """Realtime mode: positive delay invokes asyncio.sleep (covers lines 504-506)."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]

        frame = _build_ipv4_tcp(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=80)
        pcap_path = tmp_path / "realtime_pos.pcap"
        pkt1 = Ether(frame)
        pkt1.time = 1_000_000.0
        pkt2 = Ether(frame)
        pkt2.time = 1_000_000.001  # 1ms delay
        wrpcap(str(pcap_path), [pkt1, pkt2])

        worker = MagicMock()
        replay = PcapReplay(pcap_path, [worker], realtime=True)
        slept = []
        original_sleep = asyncio.sleep

        async def fake_sleep(delay):
            slept.append(delay)

        with patch("src.tap.capture.asyncio.sleep", fake_sleep):
            await replay.start()

        assert len(slept) >= 1  # asyncio.sleep was called for the delay

    @pytest.mark.asyncio
    async def test_pcap_replay_skips_unparsable_scapy_packet(self, tmp_path):
        """Packets where _scapy_to_parsed returns None must be silently skipped."""
        from scapy.all import Ether, wrpcap  # type: ignore[import]

        frame = _build_ipv4_tcp(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=80)
        pcap_path = tmp_path / "skip_bad.pcap"
        wrpcap(str(pcap_path), [Ether(frame), Ether(frame)])

        received = []

        class MockWorker:
            def on_packet(self, pkt):
                received.append(pkt)

        replay = PcapReplay(pcap_path, [MockWorker()], realtime=False)
        # Force _scapy_to_parsed to return None for all packets
        with patch.object(replay, "_scapy_to_parsed", return_value=None):
            await replay.start()
        # Nothing should have been dispatched
        assert len(received) == 0


# ---------------------------------------------------------------------------
# PacketCapture._dispatch — early-return paths
# ---------------------------------------------------------------------------


class TestDispatchEarlyReturn:
    def test_dispatch_returns_early_on_unparsable_frame(self):
        """_dispatch must not call _route_to_worker for frames that parse as None."""
        cap = PacketCapture(config={"tap": {}}, workers=[])
        routed = []
        cap._route_to_worker = lambda pkt: routed.append(pkt)
        # Frame too short to parse (< 14 bytes)
        cap._dispatch(memoryview(b"\x00" * 5))
        assert len(routed) == 0

    def test_dispatch_returns_early_on_duplicate_packet(self):
        """_dispatch must not route a duplicate packet (dedup returns True)."""
        cap = PacketCapture(
            config={"tap": {"interface": "lo", "dedup_window_s": 60.0}},
            workers=[],
        )
        frame = _build_ipv4_tcp(src="1.2.3.4", dst="5.6.7.8", sport=9000, dport=443)
        routed = []
        cap._route_to_worker = lambda pkt: routed.append(pkt)
        # First dispatch — goes through
        cap._dispatch(memoryview(frame))
        assert len(routed) == 1
        # Second dispatch — same frame, should be deduped
        cap._dispatch(memoryview(frame))
        assert len(routed) == 1  # still only 1
