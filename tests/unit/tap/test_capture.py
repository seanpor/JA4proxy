"""
Unit tests for src/tap/capture.py (Phase 20 Group 3).

Uses PcapReplay and synthetic Ethernet frames — no live AF_PACKET socket required.
"""
import socket as _socket
import struct
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.config.loader import ConfigError
from src.tap.capture import (
    ETH_P_8021AD,
    ETH_P_8021Q,
    ETH_P_IP,
    ETH_P_IPV6,
    GENEVE_PORT,
    VXLAN_PORT,
    PacketCapture,
    ParsedPacket,
    PcapReplay,
    _parse_ethernet_frame,
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
        0x45,          # ver=4, ihl=5
        0,             # DSCP/ECN
        0,             # total_length (not used by parser)
        ip_id,
        flags_frag,
        ttl,
        proto,
        0,             # checksum
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
    hdr = struct.pack("!HHIIHHHH",
        sport, dport, seq, ack, dof_flags, window, 0, 0)
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
        geneve_hdr = struct.pack("!BBH", 0x00, 0x00, 0x6558)  # opt_len=0, proto=Ethernet
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
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2,
            proto="tcp", seq=10, ack=0, flags=2,
            data=b"hello", timestamp=_TS,
            tcp_options_raw=b"", window_size=65535, ip_ttl=64,
            ip_df=True, ip_id=1,
        )
        first = cap._dedup_check(pkt)
        second = cap._dedup_check(pkt)
        assert first is False   # first time: not a duplicate
        assert second is True   # second time: duplicate

    def test_dedup_allows_identical_packet_after_window_expires(self):
        cap = self._make_capture(dedup_window=0.0)  # expires immediately
        pkt = ParsedPacket(
            src_ip="3.3.3.3", dst_ip="4.4.4.4",
            src_port=10, dst_port=20,
            proto="tcp", seq=99, ack=0, flags=2,
            data=b"x", timestamp=_TS,
            tcp_options_raw=b"", window_size=8192, ip_ttl=64,
            ip_df=False, ip_id=5,
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
                src="1.2.3.4", dst="5.6.7.8", sport=9000, dport=443,
                seq=i * 1000, payload=bytes([i]) * 10,
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
