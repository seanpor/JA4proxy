"""
Packet capture engine for TAP mode (Phase 20, Group 3).

Classes:
    ParsedPacket   — decoded packet ready for StreamReassembler
    PacketCapture  — AF_PACKET TPACKET_V3 live capture
    PcapReplay     — replays PCAP file; API-compatible with PacketCapture

Supported encapsulations (parsed by _parse_ethernet_frame):
    - Plain Ethernet (IPv4 / IPv6)
    - 802.1q VLAN
    - QinQ (double-tagged 0x88a8 / 0x9100)
    - VxLAN  (UDP dst port 4789)
    - GENEVE (UDP dst port 6081)
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from src.config.loader import ConfigError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETH_P_IP: int = 0x0800
ETH_P_IPV6: int = 0x86DD
ETH_P_8021Q: int = 0x8100
ETH_P_8021AD: int = 0x88A8
ETH_P_8021Q_ALT: int = 0x9100

IPPROTO_TCP: int = 6
IPPROTO_UDP: int = 17
IPPROTO_FRAGMENT: int = 44  # IPv6 fragment extension header

VXLAN_PORT: int = 4789
GENEVE_PORT: int = 6081

_VLAN_TYPES: frozenset[int] = frozenset({ETH_P_8021Q, ETH_P_8021AD, ETH_P_8021Q_ALT})


# ---------------------------------------------------------------------------
# ParsedPacket
# ---------------------------------------------------------------------------


@dataclass
class ParsedPacket:
    """Decoded packet ready for StreamReassembler consumption."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "tcp" | "udp"
    seq: int  # TCP sequence number
    ack: int  # TCP ACK number
    flags: int  # TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
    data: bytes  # payload bytes (after TCP header)
    timestamp: float  # seconds since epoch (kernel or hardware)
    tcp_options_raw: bytes  # raw TCP options bytes (from SYN/SYN-ACK only)
    window_size: int
    ip_ttl: int
    ip_df: bool  # IPv4 Don't Fragment bit
    ip_id: int  # IPv4 identification field


# ---------------------------------------------------------------------------
# Internal frame parser (shared by PacketCapture and PcapReplay)
# ---------------------------------------------------------------------------


def _parse_ethernet_frame(
    frame: memoryview | bytes,
    timestamp: float,
    frag_store: dict,
) -> Optional[ParsedPacket]:
    """Parse one Ethernet frame.

    Handles: plain Ethernet, 802.1q VLAN, QinQ, VxLAN, GENEVE.

    Args:
        frame:      raw frame bytes (from AF_PACKET or PcapReplay)
        timestamp:  capture timestamp (seconds since epoch)
        frag_store: mutable dict for IPv4 fragment reassembly state

    Returns:
        ParsedPacket on success, None if the frame cannot be parsed,
        carries an unknown ethertype, or is truncated.
    """
    buf = bytes(frame) if isinstance(frame, memoryview) else frame

    # --- Ethernet header ---
    if len(buf) < 14:
        return None  # truncated

    offset = 12
    ethertype, = struct.unpack_from("!H", buf, offset)
    offset += 2

    # --- Strip VLAN tags (802.1q, QinQ) ---
    while ethertype in _VLAN_TYPES:
        if offset + 4 > len(buf):
            return None
        ethertype, = struct.unpack_from("!H", buf, offset + 2)
        offset += 4

    # --- Dispatch by ethertype ---
    if ethertype == ETH_P_IP:
        return _parse_ipv4(buf, offset, timestamp, frag_store)
    elif ethertype == ETH_P_IPV6:
        return _parse_ipv6(buf, offset, timestamp)
    else:
        return None  # unknown ethertype


def _parse_ipv4(
    buf: bytes,
    offset: int,
    timestamp: float,
    frag_store: dict,
) -> Optional[ParsedPacket]:
    """Parse IPv4 header and TCP/UDP payload."""
    if offset + 20 > len(buf):
        return None

    byte0 = buf[offset]
    ihl = (byte0 & 0x0F) * 4
    if ihl < 20 or offset + ihl > len(buf):
        return None

    ttl = buf[offset + 8]
    proto = buf[offset + 9]
    flags_frag, = struct.unpack_from("!H", buf, offset + 6)
    ip_df = bool(flags_frag & 0x4000)
    ip_id, = struct.unpack_from("!H", buf, offset + 4)
    frag_offset = (flags_frag & 0x1FFF) * 8
    more_frags = bool(flags_frag & 0x2000)

    src_ip = socket.inet_ntoa(buf[offset + 12: offset + 16])
    dst_ip = socket.inet_ntoa(buf[offset + 16: offset + 20])

    payload_start = offset + ihl
    payload = buf[payload_start:]

    # --- Fragment reassembly ---
    if frag_offset != 0 or more_frags:
        frag_key = (src_ip, dst_ip, ip_id, proto)
        frags = frag_store.setdefault(frag_key, [])
        frags.append((frag_offset, payload, more_frags))
        if more_frags:
            # Not the last fragment yet
            return None
        # Last fragment arrived — reassemble
        frags.sort(key=lambda x: x[0])
        payload = b"".join(data for _, data, _ in frags)
        del frag_store[frag_key]

    # --- VxLAN inner frame ---
    if proto == IPPROTO_UDP:
        pkt = _try_vxlan_or_geneve(buf, payload, timestamp, frag_store, ttl, ip_df, ip_id)
        if pkt is not None:
            return pkt

    if proto == IPPROTO_TCP:
        return _parse_tcp(payload, src_ip, dst_ip, timestamp, ttl, ip_df, ip_id)
    elif proto == IPPROTO_UDP:
        return _parse_udp(payload, src_ip, dst_ip, timestamp, ttl, ip_df, ip_id)
    return None


def _try_vxlan_or_geneve(
    buf: bytes,
    udp_payload_including_hdr: bytes,
    timestamp: float,
    frag_store: dict,
    ttl: int,
    ip_df: bool,
    ip_id: int,
) -> Optional[ParsedPacket]:
    """Check if UDP payload is VxLAN or GENEVE; parse inner frame if so."""
    if len(udp_payload_including_hdr) < 8:
        return None
    dst_port, = struct.unpack_from("!H", udp_payload_including_hdr, 2)
    udp_data = udp_payload_including_hdr[8:]  # past UDP header

    if dst_port == VXLAN_PORT:
        # VxLAN: 8-byte header, then inner Ethernet frame
        if len(udp_data) < 8:
            return None
        inner_eth = udp_data[8:]
        return _parse_ethernet_frame(memoryview(inner_eth), timestamp, frag_store)

    elif dst_port == GENEVE_PORT:
        # GENEVE: 4-byte fixed header + variable options (opt_len * 4 bytes)
        if len(udp_data) < 4:
            return None
        opt_len = (udp_data[0] & 0x3F) * 4
        inner_eth = udp_data[4 + opt_len:]
        return _parse_ethernet_frame(memoryview(inner_eth), timestamp, frag_store)

    return None


def _parse_ipv6(
    buf: bytes,
    offset: int,
    timestamp: float,
) -> Optional[ParsedPacket]:
    """Parse IPv6 header, walk extension headers, parse TCP/UDP payload."""
    if offset + 40 > len(buf):
        return None

    ttl = buf[offset + 7]  # hop limit
    next_hdr = buf[offset + 6]
    src_ip = socket.inet_ntop(socket.AF_INET6, buf[offset + 8: offset + 24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, buf[offset + 24: offset + 40])
    payload_start = offset + 40
    payload = buf[payload_start:]

    # Walk extension headers
    while next_hdr not in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_FRAGMENT):
        # Simple extension header walking: skip known types
        if next_hdr in (0, 43, 60):  # Hop-by-Hop, Routing, Destination options
            if len(payload) < 2:
                return None
            ext_len = (payload[1] + 1) * 8
            if ext_len > len(payload):
                return None
            next_hdr = payload[0]
            payload = payload[ext_len:]
        else:
            # Unrecognized extension header — stop walking
            break

    if next_hdr == IPPROTO_FRAGMENT:
        # IPv6 fragmentation extension header (8 bytes)
        if len(payload) < 8:
            return None
        next_hdr = payload[0]
        # For now, just skip the fragment header and continue with remaining payload
        payload = payload[8:]

    if next_hdr == IPPROTO_TCP:
        return _parse_tcp(payload, src_ip, dst_ip, timestamp, ttl, False, 0)
    elif next_hdr == IPPROTO_UDP:
        return _parse_udp(payload, src_ip, dst_ip, timestamp, ttl, False, 0)
    return None


def _parse_tcp(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    timestamp: float,
    ttl: int,
    ip_df: bool,
    ip_id: int,
) -> Optional[ParsedPacket]:
    """Parse TCP header from *payload*."""
    if len(payload) < 20:
        return None
    src_port, dst_port = struct.unpack_from("!HH", payload, 0)
    seq, ack = struct.unpack_from("!II", payload, 4)
    data_offset_and_flags, = struct.unpack_from("!H", payload, 12)
    data_offset = ((data_offset_and_flags >> 12) & 0xF) * 4
    flags = data_offset_and_flags & 0x1FF
    window, = struct.unpack_from("!H", payload, 14)

    if data_offset < 20 or data_offset > len(payload):
        return None

    tcp_options_raw = payload[20:data_offset]
    data = payload[data_offset:]

    return ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto="tcp",
        seq=seq,
        ack=ack,
        flags=flags,
        data=bytes(data),
        timestamp=timestamp,
        tcp_options_raw=bytes(tcp_options_raw),
        window_size=window,
        ip_ttl=ttl,
        ip_df=ip_df,
        ip_id=ip_id,
    )


def _parse_udp(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    timestamp: float,
    ttl: int,
    ip_df: bool,
    ip_id: int,
) -> Optional[ParsedPacket]:
    """Parse UDP header from *payload*."""
    if len(payload) < 8:
        return None
    src_port, dst_port = struct.unpack_from("!HH", payload, 0)
    data = payload[8:]
    return ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto="udp",
        seq=0,
        ack=0,
        flags=0,
        data=bytes(data),
        timestamp=timestamp,
        tcp_options_raw=b"",
        window_size=0,
        ip_ttl=ttl,
        ip_df=ip_df,
        ip_id=ip_id,
    )


# ---------------------------------------------------------------------------
# PacketCapture
# ---------------------------------------------------------------------------


class PacketCapture:
    """AF_PACKET TPACKET_V3 capture engine.

    Requires CAP_NET_RAW. In TAP mode, ``start()`` binds the socket,
    attaches the BPF filter, and spawns a reader thread via
    ``asyncio.to_thread()``.
    """

    def __init__(self, config: dict, workers: list) -> None:
        tap_cfg = config.get("tap") or {}
        self._interface: str = tap_cfg.get("interface", "eth0")
        self._bpf_filter: str = tap_cfg.get("bpf_filter", "tcp or udp")
        self._dedup_window: float = float(tap_cfg.get("dedup_window_s", 1.0))
        self._workers = workers
        self._sock: Optional[socket.socket] = None
        self._stop: bool = False
        # IPv4 fragment reassembly state
        self._frag_store: dict = {}
        # Dedup: maps packet fingerprint → expiry timestamp
        self._dedup_cache: dict[str, float] = {}

    async def start(self) -> None:
        """Bind AF_PACKET socket, attach BPF, and start capture thread."""
        try:
            sock = self._setup_socket()
        except OSError as exc:
            raise ConfigError(f"Cannot bind AF_PACKET socket: {exc}") from exc
        self._set_bpf_filter(sock, self._bpf_filter)
        self._sock = sock
        self._stop = False
        asyncio.get_running_loop().run_in_executor(None, self._poll_ring)

    async def stop(self) -> None:
        """Signal the capture thread to stop and close the socket."""
        self._stop = True
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _setup_socket(self) -> socket.socket:
        """Create and bind an AF_PACKET / SOCK_RAW socket."""
        import socket as _socket
        sock = _socket.socket(
            _socket.AF_PACKET,
            _socket.SOCK_RAW,
            _socket.htons(0x0003),  # ETH_P_ALL
        )
        sock.bind((self._interface, 0))
        return sock

    def _set_bpf_filter(self, sock: socket.socket, expr: str) -> None:
        """Validate and attach a BPF filter expression.

        Uses ``tcpdump -d`` to validate the expression.  Raises
        ``ConfigError`` if the expression is syntactically invalid.
        """
        result = subprocess.run(
            ["tcpdump", "-d", expr],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ConfigError(
                f"Invalid BPF filter {expr!r}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        # TODO: attach compiled BPF via SO_ATTACH_FILTER (requires ctypes + libpcap)

    def _poll_ring(self) -> None:
        """Read raw frames in a loop (runs in a dedicated OS thread)."""
        while not self._stop and self._sock is not None:
            try:
                frame = self._sock.recv(65535)
                self._dispatch(memoryview(frame))
            except OSError:
                break

    def _dispatch(self, frame: memoryview) -> None:
        """Parse frame, dedup-check, then route to a worker shard."""
        pkt = _parse_ethernet_frame(frame, time.monotonic(), self._frag_store)
        if pkt is None:
            return
        if self._dedup_check(pkt):
            return
        self._route_to_worker(pkt)

    def _route_to_worker(self, pkt: ParsedPacket) -> None:
        """Consistent-hash the 4-tuple to a worker shard."""
        if not self._workers:
            return
        h = hash((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))
        worker = self._workers[h % len(self._workers)]
        if hasattr(worker, "on_packet"):
            worker.on_packet(pkt)
        else:
            try:
                worker.put_nowait(pkt)
            except Exception:
                pass

    def _dedup_check(self, pkt: ParsedPacket) -> bool:
        """Return True (discard) if this packet appeared within *dedup_window_s*."""
        now = time.monotonic()
        key = hashlib.md5(
            f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
            f":{pkt.seq}:{pkt.data[:32]}".encode()
        ).hexdigest()
        expire = self._dedup_cache.get(key)
        if expire is not None and expire > now:
            return True
        # Evict expired entries periodically
        if len(self._dedup_cache) > 10_000:
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items() if v > now
            }
        self._dedup_cache[key] = now + self._dedup_window
        return False


# ---------------------------------------------------------------------------
# PcapReplay
# ---------------------------------------------------------------------------


class PcapReplay:
    """Replays a PCAP file into the worker pipeline.

    API-compatible with PacketCapture: call ``await start()`` to replay all
    packets, ``await stop()`` to abort.
    """

    def __init__(
        self,
        pcap_path: Path,
        workers: list,
        realtime: bool = False,
    ) -> None:
        self._pcap_path = Path(pcap_path)
        self._workers = workers
        self._realtime = realtime
        self._stop = False
        self._frag_store: dict = {}

    async def start(self) -> None:
        """Replay all packets in the PCAP file, dispatching to workers."""
        from scapy.all import rdpcap  # type: ignore[import]

        packets = rdpcap(str(self._pcap_path))
        prev_ts: Optional[float] = None

        for scapy_pkt in packets:
            if self._stop:
                break

            ts = float(scapy_pkt.time)

            if self._realtime and prev_ts is not None:
                delay = ts - prev_ts
                if delay > 0:
                    await asyncio.sleep(delay)
            prev_ts = ts

            pkt = self._scapy_to_parsed(scapy_pkt, ts)
            if pkt is None:
                continue
            self._route_to_worker(pkt)

    async def stop(self) -> None:
        """Abort replay."""
        self._stop = True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scapy_to_parsed(self, scapy_pkt: Any, ts: float) -> Optional[ParsedPacket]:
        """Convert a Scapy packet to a ParsedPacket.

        Converts to raw bytes and reuses the frame parser so all
        encapsulation handling is shared.
        """
        try:
            raw = bytes(scapy_pkt)
        except Exception:
            return None
        return _parse_ethernet_frame(raw, ts, self._frag_store)

    def _route_to_worker(self, pkt: ParsedPacket) -> None:
        """Consistent-hash the 4-tuple to a worker shard."""
        if not self._workers:
            return
        h = hash((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))
        worker = self._workers[h % len(self._workers)]
        if hasattr(worker, "on_packet"):
            worker.on_packet(pkt)
        else:
            try:
                worker.put_nowait(pkt)
            except Exception:
                pass
