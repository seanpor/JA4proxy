"""
TAP-mode test infrastructure (Phase 20, Group 13).

Fixtures:
    synthetic_packets  — returns a SyntheticPacketBuilder
    tap_config         — minimal TapConfig dict for unit tests

Classes:
    SyntheticPacketBuilder — builds lists of ParsedPacket for protocol replays
"""

from __future__ import annotations

import struct
import time
import uuid
from dataclasses import dataclass
from typing import Optional

import pytest

from src.tap.capture import ParsedPacket

# TCP flag constants
_SYN = 0x002
_ACK = 0x010
_FIN = 0x001
_RST = 0x004
_SYNACK = _SYN | _ACK
_FINACK = _FIN | _ACK

# ─────────────────────────────────────────────────────────────────────────────
# SyntheticPacketBuilder
# ─────────────────────────────────────────────────────────────────────────────


class SyntheticPacketBuilder:
    """Builds synthetic ParsedPacket sequences for TAP-mode tests.

    Usage::

        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 54321, "5.6.7.8", 443)
            .synack()
            .ack()
            .tls_client_hello(ciphers=[0x1301, 0x1302], extensions=[0, 16, 43, 51])
            .tls_server_hello(cipher=0x1301, extensions=[43, 51])
            .fin()
            .build()
        )
    """

    def __init__(self) -> None:
        self._packets: list[ParsedPacket] = []
        self._src_ip: str = "1.2.3.4"
        self._src_port: int = 54321
        self._dst_ip: str = "5.6.7.8"
        self._dst_port: int = 443
        self._client_seq: int = 1000
        self._server_seq: int = 2000
        self._ts: float = time.time()

    # ------------------------------------------------------------------
    # Public builder methods
    # ------------------------------------------------------------------

    def syn(
        self,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        window_size: int = 65535,
        ttl: int = 64,
        mss: int = 1460,
        wscale: int = 7,
    ) -> "SyntheticPacketBuilder":
        self._src_ip = src
        self._src_port = sport
        self._dst_ip = dst
        self._dst_port = dport
        tcp_opts = self._build_tcp_options(mss=mss, wscale=wscale, sack=True, ts=False)
        self._packets.append(
            ParsedPacket(
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                proto="tcp",
                seq=self._client_seq,
                ack=0,
                flags=_SYN,
                data=b"",
                timestamp=self._ts,
                tcp_options_raw=tcp_opts,
                window_size=window_size,
                ip_ttl=ttl,
                ip_df=True,
                ip_id=1,
            )
        )
        self._ts += 0.001
        return self

    def synack(
        self,
        window_size: int = 65535,
        ttl: int = 64,
        mss: int = 1460,
        wscale: int = 8,
    ) -> "SyntheticPacketBuilder":
        tcp_opts = self._build_tcp_options(mss=mss, wscale=wscale, sack=True, ts=False)
        self._packets.append(
            ParsedPacket(
                src_ip=self._dst_ip,
                dst_ip=self._src_ip,
                src_port=self._dst_port,
                dst_port=self._src_port,
                proto="tcp",
                seq=self._server_seq,
                ack=self._client_seq + 1,
                flags=_SYNACK,
                data=b"",
                timestamp=self._ts,
                tcp_options_raw=tcp_opts,
                window_size=window_size,
                ip_ttl=ttl,
                ip_df=True,
                ip_id=1,
            )
        )
        self._ts += 0.001
        return self

    def ack(self) -> "SyntheticPacketBuilder":
        self._client_seq += 1  # after SYN
        self._server_seq += 1  # after SYN-ACK
        self._packets.append(
            ParsedPacket(
                src_ip=self._src_ip,
                dst_ip=self._dst_ip,
                src_port=self._src_port,
                dst_port=self._dst_port,
                proto="tcp",
                seq=self._client_seq,
                ack=self._server_seq,
                flags=_ACK,
                data=b"",
                timestamp=self._ts,
                tcp_options_raw=b"",
                window_size=65535,
                ip_ttl=64,
                ip_df=True,
                ip_id=2,
            )
        )
        self._ts += 0.0005
        return self

    def tls_client_hello(
        self,
        ciphers: list[int] = None,
        extensions: list[int] = None,
        sni: Optional[str] = None,
        grease: bool = True,
    ) -> "SyntheticPacketBuilder":
        """Add a TCP data packet containing a synthetic TLS ClientHello."""
        if ciphers is None:
            ciphers = [0x1301, 0x1302, 0x1303, 0x00FF]
        if extensions is None:
            extensions = [0, 11, 10, 16, 22, 23, 13, 43, 45, 51, 21]
        data = self._build_client_hello(ciphers, extensions, sni, grease)
        self._add_client_data(data)
        return self

    def tls_server_hello(
        self,
        cipher: int = 0x1301,
        extensions: list[int] = None,
    ) -> "SyntheticPacketBuilder":
        """Add a TCP data packet containing a synthetic TLS ServerHello."""
        if extensions is None:
            extensions = [43, 51]
        data = self._build_server_hello(cipher, extensions)
        self._add_server_data(data)
        return self

    def http_request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: dict = None,
        body: bytes = b"",
    ) -> "SyntheticPacketBuilder":
        if headers is None:
            headers = {
                "Host": "example.com",
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html",
                "Accept-Language": "en-US,en;q=0.9",
            }
        lines = [f"{method} {path} HTTP/1.1\r\n"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}\r\n")
        lines.append("\r\n")
        data = "".join(lines).encode() + body
        self._add_client_data(data)
        return self

    def fin(self) -> "SyntheticPacketBuilder":
        self._packets.append(
            ParsedPacket(
                src_ip=self._src_ip,
                dst_ip=self._dst_ip,
                src_port=self._src_port,
                dst_port=self._dst_port,
                proto="tcp",
                seq=self._client_seq,
                ack=self._server_seq,
                flags=_FINACK,
                data=b"",
                timestamp=self._ts,
                tcp_options_raw=b"",
                window_size=65535,
                ip_ttl=64,
                ip_df=True,
                ip_id=100,
            )
        )
        self._ts += 0.001
        return self

    def rst(self) -> "SyntheticPacketBuilder":
        self._packets.append(
            ParsedPacket(
                src_ip=self._src_ip,
                dst_ip=self._dst_ip,
                src_port=self._src_port,
                dst_port=self._dst_port,
                proto="tcp",
                seq=self._client_seq,
                ack=self._server_seq,
                flags=_RST,
                data=b"",
                timestamp=self._ts,
                tcp_options_raw=b"",
                window_size=0,
                ip_ttl=64,
                ip_df=False,
                ip_id=0,
            )
        )
        return self

    def build(self) -> list[ParsedPacket]:
        return list(self._packets)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _add_client_data(self, data: bytes) -> None:
        pkt = ParsedPacket(
            src_ip=self._src_ip,
            dst_ip=self._dst_ip,
            src_port=self._src_port,
            dst_port=self._dst_port,
            proto="tcp",
            seq=self._client_seq,
            ack=self._server_seq,
            flags=_ACK,
            data=data,
            timestamp=self._ts,
            tcp_options_raw=b"",
            window_size=65535,
            ip_ttl=64,
            ip_df=True,
            ip_id=10,
        )
        self._client_seq += len(data)
        self._ts += 0.0001
        self._packets.append(pkt)

    def _add_server_data(self, data: bytes) -> None:
        pkt = ParsedPacket(
            src_ip=self._dst_ip,
            dst_ip=self._src_ip,
            src_port=self._dst_port,
            dst_port=self._src_port,
            proto="tcp",
            seq=self._server_seq,
            ack=self._client_seq,
            flags=_ACK,
            data=data,
            timestamp=self._ts,
            tcp_options_raw=b"",
            window_size=65535,
            ip_ttl=64,
            ip_df=True,
            ip_id=20,
        )
        self._server_seq += len(data)
        self._ts += 0.0001
        self._packets.append(pkt)

    @staticmethod
    def _build_tcp_options(
        mss: int = 1460, wscale: int = 7, sack: bool = True, ts: bool = False
    ) -> bytes:
        opts = b""
        # MSS: kind=2, len=4
        opts += struct.pack("!BBH", 2, 4, mss)
        # SACK_PERMITTED: kind=4, len=2
        if sack:
            opts += struct.pack("!BB", 4, 2)
        # NOP
        opts += b"\x01"
        # WSCALE: kind=3, len=3
        opts += struct.pack("!BBB", 3, 3, wscale)
        return opts

    @staticmethod
    def _build_client_hello(
        ciphers: list[int],
        extensions: list[int],
        sni: Optional[str],
        grease: bool,
    ) -> bytes:
        """Build a minimal TLS 1.3 ClientHello byte sequence."""
        # Add GREASE cipher and extension if requested
        grease_val = 0x0A0A
        cipher_list = ([grease_val] if grease else []) + ciphers
        ext_list = ([grease_val] if grease else []) + extensions

        # Cipher suites
        cipher_data = b"".join(struct.pack("!H", c) for c in cipher_list)
        cipher_section = struct.pack("!H", len(cipher_data)) + cipher_data

        # Build extensions
        ext_bytes = b""
        for ext_type in ext_list:
            if ext_type == 0 and sni:  # SNI
                sni_bytes = sni.encode()
                name_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
                list_bytes = struct.pack("!H", len(name_entry)) + name_entry
                ext_bytes += struct.pack("!HH", 0, len(list_bytes)) + list_bytes
            elif ext_type == 43:  # supported_versions
                # TLS 1.3 = 0x0304
                versions = struct.pack("!H", 0x0304)
                ext_bytes += (
                    struct.pack("!HHB", 43, len(versions) + 1, len(versions)) + versions
                )
            elif ext_type == grease_val:
                ext_bytes += struct.pack("!HH", grease_val, 0)
            else:
                ext_bytes += struct.pack("!HH", ext_type, 0)

        ext_section = struct.pack("!H", len(ext_bytes)) + ext_bytes

        # ClientHello body
        random_bytes = b"\x00" * 32
        body = (
            b"\x03\x03"  # client version TLS 1.2
            + random_bytes  # random
            + b"\x00"  # session ID length = 0
            + cipher_section  # cipher suites
            + b"\x01\x00"  # compression methods (1 byte, null)
            + ext_section  # extensions
        )

        # Handshake header: type=1 (ClientHello), 3-byte length
        handshake = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body

        # TLS record header: type=22 (Handshake), version=0x0301, length
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        return record

    @staticmethod
    def _build_server_hello(cipher: int, extensions: list[int]) -> bytes:
        """Build a minimal TLS ServerHello byte sequence."""
        random_bytes = b"\x00" * 32
        ext_bytes = b""
        for ext_type in extensions:
            if ext_type == 43:  # supported_versions: TLS 1.3
                ext_bytes += struct.pack("!HHH", 43, 2, 0x0304)
            else:
                ext_bytes += struct.pack("!HH", ext_type, 0)
        ext_section = struct.pack("!H", len(ext_bytes)) + ext_bytes

        body = (
            b"\x03\x03"  # server version TLS 1.2
            + random_bytes  # random
            + b"\x00"  # session ID length = 0
            + struct.pack("!H", cipher)  # cipher suite
            + b"\x00"  # compression method
            + ext_section  # extensions
        )
        handshake = bytes([0x02]) + struct.pack("!I", len(body))[1:] + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        return record


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def synthetic_packets() -> SyntheticPacketBuilder:
    """Return a fresh SyntheticPacketBuilder."""
    return SyntheticPacketBuilder()


@pytest.fixture
def tap_config(tmp_path) -> dict:
    """Minimal valid TAP config dict for unit tests."""
    return {
        "tap": {
            "interface": "eth0",
            "ring_buffer_mb": 64,
            "workers": 2,
            "tls_ports": [443, 8443],
            "ssh_ports": [22],
            "http_ports": [80, 8080],
            "stream_timeout_s": 30,
        },
        "tap_enforcement": {
            "ban_ttl_s": 3600,
            "iptables": {"enabled": False, "ipset_name": "ja4proxy_ban"},
            "bgp": {"enabled": False},
            "webhook": {"enabled": False},
        },
        "intelligence_export": {
            "edl": {"enabled": False},
            "f5": {"enabled": False},
            "palo_alto": {"enabled": False},
            "kafka": {"enabled": False},
            "syslog": {"enabled": False},
            "taxii": {"enabled": False},
            "misp": {"enabled": False},
        },
    }
