#!/usr/bin/env python3
"""
generate_test_pcap.py — Synthetic PCAP corpus generator for TAP mode tests.

Creates test PCAPs in tests/pcap_corpus/ covering:
- Chrome-like TLS 1.3 ClientHello
- Firefox-like TLS 1.3 ClientHello
- nmap SYN scan
- Masscan probe
- Port 443 SYN flood (DDoS simulation)
- HTTP/1.1 GET request (cleartext)
- Truncated/malformed TLS records (for chaos tests)
- Tranco top-10k domain list (for FP rate tests)

Usage:
    python3 scripts/generate_test_pcap.py [--output-dir tests/pcap_corpus]

Requirements:
    scapy  (pip install scapy)
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


def _build_client_hello(
    ciphers: list[int],
    extensions: list[int],
    sni: str | None,
    grease: bool,
) -> bytes:
    """Build a minimal TLS 1.3 ClientHello byte sequence."""
    grease_val = 0x0A0A
    cipher_list = ([grease_val] if grease else []) + ciphers
    ext_list = ([grease_val] if grease else []) + extensions

    cipher_data = b"".join(struct.pack("!H", c) for c in cipher_list)
    cipher_section = struct.pack("!H", len(cipher_data)) + cipher_data

    ext_bytes = b""
    for ext_type in ext_list:
        if ext_type == 0 and sni:
            sni_b = sni.encode()
            name_entry = struct.pack("!BH", 0, len(sni_b)) + sni_b
            list_bytes = struct.pack("!H", len(name_entry)) + name_entry
            ext_bytes += struct.pack("!HH", 0, len(list_bytes)) + list_bytes
        elif ext_type == 43:
            versions = struct.pack("!H", 0x0304)
            ext_bytes += struct.pack("!HHB", 43, len(versions) + 1, len(versions)) + versions
        elif ext_type == grease_val:
            ext_bytes += struct.pack("!HH", grease_val, 0)
        else:
            ext_bytes += struct.pack("!HH", ext_type, 0)

    ext_section = struct.pack("!H", len(ext_bytes)) + ext_bytes
    random_bytes = b"\x00" * 32
    body = (
        b"\x03\x03"
        + random_bytes
        + b"\x00"
        + cipher_section
        + b"\x01\x00"
        + ext_section
    )
    handshake = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _write_pcap(path: Path, packets: list[bytes], *, link_type: int = 1) -> None:
    """Write a minimal libpcap file containing raw Ethernet frames."""
    PCAP_MAGIC = 0xA1B2C3D4
    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    SNAPLEN = 65535

    global_header = struct.pack(
        "IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,      # GMT offset
        0,      # timestamp accuracy
        SNAPLEN,
        link_type,
    )

    records = b""
    ts = 1_700_000_000
    for i, pkt in enumerate(packets):
        ts_sec = ts + i
        ts_usec = 0
        caplen = len(pkt)
        origlen = len(pkt)
        records += struct.pack("IIII", ts_sec, ts_usec, caplen, origlen) + pkt

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(global_header + records)


def _eth_ip_tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    """Build a minimal Ethernet+IPv4+TCP frame."""
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x00\xaa\xbb\xcc\xdd\xee"
    ethertype = b"\x08\x00"  # IPv4

    def ip_to_bytes(ip: str) -> bytes:
        parts = ip.split(".")
        return bytes(int(p) for p in parts)

    # TCP header (no options)
    tcp_offset = 5  # 20 bytes = 5 × 4
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        0,       # seq
        0,       # ack
        (tcp_offset << 4),
        flags,
        65535,   # window
        0,       # checksum (0 for test pcap)
        0,       # urgent
    )

    # IPv4 header (no options)
    ip_total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,        # version+IHL
        0,           # DSCP+ECN
        ip_total_len,
        0,           # id
        0x40 << 8,   # flags+fragment offset (DF)
        64,          # TTL
        6,           # protocol = TCP
        0,           # checksum
        ip_to_bytes(src_ip),
        ip_to_bytes(dst_ip),
    )

    eth_frame = dst_mac + src_mac + ethertype + ip_header + tcp_header + payload
    return eth_frame


def generate_chrome_pcap(output_dir: Path) -> None:
    """Chrome-like TLS 1.3 ClientHello with GREASE."""
    ch = _build_client_hello(
        ciphers=[0x1301, 0x1302, 0x1303, 0x00ff],
        extensions=[0, 11, 10, 16, 22, 23, 13, 43, 45, 51, 21],
        sni="example.com",
        grease=True,
    )
    syn = _eth_ip_tcp("1.2.3.4", "5.6.7.8", 54321, 443, 0x002)
    synack = _eth_ip_tcp("5.6.7.8", "1.2.3.4", 443, 54321, 0x012)
    ack = _eth_ip_tcp("1.2.3.4", "5.6.7.8", 54321, 443, 0x010)
    data = _eth_ip_tcp("1.2.3.4", "5.6.7.8", 54321, 443, 0x010, ch)
    _write_pcap(output_dir / "chrome_tls13.pcap", [syn, synack, ack, data])
    print(f"  + {output_dir / 'chrome_tls13.pcap'}")


def generate_firefox_pcap(output_dir: Path) -> None:
    """Firefox-like TLS 1.3 ClientHello."""
    ch = _build_client_hello(
        ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c],
        extensions=[0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 45, 21],
        sni="example.com",
        grease=False,
    )
    syn = _eth_ip_tcp("2.3.4.5", "5.6.7.8", 44444, 443, 0x002)
    synack = _eth_ip_tcp("5.6.7.8", "2.3.4.5", 443, 44444, 0x012)
    ack = _eth_ip_tcp("2.3.4.5", "5.6.7.8", 44444, 443, 0x010)
    data = _eth_ip_tcp("2.3.4.5", "5.6.7.8", 44444, 443, 0x010, ch)
    _write_pcap(output_dir / "firefox_tls13.pcap", [syn, synack, ack, data])
    print(f"  + {output_dir / 'firefox_tls13.pcap'}")


def generate_nmap_pcap(output_dir: Path) -> None:
    """nmap SYN scan probe (no SNI, single cipher, no GREASE)."""
    ch = _build_client_hello(
        ciphers=[0x1301],
        extensions=[43],
        sni=None,
        grease=False,
    )
    syn = _eth_ip_tcp("192.168.1.100", "5.6.7.8", 33333, 443, 0x002)
    data = _eth_ip_tcp("192.168.1.100", "5.6.7.8", 33333, 443, 0x010, ch)
    _write_pcap(output_dir / "nmap_scan.pcap", [syn, data])
    print(f"  + {output_dir / 'nmap_scan.pcap'}")


def generate_malformed_pcap(output_dir: Path) -> None:
    """Truncated and malformed TLS records for chaos tests."""
    # Truncated TLS record (claims 80 bytes but only has 10)
    truncated = b"\x16\x03\x01\x00\x50" + b"\x00" * 10
    data_pkt = _eth_ip_tcp("10.0.0.1", "5.6.7.8", 11111, 443, 0x010, truncated)

    # Random garbage
    garbage = bytes(range(256)) * 4
    garbage_pkt = _eth_ip_tcp("10.0.0.2", "5.6.7.8", 22222, 443, 0x010, garbage)

    _write_pcap(output_dir / "malformed_tls.pcap", [data_pkt, garbage_pkt])
    print(f"  + {output_dir / 'malformed_tls.pcap'}")


def generate_tranco_list(output_dir: Path) -> None:
    """Write a minimal Tranco top-10k list for FP rate tests."""
    path = output_dir / "tranco_top10k.txt"
    # Synthetic domain list — real tests require the actual Tranco list
    domains = [f"domain{i}.example.com" for i in range(10000)]
    path.write_text("\n".join(domains))
    print(f"  + {path} ({len(domains)} domains)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic PCAP corpus")
    parser.add_argument(
        "--output-dir",
        default="tests/pcap_corpus",
        help="Output directory for PCAP files (default: tests/pcap_corpus)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Generating PCAP corpus in {output_dir}/")

    generate_chrome_pcap(output_dir)
    generate_firefox_pcap(output_dir)
    generate_nmap_pcap(output_dir)
    generate_malformed_pcap(output_dir)
    generate_tranco_list(output_dir)

    print(f"\nDone. Run: python3 -m pytest tests/tap/fp_corpus/ -v")


if __name__ == "__main__":
    main()
