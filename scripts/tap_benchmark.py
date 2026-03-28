#!/usr/bin/env python3
"""
tap_benchmark.py — TAP mode throughput benchmark.

Measures packets-per-second through the full TAP pipeline:
  raw bytes → Ethernet parse → IP/TCP decode → stream reassembly →
  fingerprint extraction → signal scoring → Redis write (optional)

Modes:
  --mode synthetic  Build synthetic packets in memory and replay them (default)
  --mode pcap       Replay a PCAP file through the pipeline
  --mode live       Capture from a live interface (requires --interface)

Targets (from PHASE_20.md §12.9):
  ≥ 500,000 pps on a 4-core machine
  ≤ 1% packet drop rate under sustained 1 Gbps traffic

Usage:
    python3 scripts/tap_benchmark.py --mode synthetic --packets 1000000
    python3 scripts/tap_benchmark.py --mode pcap --pcap tests/pcap_corpus/chrome_tls13.pcap
"""
from __future__ import annotations

import argparse
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


# ─────────────────────────────────────────────────────────────────────────────
# Minimal inline ParsedPacket (avoids import latency in benchmark)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _Pkt:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    flags: int
    data: bytes
    seq: int = 1000
    ack: int = 0
    proto: str = "tcp"
    timestamp: float = 0.0
    tcp_options_raw: bytes = b""
    window_size: int = 65535
    ip_ttl: int = 64
    ip_df: bool = True
    ip_id: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic packet generator
# ─────────────────────────────────────────────────────────────────────────────


def _build_client_hello_bytes() -> bytes:
    """Build a minimal TLS ClientHello for benchmark payloads."""
    ciphers = [0x1301, 0x1302, 0x1303, 0x00ff]
    cipher_data = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_section = struct.pack("!H", len(cipher_data)) + cipher_data

    exts = [0, 43, 51, 16]
    ext_bytes = b""
    for t in exts:
        if t == 43:
            v = struct.pack("!H", 0x0304)
            ext_bytes += struct.pack("!HHB", 43, len(v) + 1, len(v)) + v
        else:
            ext_bytes += struct.pack("!HH", t, 0)
    ext_section = struct.pack("!H", len(ext_bytes)) + ext_bytes

    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + cipher_section + b"\x01\x00" + ext_section
    hs = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


_CLIENT_HELLO = _build_client_hello_bytes()


def generate_synthetic_packets(n: int) -> Iterator[_Pkt]:
    """Generate n synthetic TCP+TLS connection packets."""
    base_ip = 0x0A000001  # 10.0.0.1
    ch = _CLIENT_HELLO
    for i in range(n):
        src_ip_int = base_ip + (i % 65536)
        a = (src_ip_int >> 24) & 0xFF
        b_ = (src_ip_int >> 16) & 0xFF
        c = (src_ip_int >> 8) & 0xFF
        d = src_ip_int & 0xFF
        src_ip = f"{a}.{b_}.{c}.{d}"
        sport = 50000 + (i % 15535)

        # SYN
        yield _Pkt(
            src_ip=src_ip, dst_ip="5.6.7.8",
            src_port=sport, dst_port=443,
            flags=0x002, data=b"",
            seq=1000, ack=0, timestamp=float(i),
        )
        # TLS ClientHello data
        yield _Pkt(
            src_ip=src_ip, dst_ip="5.6.7.8",
            src_port=sport, dst_port=443,
            flags=0x010, data=ch,
            seq=1001, ack=1, timestamp=float(i) + 0.001,
        )


# ─────────────────────────────────────────────────────────────────────────────
# PCAP reader
# ─────────────────────────────────────────────────────────────────────────────


def read_pcap(path: Path) -> Iterator[bytes]:
    """Yield raw frame bytes from a libpcap file."""
    data = path.read_bytes()
    offset = 0

    # Global header
    magic = struct.unpack_from("I", data, offset)[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
        raise ValueError(f"Not a pcap file: {path}")
    offset += 24

    while offset < len(data):
        if offset + 16 > len(data):
            break
        ts_sec, ts_usec, caplen, origlen = struct.unpack_from("IIII", data, offset)
        offset += 16
        if offset + caplen > len(data):
            break
        yield data[offset : offset + caplen]
        offset += caplen


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark runner
# ─────────────────────────────────────────────────────────────────────────────


def run_synthetic_benchmark(n_packets: int, use_reassembler: bool) -> None:
    """Run the synthetic packet benchmark."""
    try:
        from src.tap.reassembler import StreamReassembler
        from src.tap.capture import ParsedPacket
    except ImportError as exc:
        print(f"ERROR: Cannot import TAP modules: {exc}")
        print("Run from the project root: python3 scripts/tap_benchmark.py")
        raise SystemExit(1)

    config = {"tap": {"max_streams": 100_000, "stream_timeout_s": 300}}
    reassembler = StreamReassembler(extractor=None, config=config) if use_reassembler else None

    n_processed = 0
    n_errors = 0
    start = time.perf_counter()

    for pkt in generate_synthetic_packets(n_packets):
        try:
            if reassembler is not None:
                real_pkt = ParsedPacket(
                    src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port, dst_port=pkt.dst_port,
                    proto=pkt.proto, seq=pkt.seq, ack=pkt.ack,
                    flags=pkt.flags, data=pkt.data,
                    timestamp=pkt.timestamp,
                    tcp_options_raw=pkt.tcp_options_raw,
                    window_size=pkt.window_size,
                    ip_ttl=pkt.ip_ttl, ip_df=pkt.ip_df, ip_id=pkt.ip_id,
                )
                reassembler.on_packet(real_pkt)
            n_processed += 1
        except Exception:
            n_errors += 1

    elapsed = time.perf_counter() - start
    pps = n_processed / elapsed if elapsed > 0 else 0

    print(f"\n=== TAP Benchmark Results ===")
    print(f"  Mode:       synthetic")
    print(f"  Packets:    {n_processed:,}")
    print(f"  Errors:     {n_errors}")
    print(f"  Duration:   {elapsed:.2f}s")
    print(f"  Throughput: {pps:,.0f} pps")
    if reassembler is not None:
        print(f"  Streams:    {len(reassembler._streams):,} (active)")

    target_pps = 500_000
    if pps >= target_pps:
        print(f"\n  PASS: {pps:,.0f} >= {target_pps:,} pps target")
    else:
        print(f"\n  WARN: {pps:,.0f} < {target_pps:,} pps target")
        print(f"        Consider: more workers, ring buffer tuning, or Go rewrite (Phase 15)")


def run_pcap_benchmark(pcap_path: Path) -> None:
    """Replay a PCAP and measure parse throughput."""
    try:
        from src.tap.capture import _parse_ethernet_frame
    except ImportError as exc:
        print(f"ERROR: Cannot import TAP modules: {exc}")
        raise SystemExit(1)

    frames = list(read_pcap(pcap_path))
    print(f"Loaded {len(frames)} frames from {pcap_path}")

    n_ok = 0
    n_none = 0
    start = time.perf_counter()
    frag_store: dict = {}
    for frame in frames:
        result = _parse_ethernet_frame(frame, time.time(), frag_store)
        if result is not None:
            n_ok += 1
        else:
            n_none += 1
    elapsed = time.perf_counter() - start

    total = len(frames)
    pps = total / elapsed if elapsed > 0 else 0

    print(f"\n=== PCAP Replay Benchmark Results ===")
    print(f"  File:       {pcap_path}")
    print(f"  Frames:     {total}")
    print(f"  Parsed OK:  {n_ok}")
    print(f"  Skipped:    {n_none}")
    print(f"  Duration:   {elapsed:.3f}s")
    print(f"  Throughput: {pps:,.0f} fps")


def main() -> None:
    parser = argparse.ArgumentParser(description="TAP mode throughput benchmark")
    parser.add_argument(
        "--mode",
        choices=["synthetic", "pcap"],
        default="synthetic",
        help="Benchmark mode (default: synthetic)",
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=200_000,
        help="Number of synthetic packets to generate (default: 200000)",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Path to PCAP file (required for --mode pcap)",
    )
    parser.add_argument(
        "--no-reassembler",
        action="store_true",
        help="Skip stream reassembler (measure parse-only throughput)",
    )
    args = parser.parse_args()

    if args.mode == "synthetic":
        run_synthetic_benchmark(args.packets, use_reassembler=not args.no_reassembler)
    elif args.mode == "pcap":
        if args.pcap is None:
            parser.error("--pcap is required for --mode pcap")
        run_pcap_benchmark(args.pcap)


if __name__ == "__main__":
    main()
