"""
TCP stream reassembler for TAP mode (Phase 20, Group 4).

Classes:
    TCPStream         — per-connection state
    StreamReassembler — tracks streams for one worker shard

The reassembler processes ParsedPacket objects from PacketCapture/PcapReplay,
reassembles in-order TCP payload data (with out-of-order buffering), and
invokes FingerprintExtractor callbacks when stream data arrives or closes.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from sortedcontainers import SortedList  # type: ignore[import]

from src.tap.capture import ParsedPacket

if TYPE_CHECKING:
    pass  # Forward-declaration placeholder for FingerprintExtractor

logger = logging.getLogger(__name__)

# TCP flag bitmasks
TCP_FIN = 0x001
TCP_SYN = 0x002
TCP_RST = 0x004
TCP_ACK = 0x010

StreamKey = tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port)


# ---------------------------------------------------------------------------
# TCPStream
# ---------------------------------------------------------------------------


@dataclass
class TCPStream:
    """Per-connection state tracked by StreamReassembler."""

    key: StreamKey
    conn_id: str  # UUID, generated at SYN
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    state: str  # "SYN_RCVD" | "ESTABLISHED" | "CLOSING" | "CLOSED"
    client_seq: int = 0
    server_seq: int = 0
    # Out-of-order buffers: sorted list of (seq, data) tuples
    client_buf: SortedList = field(default_factory=SortedList)
    server_buf: SortedList = field(default_factory=SortedList)
    # Assembled bytes (capped at max_stream_buffer_bytes)
    client_data: bytearray = field(default_factory=bytearray)
    server_data: bytearray = field(default_factory=bytearray)
    # Timing
    syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    ack_ts: Optional[float] = None
    # Raw TCP options from SYN / SYN-ACK for JA4T
    syn_tcp_opts: bytes = b""
    synack_tcp_opts: bytes = b""
    last_activity: float = field(default_factory=time.monotonic)
    fingerprints: dict = field(default_factory=dict)
    score_emitted: bool = False


# ---------------------------------------------------------------------------
# StreamReassembler
# ---------------------------------------------------------------------------


class StreamReassembler:
    """Tracks TCP streams for one worker shard.

    Instantiated once per StreamWorker. All packets for the shard are
    processed by ``on_packet()``.

    Args:
        extractor:  FingerprintExtractor; receives ``on_stream_data()`` and
                    ``on_stream_close()`` callbacks.  May be None in tests.
        config:     Proxy config dict; reads ``tap.max_streams`` (default
                    100_000), ``tap.stream_timeout_s`` (default 300),
                    ``tap.max_stream_buffer_bytes`` (default 1_048_576).
    """

    def __init__(self, extractor: Any, config: dict) -> None:
        tap_cfg = config.get("tap") or {}
        self._max_streams: int = int(tap_cfg.get("max_streams", 100_000))
        self._stream_timeout_s: float = float(tap_cfg.get("stream_timeout_s", 300))
        self._max_buf_bytes: int = int(
            tap_cfg.get("max_stream_buffer_bytes", 1_048_576)
        )
        self._extractor = extractor
        # Stream table: StreamKey → TCPStream
        self._streams: dict[StreamKey, TCPStream] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_packet(self, pkt: ParsedPacket) -> None:
        """Process one parsed packet and update stream state."""
        if pkt.proto != "tcp":
            return

        key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        rev_key = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)

        flags = pkt.flags

        # SYN without ACK → new stream
        if (flags & TCP_SYN) and not (flags & TCP_ACK):
            self._on_syn(key, pkt)
            return

        # SYN-ACK → server responding to SYN
        if (flags & TCP_SYN) and (flags & TCP_ACK):
            stream = self._streams.get(rev_key)
            if stream is not None:
                self._on_synack(stream, pkt)
            return

        # RST or FIN → close stream
        if flags & (TCP_RST | TCP_FIN):
            stream = self._streams.get(key) or self._streams.get(rev_key)
            if stream is not None:
                self._on_fin_rst(stream, pkt)
            return

        # Data / ACK packet
        stream = self._streams.get(key) or self._streams.get(rev_key)
        if stream is not None:
            self._on_data(stream, pkt)

    def expire_idle(self) -> int:
        """Evict streams silent for longer than *stream_timeout_s*.

        Returns the number of streams evicted.
        """
        cutoff = time.monotonic() - self._stream_timeout_s
        to_evict = [
            k for k, s in self._streams.items() if s.last_activity < cutoff
        ]
        for k in to_evict:
            stream = self._streams.pop(k, None)
            if stream is not None and stream.state != "CLOSED":
                stream.state = "CLOSED"
                self._call_extractor_close(stream)
        return len(to_evict)

    def evict_oldest(self, n: int) -> int:
        """Evict the *n* oldest streams when the table is full.

        Returns the number of streams actually evicted.
        """
        if n <= 0 or not self._streams:
            return 0
        sorted_streams = sorted(
            self._streams.items(), key=lambda kv: kv[1].last_activity
        )
        count = 0
        for k, stream in sorted_streams[:n]:
            self._streams.pop(k, None)
            stream.state = "CLOSED"
            self._call_extractor_close(stream)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Private stream handlers
    # ------------------------------------------------------------------

    def _on_syn(self, key: StreamKey, pkt: ParsedPacket) -> None:
        """Handle incoming SYN: create a new stream in SYN_RCVD state."""
        if len(self._streams) >= self._max_streams:
            self.evict_oldest(max(1, self._max_streams // 100))

        conn_id = str(uuid.uuid4())
        stream = TCPStream(
            key=key,
            conn_id=conn_id,
            client_ip=pkt.src_ip,
            client_port=pkt.src_port,
            server_ip=pkt.dst_ip,
            server_port=pkt.dst_port,
            state="SYN_RCVD",
            client_seq=pkt.seq + 1,  # next expected
            syn_ts=pkt.timestamp,
            syn_tcp_opts=pkt.tcp_options_raw,
            last_activity=time.monotonic(),
        )
        self._streams[key] = stream

    def _on_synack(self, stream: TCPStream, pkt: ParsedPacket) -> None:
        """Handle SYN-ACK: record server sequence and move to ESTABLISHED."""
        stream.server_seq = pkt.seq + 1  # next expected from server
        stream.synack_ts = pkt.timestamp
        stream.synack_tcp_opts = pkt.tcp_options_raw
        stream.state = "ESTABLISHED"
        stream.last_activity = time.monotonic()

    def _on_data(self, stream: TCPStream, pkt: ParsedPacket) -> None:
        """Handle data / pure ACK packets."""
        stream.last_activity = time.monotonic()
        if not pkt.data:
            return

        # Determine direction
        if (pkt.src_ip, pkt.src_port) == (stream.client_ip, stream.client_port):
            self._append_data(stream, pkt.data, "client", pkt.seq)
        else:
            self._append_data(stream, pkt.data, "server", pkt.seq)

        # Notify extractor incrementally
        if self._extractor is not None and hasattr(
            self._extractor, "on_stream_data"
        ):
            self._extractor.on_stream_data(stream)

    def _on_fin_rst(self, stream: TCPStream, pkt: ParsedPacket) -> None:
        """Handle FIN or RST: transition stream to CLOSED."""
        stream.state = "CLOSING" if pkt.flags & TCP_FIN else "CLOSED"
        stream.last_activity = time.monotonic()

        # Remove from the stream table
        self._streams.pop(stream.key, None)
        # Also remove reverse direction entry if present
        rev_key = (
            stream.server_ip,
            stream.server_port,
            stream.client_ip,
            stream.client_port,
        )
        self._streams.pop(rev_key, None)

        stream.state = "CLOSED"
        self._call_extractor_close(stream)

    def _append_data(
        self,
        stream: TCPStream,
        data: bytes,
        direction: str,
        seq: int,
    ) -> None:
        """Append *data* to the correct side of the stream, handling re-ordering.

        Data exceeding *max_stream_buffer_bytes* causes the stream to be
        dropped (evicted) rather than silently truncated, to avoid producing
        incomplete fingerprints.
        """
        if direction == "client":
            expected = stream.client_seq
            buf = stream.client_buf
            assembled = stream.client_data
        else:
            expected = stream.server_seq
            buf = stream.server_buf
            assembled = stream.server_data

        # Detect retransmission
        if seq < expected and seq + len(data) <= expected:
            return  # entirely old — discard

        if seq == expected:
            # In-order: append directly
            assembled.extend(data)
            expected += len(data)
            # Flush buffered out-of-order segments
            while buf and buf[0][0] <= expected:
                seg_seq, seg_data = buf[0]
                buf.pop(0)
                overlap = expected - seg_seq
                if overlap < len(seg_data):
                    assembled.extend(seg_data[overlap:])
                    expected += len(seg_data) - overlap
        else:
            # Out-of-order: buffer it
            buf.add((seq, data))

        # Update expected
        if direction == "client":
            stream.client_seq = expected
        else:
            stream.server_seq = expected

        # Check buffer cap
        if len(assembled) > self._max_buf_bytes:
            # Drop stream — buffer overflow
            self._streams.pop(stream.key, None)

    def _flush_reorder_buf(self, stream: TCPStream, direction: str) -> None:
        """Flush any buffered out-of-order segments now that new data arrived."""
        if direction == "client":
            buf = stream.client_buf
            assembled = stream.client_data
            expected = stream.client_seq
        else:
            buf = stream.server_buf
            assembled = stream.server_data
            expected = stream.server_seq

        while buf and buf[0][0] <= expected:
            seg_seq, seg_data = buf[0]
            buf.pop(0)
            overlap = expected - seg_seq
            if overlap < len(seg_data):
                assembled.extend(seg_data[overlap:])
                expected += len(seg_data) - overlap

        if direction == "client":
            stream.client_seq = expected
        else:
            stream.server_seq = expected

    def _call_extractor_close(self, stream: TCPStream) -> None:
        """Call extractor.on_stream_close() if extractor is wired."""
        if self._extractor is not None and hasattr(
            self._extractor, "on_stream_close"
        ):
            try:
                self._extractor.on_stream_close(stream)
            except Exception:
                logger.exception("extractor.on_stream_close raised")

    def __len__(self) -> int:
        """Return number of active streams."""
        return len(self._streams)
