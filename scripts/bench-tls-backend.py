#!/usr/bin/env python3
"""
Minimal asyncio TLS echo backend for benchmark use.

Accepts TLS connections, sends a single HTTP 200 response, and closes.
Designed to sustain 2000+ conn/s so it is never the bottleneck during
Go vs Python proxy benchmarks.

Usage:
    python3 scripts/bench-tls-backend.py [--host HOST] [--port PORT]
    python3 scripts/bench-tls-backend.py --port 8444

The server uses ssl/certs/backend.crt and ssl/private/backend.key by default.
Those are the same self-signed certs used by the Docker mock-backend service.

Exit: Ctrl-C or SIGTERM.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import ssl
import sys
import time
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  bench-backend  %(levelname)s  %(message)s",
)
log = logging.getLogger("bench-backend")

# ── Constants ─────────────────────────────────────────────────────────────────
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"OK"
)

# ── Connection handler ────────────────────────────────────────────────────────

async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Accept connection, drain any request bytes, send 200, close."""
    try:
        # Drain the request without blocking indefinitely.
        # We don't need to parse it — just acknowledge and close.
        try:
            await asyncio.wait_for(reader.read(4096), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        writer.write(RESPONSE)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
        pass  # client closed early; fine
    finally:
        writer.close()


# ── Stats tracker ─────────────────────────────────────────────────────────────

class Stats:
    """Thread-safe connection counter with periodic reporting."""

    def __init__(self) -> None:
        self._total = 0
        self._window_start = time.monotonic()
        self._window_count = 0

    def record(self) -> None:
        self._total += 1
        self._window_count += 1

    def maybe_report(self, interval: float = 5.0) -> None:
        now = time.monotonic()
        elapsed = now - self._window_start
        if elapsed >= interval:
            rate = self._window_count / elapsed
            log.info("connections: total=%d  rate=%.0f/s", self._total, rate)
            self._window_start = now
            self._window_count = 0


_stats = Stats()


async def _handle_with_stats(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    _stats.record()
    _stats.maybe_report()
    await _handle(reader, writer)


# ── SSL context ────────────────────────────────────────────────────────────────

def _build_ssl_ctx(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    # Accept any cipher the client proposes — we're a benchmark backend, not production.
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


# ── Main ──────────────────────────────────────────────────────────────────────

async def _serve(host: str, port: int, ssl_ctx: ssl.SSLContext) -> None:
    server = await asyncio.start_server(
        _handle_with_stats,
        host=host,
        port=port,
        ssl=ssl_ctx,
        # Large backlog so burst connections don't get refused.
        backlog=1024,
        # Reuse address/port for fast restart.
        reuse_address=True,
        reuse_port=True,
    )
    addr = f"{host}:{port}"
    log.info("bench-tls-backend listening on %s (TLS)", addr)
    log.info("cert: %s", ssl_ctx)

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set_result, None)

    async with server:
        await stop

    log.info("shutting down")


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent

    p = argparse.ArgumentParser(description="Minimal TLS echo backend for benchmarking")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8444)
    p.add_argument(
        "--cert",
        type=Path,
        default=repo_root / "ssl" / "certs" / "backend.crt",
    )
    p.add_argument(
        "--key",
        type=Path,
        default=repo_root / "ssl" / "private" / "backend.key",
    )
    args = p.parse_args()

    if not args.cert.exists():
        log.error("cert not found: %s", args.cert)
        sys.exit(1)
    if not args.key.exists():
        log.error("key not found: %s", args.key)
        sys.exit(1)

    ssl_ctx = _build_ssl_ctx(args.cert, args.key)
    log.info("loaded cert %s", args.cert)

    asyncio.run(_serve(args.host, args.port, ssl_ctx))


if __name__ == "__main__":
    main()
