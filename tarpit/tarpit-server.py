#!/usr/bin/env python3
"""
Tarpit server for JA4proxy.

Accepts TCP connections and responds extremely slowly, wasting attacker
resources (sockets, threads, bandwidth) while costing us almost nothing.

The server pretends to be a slow TLS endpoint — it sends bytes at
~1 byte/second for a configurable duration, keeping the attacker's
connection open and their socket occupied.
"""

import asyncio
import logging
import os
import signal
import sys
import time

from prometheus_client import Counter, Gauge, Histogram, start_http_server

# Metrics
TARPIT_CONNECTIONS = Counter(
    'tarpit_connections_total', 'Total connections received'
)
TARPIT_ACTIVE = Gauge(
    'tarpit_active_connections', 'Currently active tarpit connections'
)
TARPIT_DURATION = Histogram(
    'tarpit_connection_duration_seconds', 'Time connections were held',
    buckets=[1, 5, 10, 15, 30, 45, 60, 90, 120]
)
TARPIT_BYTES_SENT = Counter(
    'tarpit_bytes_sent_total', 'Total bytes trickled to clients'
)

logger = logging.getLogger('tarpit')

# Configurable via environment
TARPIT_PORT = int(os.environ.get('TARPIT_PORT', 8888))
TARPIT_DURATION_SECS = int(os.environ.get('TARPIT_DURATION', 60))
TARPIT_METRICS_PORT = int(os.environ.get('TARPIT_METRICS_PORT', 9099))
TARPIT_MAX_CONNECTIONS = int(os.environ.get('TARPIT_MAX_CONNECTIONS', 1000))

# Fake TLS ServerHello-ish bytes to trickle (looks like a slow TLS server)
TARPIT_PAYLOAD = (
    b'\x16\x03\x03'  # TLS record header (handshake, TLS 1.2)
    + b'\x00' * 64    # Padding — sent very slowly
)


async def handle_tarpit_connection(reader, writer):
    """Hold a connection open, trickling bytes slowly."""
    client_addr = writer.get_extra_info('peername')
    client_ip = client_addr[0] if client_addr else 'unknown'

    TARPIT_CONNECTIONS.inc()
    TARPIT_ACTIVE.inc()
    start_time = time.time()

    logger.info(f"TARPIT: Trapping connection from {client_ip}")

    try:
        # Trickle bytes slowly
        for i in range(TARPIT_DURATION_SECS):
            byte_to_send = TARPIT_PAYLOAD[i % len(TARPIT_PAYLOAD):i % len(TARPIT_PAYLOAD) + 1]
            writer.write(byte_to_send)
            await writer.drain()
            TARPIT_BYTES_SENT.inc()
            await asyncio.sleep(1)
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        logger.debug(f"Tarpit connection ended: {e}")
    finally:
        duration = time.time() - start_time
        TARPIT_DURATION.observe(duration)
        TARPIT_ACTIVE.dec()
        logger.info(f"TARPIT: Released {client_ip} after {duration:.1f}s")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Start metrics server
    start_http_server(TARPIT_METRICS_PORT)
    logger.info(f"Tarpit metrics on :{TARPIT_METRICS_PORT}")

    # Semaphore to limit concurrent connections
    sem = asyncio.Semaphore(TARPIT_MAX_CONNECTIONS)

    async def limited_handler(reader, writer):
        async with sem:
            await handle_tarpit_connection(reader, writer)

    server = await asyncio.start_server(
        limited_handler, '0.0.0.0', TARPIT_PORT
    )
    logger.info(f"Tarpit server listening on :{TARPIT_PORT}")
    logger.info(f"Tarpit duration: {TARPIT_DURATION_SECS}s per connection")

    # Graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(server)))

    async with server:
        await server.serve_forever()


async def shutdown(server):
    logger.info("Tarpit shutting down...")
    server.close()
    await server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
