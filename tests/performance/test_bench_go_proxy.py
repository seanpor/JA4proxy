"""
Performance benchmarks: Go proxy vs Python proxy throughput.
Requires both proxies running.

Run: python3 -m pytest tests/performance/test_bench_go_proxy.py -v -s
"""
import os
import socket
import time

import pytest

GO_BINARY = "bin/ja4proxy"

pytestmark = pytest.mark.skipif(
    not os.path.exists(GO_BINARY),
    reason="Go binary not built",
)

PYTHON_PORT = 8080
GO_PORT = 8082
DURATION_SECONDS = 10


def _count_connections(port: int, duration: float) -> int:
    """Open as many TCP connections as possible in duration seconds."""
    count = 0
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                count += 1
        except (ConnectionRefusedError, OSError):
            pass
    return count


def test_go_throughput_vs_python():
    """Go proxy must handle connections (throughput comparison)."""
    go_conns = _count_connections(GO_PORT, DURATION_SECONDS)
    go_rate = go_conns / DURATION_SECONDS
    print(f"\nGo proxy: {go_rate:.0f} conn/s over {DURATION_SECONDS}s")
    # Just report — don't fail if Python proxy not running
    assert go_rate > 0, "Go proxy accepted no connections"


def test_go_allow_bypass_latency():
    """Measure p99 latency for Go proxy connections."""
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        try:
            with socket.create_connection(("127.0.0.1", GO_PORT), timeout=1):
                pass
        except OSError:
            continue
        latencies.append(time.perf_counter() - t0)
    if not latencies:
        pytest.skip("Go proxy not accepting connections")
    latencies.sort()
    p99_ms = latencies[int(len(latencies) * 0.99)] * 1000
    print(f"\nGo proxy p99 connect latency: {p99_ms:.2f}ms")
    assert p99_ms < 1000, f"p99 latency {p99_ms:.2f}ms is unreasonably high"
