"""
Performance benchmarks: Go proxy throughput and latency.

Measures connection throughput (conn/s) and p99 latency for the Go proxy.

Run: python3 -m pytest tests/performance/test_bench_go_proxy.py -v -s

Environment variables:
  GO_PROXY_HOST, GO_PROXY_PORT  -- Go proxy address (default: HOST_PORT_DIRECT, .env, or 8080)
"""

import concurrent.futures
import os
import socket
import statistics
import time
from pathlib import Path

import pytest

# ── Configuration ─────────────────────────────────────────────────────────────


def _resolve_proxy_port() -> int:
    """Resolve the Go proxy port from environment, .env file, or standard default."""
    if "GO_PROXY_PORT" in os.environ:
        return int(os.environ["GO_PROXY_PORT"])
    if "HOST_PORT_DIRECT" in os.environ:
        return int(os.environ["HOST_PORT_DIRECT"])

    # Attempt to read from .env if present
    env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("HOST_PORT_DIRECT="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val.isdigit():
                        return int(val)
        except OSError:
            pass

    return 8080


GO_PROXY_HOST = os.environ.get("GO_PROXY_HOST", "127.0.0.1")
GO_PROXY_PORT = _resolve_proxy_port()
GO_BINARY = os.environ.get("GO_BINARY", "bin/ja4pd")

THROUGHPUT_DURATION = 10  # seconds for throughput test
THROUGHPUT_THREADS = 10
SUSTAINED_CONNECTIONS = 1000
LATENCY_SAMPLES = 100

# All tests in this file require a live Go proxy on GO_PROXY_PORT.
# Excluded from `make test`; use `make test-live` or `make test-go-perf` when services are running.
pytestmark = [
    pytest.mark.live_services,
]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _one_connection(host: str, port: int, timeout: float = 1.0) -> float:
    """Attempt one TCP connection; return elapsed seconds or -1 on failure."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return time.perf_counter() - t0
    except OSError:
        return -1.0


def _connections_in_duration(
    host: str, port: int, duration: float, threads: int
) -> tuple:
    """Open as many connections as possible across *threads* workers for *duration* s.

    Returns (total_connections, successful_connections, elapsed_seconds).
    """
    deadline = time.monotonic() + duration

    def _worker():
        count = 0
        while time.monotonic() < deadline:
            if _one_connection(host, port, timeout=0.5) >= 0:
                count += 1
        return count

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_worker) for _ in range(threads)]
        counts = [f.result() for f in concurrent.futures.as_completed(futures)]
    elapsed = time.monotonic() - t0

    total = sum(counts)
    return total, elapsed


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_go_proxy_connection_throughput():
    """Go proxy must sustain a measurable connection rate under multithreaded load.

    Uses THROUGHPUT_THREADS threads for THROUGHPUT_DURATION seconds.
    Asserts that the proxy accepts at least 1 conn/s (sanity floor only).
    """
    if not _check_port(GO_PROXY_HOST, GO_PROXY_PORT):
        pytest.skip(f"Go proxy not reachable at {GO_PROXY_HOST}:{GO_PROXY_PORT}")

    total, elapsed = _connections_in_duration(
        GO_PROXY_HOST, GO_PROXY_PORT, THROUGHPUT_DURATION, THROUGHPUT_THREADS
    )
    rate = total / elapsed if elapsed > 0 else 0

    print(
        f"\nGo proxy throughput: {total} connections in {elapsed:.1f}s "
        f"= {rate:.1f} conn/s ({THROUGHPUT_THREADS} threads)"
    )

    assert rate > 1.0, f"Go proxy accepted only {rate:.1f} conn/s — expected > 1 conn/s"


def test_go_proxy_p99_latency():
    """Measure p99 TCP connect latency for Go proxy over LATENCY_SAMPLES sequential connections.

    Asserts p99 < 1000ms (sanity floor; typical value is <5ms on localhost).
    """
    if not _check_port(GO_PROXY_HOST, GO_PROXY_PORT):
        pytest.skip(f"Go proxy not reachable at {GO_PROXY_HOST}:{GO_PROXY_PORT}")

    latencies = []
    for _ in range(LATENCY_SAMPLES):
        elapsed = _one_connection(GO_PROXY_HOST, GO_PROXY_PORT, timeout=1.0)
        if elapsed >= 0:
            latencies.append(elapsed * 1000)  # convert to ms

    if not latencies:
        pytest.skip("Go proxy accepted no connections during latency measurement")

    latencies.sort()
    p50_ms = statistics.median(latencies)
    p99_idx = max(0, int(len(latencies) * 0.99) - 1)
    p99_ms = latencies[p99_idx]
    mean_ms = statistics.mean(latencies)

    print(
        f"\nGo proxy latency over {len(latencies)} connections:\n"
        f"  mean:  {mean_ms:.2f}ms\n"
        f"  p50:   {p50_ms:.2f}ms\n"
        f"  p99:   {p99_ms:.2f}ms"
    )

    assert (
        p99_ms < 1000.0
    ), f"p99 latency {p99_ms:.2f}ms exceeds 1000ms — proxy may be overloaded"


def test_go_proxy_sustained_load():
    """Go proxy must survive SUSTAINED_CONNECTIONS sequential connections without crashing.

    After completing all connections, verifies the proxy is still accepting new ones.
    """
    if not _check_port(GO_PROXY_HOST, GO_PROXY_PORT):
        pytest.skip(f"Go proxy not reachable at {GO_PROXY_HOST}:{GO_PROXY_PORT}")

    successes = 0
    failures = 0

    for i in range(SUSTAINED_CONNECTIONS):
        elapsed = _one_connection(GO_PROXY_HOST, GO_PROXY_PORT, timeout=2.0)
        if elapsed >= 0:
            successes += 1
        else:
            failures += 1

    print(
        f"\nSustained load: {successes} ok, {failures} failed "
        f"out of {SUSTAINED_CONNECTIONS} connections"
    )

    # After the load test, proxy must still be alive
    assert _check_port(GO_PROXY_HOST, GO_PROXY_PORT, timeout=2.0), (
        f"Go proxy is no longer accepting connections after "
        f"{SUSTAINED_CONNECTIONS} sequential connections"
    )

    # Tolerate up to 10% failure rate (could be rate-limiting or backpressure)
    fail_pct = (failures / SUSTAINED_CONNECTIONS) * 100
    assert fail_pct < 10.0, (
        f"Too many connection failures during sustained load: "
        f"{failures}/{SUSTAINED_CONNECTIONS} ({fail_pct:.1f}%)"
    )
