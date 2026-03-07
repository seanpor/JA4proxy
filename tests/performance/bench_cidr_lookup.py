"""Performance benchmarks: CIDR trie lookup (Phase 8).

Not run as part of the main test suite by default. Execute directly:
    python3 tests/performance/bench_cidr_lookup.py

Acceptance criteria (Phase 8):
- BlocklistManager.is_blocked() p99 < 10µs for 50k entries
- Full blocklist pipeline (all feeds) p99 < 15µs per connection
"""

import ipaddress
import random
import statistics
import time

from src.security.blocklists import BlocklistManager, FeedConfig


def _generate_cidrs(count: int) -> list[str]:
    """Generate count unique /24 CIDRs spread across the IPv4 space."""
    cidrs = []
    seen: set[str] = set()
    while len(cidrs) < count:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        cidr = f"{a}.{b}.{c}.0/24"
        if cidr not in seen:
            seen.add(cidr)
            cidrs.append(cidr)
    return cidrs


def bench_ipv4_lookup(entry_count: int = 50_000, iterations: int = 10_000) -> None:
    mgr = BlocklistManager()
    cidrs = _generate_cidrs(entry_count)
    mgr.load_cidrs(cidrs, "bench_feed")

    # Use a mix of blocked and unblocked IPs
    blocked_sample = "1.10.16.1"    # Not in our random list → unblocked
    test_ips = [f"10.{i % 256}.{(i // 256) % 256}.{i % 128}" for i in range(iterations)]

    latencies: list[float] = []
    for ip in test_ips:
        t0 = time.perf_counter()
        mgr.is_blocked(ip)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1e6)  # microseconds

    p50 = statistics.median(latencies)
    p99 = sorted(latencies)[int(len(latencies) * 0.99)]
    p_max = max(latencies)

    print(f"\nIPv4 CIDR lookup — {entry_count:,} entries, {iterations:,} iterations")
    print(f"  p50={p50:.2f}µs  p99={p99:.2f}µs  max={p_max:.2f}µs")

    assert p99 < 10.0, f"p99 {p99:.2f}µs exceeds 10µs target"
    print("  ✓ p99 < 10µs")


def bench_full_pipeline(entry_count: int = 50_000, iterations: int = 10_000) -> None:
    """Simulate the full hot-path blocklist check."""
    mgr = BlocklistManager()
    cidrs_bypass = _generate_cidrs(entry_count // 2)
    cidrs_scored = _generate_cidrs(entry_count // 2)

    bypass_cfg = FeedConfig(
        name="spamhaus_drop", url="", format="spamhaus",
        is_bypass=True, action="block", score=80, refresh_interval_seconds=43200,
    )
    scored_cfg = FeedConfig(
        name="custom_list", url="", format="cidr",
        is_bypass=False, action="block", score=60, refresh_interval_seconds=3600,
    )
    mgr.load_cidrs(cidrs_bypass, "spamhaus_drop", bypass_cfg)
    mgr.load_cidrs(cidrs_scored, "custom_list", scored_cfg)

    test_ips = [f"172.{i % 256}.{(i // 256) % 256}.1" for i in range(iterations)]

    latencies: list[float] = []
    for ip in test_ips:
        t0 = time.perf_counter()
        blocked, feed = mgr.is_blocked(ip)
        if not blocked:
            mgr.get_signals(ip)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1e6)

    p50 = statistics.median(latencies)
    p99 = sorted(latencies)[int(len(latencies) * 0.99)]
    p_max = max(latencies)

    print(f"\nFull pipeline check — {entry_count:,} entries, {iterations:,} iterations")
    print(f"  p50={p50:.2f}µs  p99={p99:.2f}µs  max={p_max:.2f}µs")

    assert p99 < 15.0, f"p99 {p99:.2f}µs exceeds 15µs target"
    print("  ✓ p99 < 15µs")


if __name__ == "__main__":
    print("=== Phase 8 — Blocklist Performance Benchmarks ===")
    bench_ipv4_lookup()
    bench_full_pipeline()
    print("\nAll benchmarks passed.")
