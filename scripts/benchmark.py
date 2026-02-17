#!/usr/bin/env python3
"""
JA4proxy Performance Benchmark

Measures maximum throughput with controlled good/bad traffic rates.
Tests 1, 2, and 4 proxy instances with HAProxy load balancing.

Usage:
    python3 scripts/benchmark.py --good-rate 5 --duration 30
    python3 scripts/benchmark.py --good-rate 10 --duration 60 --bad-rates 50,100,200,500
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BenchResult:
    """Results from a single benchmark run."""
    scenario: str
    proxy_count: int
    good_rate_target: float
    bad_rate_target: float
    duration: float
    # Measured
    total_connections: int = 0
    total_good: int = 0
    total_bad: int = 0
    good_allowed: int = 0
    good_blocked: int = 0
    bad_allowed: int = 0
    bad_blocked: int = 0
    errors: int = 0
    elapsed: float = 0.0

    @property
    def actual_rate(self):
        return self.total_connections / self.elapsed if self.elapsed > 0 else 0

    @property
    def good_pass_rate(self):
        return self.good_allowed / self.total_good * 100 if self.total_good > 0 else 0

    @property
    def bad_block_rate(self):
        return self.bad_blocked / self.total_bad * 100 if self.total_bad > 0 else 0

    @property
    def false_positive_rate(self):
        return self.good_blocked / self.total_good * 100 if self.total_good > 0 else 0

    @property
    def false_negative_rate(self):
        return self.bad_allowed / self.total_bad * 100 if self.total_bad > 0 else 0


# SSL contexts — pre-built for speed
def make_browser_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx

def make_bot_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5")
    # No ALPN — this is the key differentiator
    return ctx


BROWSER_CTX = make_browser_ctx()
BOT_CTX = make_bot_ctx()
HTTP_REQ = b"GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n"


class RateController:
    """Controls send rate using token bucket."""

    def __init__(self, rate: float):
        self.rate = rate
        self.interval = 1.0 / rate if rate > 0 else 1.0
        self.lock = threading.Lock()
        self.next_send = time.monotonic()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_send:
                time.sleep(self.next_send - now)
            self.next_send = max(now, self.next_send) + self.interval


def try_connection(host: str, port: int, ctx: ssl.SSLContext, is_good: bool) -> dict:
    """Make a single TLS connection, return result dict."""
    result = {"good": is_good, "allowed": False, "blocked": False, "error": False}
    sock = None
    tls_sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        tls_sock = ctx.wrap_socket(sock, server_hostname="backend")
        tls_sock.send(HTTP_REQ)
        resp = tls_sock.recv(512)
        result["allowed"] = True
    except (ssl.SSLError, ConnectionResetError, ConnectionRefusedError, socket.timeout, OSError):
        result["blocked"] = True
    except Exception:
        result["error"] = True
    finally:
        try:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()
        except Exception:
            pass
    return result


def run_benchmark(host: str, port: int, good_rate: float, bad_rate: float,
                  duration: float, proxy_count: int) -> BenchResult:
    """Run a single benchmark scenario."""
    result = BenchResult(
        scenario=f"{proxy_count}x proxy, {good_rate:.0f} good/s + {bad_rate:.0f} bad/s",
        proxy_count=proxy_count,
        good_rate_target=good_rate,
        bad_rate_target=bad_rate,
        duration=duration,
    )

    good_ctrl = RateController(good_rate)
    bad_ctrl = RateController(bad_rate)
    running = True
    lock = threading.Lock()

    def record(r):
        with lock:
            if r["good"]:
                result.total_good += 1
                if r["allowed"]:
                    result.good_allowed += 1
                elif r["blocked"]:
                    result.good_blocked += 1
                else:
                    result.errors += 1
            else:
                result.total_bad += 1
                if r["allowed"]:
                    result.bad_allowed += 1
                elif r["blocked"]:
                    result.bad_blocked += 1
                else:
                    result.errors += 1
            result.total_connections += 1

    def good_sender():
        while running:
            good_ctrl.wait()
            if not running:
                break
            r = try_connection(host, port, BROWSER_CTX, True)
            record(r)

    def bad_sender():
        while running:
            bad_ctrl.wait()
            if not running:
                break
            r = try_connection(host, port, BOT_CTX, False)
            record(r)

    # Use enough threads: 1 per ~20 conn/s for good, 1 per ~50 conn/s for bad
    good_threads = max(1, int(good_rate / 15) + 1)
    bad_threads = max(2, int(bad_rate / 30) + 1)

    start = time.monotonic()
    threads = []

    for _ in range(good_threads):
        t = threading.Thread(target=good_sender, daemon=True)
        t.start()
        threads.append(t)

    for _ in range(bad_threads):
        t = threading.Thread(target=bad_sender, daemon=True)
        t.start()
        threads.append(t)

    # Progress display
    while time.monotonic() - start < duration:
        elapsed = time.monotonic() - start
        rate = result.total_connections / elapsed if elapsed > 0 else 0
        print(f"\r  [{elapsed:.0f}s/{duration:.0f}s] "
              f"Total: {result.total_connections:,} ({rate:.0f}/s) | "
              f"Good: {result.good_allowed}/{result.total_good} | "
              f"Bad blocked: {result.bad_blocked}/{result.total_bad}",
              end="", flush=True)
        time.sleep(0.5)

    running = False
    for t in threads:
        t.join(timeout=5)

    result.elapsed = time.monotonic() - start
    print()  # newline after progress
    return result


def print_result(r: BenchResult):
    """Print a single benchmark result."""
    print(f"\n  {'─' * 60}")
    print(f"  Scenario:          {r.scenario}")
    print(f"  Duration:          {r.elapsed:.1f}s")
    print(f"  Total connections: {r.total_connections:,} ({r.actual_rate:.0f}/s)")
    print(f"  Good traffic:      {r.total_good:,} sent, {r.good_allowed:,} allowed, "
          f"{r.good_blocked:,} blocked")
    print(f"  Bad traffic:       {r.total_bad:,} sent, {r.bad_blocked:,} blocked, "
          f"{r.bad_allowed:,} leaked")
    print(f"  Errors:            {r.errors:,}")
    print(f"  ────────────────────────────────────────")
    print(f"  Good pass rate:    {r.good_pass_rate:.1f}%  "
          f"{'✅' if r.good_pass_rate >= 99 else '⚠️' if r.good_pass_rate >= 90 else '❌'}")
    print(f"  Bad block rate:    {r.bad_block_rate:.1f}%  "
          f"{'✅' if r.bad_block_rate >= 95 else '⚠️' if r.bad_block_rate >= 80 else '❌'}")
    print(f"  False positive:    {r.false_positive_rate:.1f}%")
    print(f"  False negative:    {r.false_negative_rate:.1f}%")
    print(f"  {'─' * 60}")


def format_markdown_report(results: List[BenchResult]) -> str:
    """Generate a markdown performance report."""
    lines = []
    lines.append("# JA4proxy Performance Benchmark Results\n")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Proxies | Good Rate | Bad Rate | Total Rate | "
                 "Good Pass % | Bad Block % | False +ve | False -ve |")
    lines.append("|---------|-----------|----------|------------|"
                 "-------------|-------------|-----------|-----------|")
    for r in results:
        lines.append(
            f"| {r.proxy_count} | {r.good_rate_target:.0f}/s | "
            f"{r.bad_rate_target:.0f}/s | {r.actual_rate:.0f}/s | "
            f"{r.good_pass_rate:.1f}% | {r.bad_block_rate:.1f}% | "
            f"{r.false_positive_rate:.1f}% | {r.false_negative_rate:.1f}% |"
        )

    # Group by proxy count
    by_proxy = defaultdict(list)
    for r in results:
        by_proxy[r.proxy_count].append(r)

    for count in sorted(by_proxy.keys()):
        group = by_proxy[count]
        lines.append(f"\n## {count}x Proxy Instance{'s' if count > 1 else ''}\n")
        lines.append(f"| Good/s | Bad/s | Total/s | Good Pass | Bad Block | "
                     f"Conns | Duration |")
        lines.append(f"|--------|-------|---------|-----------|-----------|"
                     f"-------|----------|")
        for r in group:
            lines.append(
                f"| {r.good_rate_target:.0f} | {r.bad_rate_target:.0f} | "
                f"{r.actual_rate:.0f} | "
                f"{r.good_pass_rate:.1f}% | {r.bad_block_rate:.1f}% | "
                f"{r.total_connections:,} | {r.elapsed:.0f}s |"
            )

        # Find max throughput with acceptable accuracy
        acceptable = [r for r in group if r.good_pass_rate >= 95 and r.bad_block_rate >= 90]
        if acceptable:
            best = max(acceptable, key=lambda r: r.actual_rate)
            lines.append(f"\n**Max throughput (≥95% good pass, ≥90% bad block): "
                         f"{best.actual_rate:.0f} conn/s** "
                         f"({best.good_rate_target:.0f} good + {best.bad_rate_target:.0f} bad)")

    # Scaling analysis
    if len(by_proxy) > 1:
        lines.append("\n## Scaling Analysis\n")
        base_count = min(by_proxy.keys())
        base_rates = {r.bad_rate_target: r for r in by_proxy[base_count]}
        for count in sorted(by_proxy.keys()):
            if count == base_count:
                continue
            lines.append(f"\n### {count}x vs {base_count}x\n")
            for r in by_proxy[count]:
                base = base_rates.get(r.bad_rate_target)
                if base and base.actual_rate > 0:
                    speedup = r.actual_rate / base.actual_rate
                    lines.append(f"- At {r.bad_rate_target:.0f} bad/s: "
                                 f"{speedup:.1f}x throughput "
                                 f"({base.actual_rate:.0f} → {r.actual_rate:.0f} conn/s)")

    lines.append(f"\n## Test Environment\n")
    lines.append("- **Platform:** Docker containers on single host")
    lines.append("- **Load balancer:** HAProxy 2.8 (TCP mode, TLS passthrough)")
    lines.append("- **Good traffic:** Browser-like TLS 1.3 with h2 ALPN (whitelisted)")
    lines.append("- **Bad traffic:** Bot-like TLS 1.3, no ALPN (rate-limited → tarpit → ban)")
    lines.append("- **Security pipeline:** GeoIP → Blacklist → Whitelist → Rate limit")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="JA4proxy Performance Benchmark")
    parser.add_argument("--host", default="proxy", help="Target host")
    parser.add_argument("--port", type=int, default=8080, help="Target port")
    parser.add_argument("--good-rate", type=float, default=5,
                        help="Good connections per second (default: 5)")
    parser.add_argument("--bad-rates", default="50,100,200,500",
                        help="Comma-separated bad rates to test")
    parser.add_argument("--duration", type=float, default=30,
                        help="Duration per test in seconds")
    parser.add_argument("--proxy-counts", default="1",
                        help="Comma-separated proxy instance counts to test")
    parser.add_argument("--output", default=None,
                        help="Output markdown file path")
    parser.add_argument("--json", default=None,
                        help="Output JSON results file path")
    args = parser.parse_args()

    bad_rates = [float(x) for x in args.bad_rates.split(",")]
    proxy_counts = [int(x) for x in args.proxy_counts.split(",")]

    print("=" * 70)
    print("  JA4proxy Performance Benchmark")
    print("=" * 70)
    print(f"  Target:       {args.host}:{args.port}")
    print(f"  Good rate:    {args.good_rate}/s")
    print(f"  Bad rates:    {bad_rates}")
    print(f"  Duration:     {args.duration}s per scenario")
    print(f"  Proxy counts: {proxy_counts}")
    print("=" * 70)

    all_results = []

    for pc in proxy_counts:
        print(f"\n{'━' * 70}")
        print(f"  Testing with {pc}x proxy instance{'s' if pc > 1 else ''}")
        print(f"{'━' * 70}")

        for bad_rate in bad_rates:
            print(f"\n▶ Scenario: {args.good_rate:.0f} good/s + {bad_rate:.0f} bad/s "
                  f"({pc}x proxy)")

            r = run_benchmark(args.host, args.port, args.good_rate, bad_rate,
                              args.duration, pc)
            print_result(r)
            all_results.append(r)

            # Brief pause between scenarios to let rate limiters reset
            print("  ⏳ Cooldown (5s)...")
            time.sleep(5)

    # Generate reports
    report = format_markdown_report(all_results)
    print("\n" + report)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n📄 Report saved to {args.output}")

    if args.json:
        json_data = []
        for r in all_results:
            json_data.append({
                "scenario": r.scenario,
                "proxy_count": r.proxy_count,
                "good_rate_target": r.good_rate_target,
                "bad_rate_target": r.bad_rate_target,
                "duration": r.duration,
                "elapsed": r.elapsed,
                "total_connections": r.total_connections,
                "actual_rate": r.actual_rate,
                "good_total": r.total_good,
                "good_allowed": r.good_allowed,
                "good_blocked": r.good_blocked,
                "bad_total": r.total_bad,
                "bad_allowed": r.bad_allowed,
                "bad_blocked": r.bad_blocked,
                "errors": r.errors,
                "good_pass_rate": r.good_pass_rate,
                "bad_block_rate": r.bad_block_rate,
            })
        with open(args.json, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"📊 JSON saved to {args.json}")


if __name__ == "__main__":
    main()
