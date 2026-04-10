#!/usr/bin/env python3
"""Phase 86c — Capacity sizing calculator for JA4proxy.

Takes traffic parameters and outputs a capacity recommendation based on
measured benchmark constants from docs/performance/benchmarks.md.

Usage:
    python3 scripts/capacity_calculator.py \
        --peak-connections-per-second 5000 \
        --p99-latency-budget-ms 10 \
        --redis-node-count 3 \
        --enable-analytics \
        --enable-beaconing-detection \
        --enable-abuseipdb \
        --cloud-provider aws \
        --region us-east-1

Output is a formatted capacity report with proxy node sizing, Redis sizing,
analytics sizing, and cloud cost estimates.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from math import ceil
from pathlib import Path

# ── Benchmark constants (sourced from docs/performance/benchmarks.md) ────────
# These MUST be updated when a new benchmark run is performed on reference
# hardware. Do NOT change these numbers based on estimates or vendor claims.
#
# Run `make bench-quick` to obtain current numbers, then record them in
# docs/performance/benchmarks.md and update the constants below.

@dataclass
class BenchmarkConstants:
    """Measured performance constants. Update after each benchmark run."""
    # Go proxy full signal path throughput (conn/s per single node)
    go_full_conn_s: float = 6200.0
    # Go proxy bypass path throughput (conn/s per single node)
    go_bypass_conn_s: float = 18400.0
    # Full signal path P99 latency (ms)
    go_p99_full_ms: float = 2.1
    # Bypass path P99 latency (ms)
    go_p99_bypass_ms: float = 0.4
    # Average Redis memory per key (bytes) — measured from INFO memory / DBSIZE
    redis_mem_per_key: float = 200.0
    # Analytics storage per connection (bytes) — measured from actual analytics
    # node disk usage over a known traffic volume
    analytics_bytes_per_conn: float = 500.0
    # Redis overhead factor (memory fragmentation, internal structures)
    redis_overhead: float = 1.3


# ── Cloud pricing (USD/month, on-demand, as of 2026-04) ──────────────────────

CLOUD_PRICES = {
    "aws": {
        "c7g.xlarge": 125,   # 4 vCPU, 8 GB — proxy
        "r7g.xlarge": 217,   # 4 vCPU, 32 GB — Redis
        "m7g.xlarge": 151,   # 4 vCPU, 16 GB — analytics
    },
    "azure": {
        "Standard_D4ps_v5": 140,       # 4 vCPU, 16 GB — proxy
        "Standard_E4ps_v5": 245,       # 4 vCPU, 32 GB — Redis
        "Standard_D4ps_v5_analytics": 140,  # 4 vCPU, 16 GB — analytics
    },
    "gcp": {
        "c4-standard-4": 135,   # 4 vCPU, 16 GB — proxy
        "r4-standard-4": 230,   # 4 vCPU, 32 GB — Redis
        "n4-standard-4": 130,   # 4 vCPU, 16 GB — analytics
    },
}


@dataclass
class CapacityReport:
    peak_rps: float
    p99_budget_ms: float
    redis_nodes: int
    features: list[str]
    cloud_provider: str
    region: str

    # Computed
    proxy_nodes_with_redundancy: int = 0
    proxy_nodes_min: int = 0
    cpu_per_proxy: str = "4 vCPU"
    ram_per_proxy: str = "8 GB"
    estimated_p99_ms: float = 0.0
    redis_memory_gb: float = 0.0
    redis_instance: str = ""
    analytics_cpu: str = ""
    analytics_ram: str = ""
    analytics_storage_gb: float = 0.0
    total_monthly_cost_usd: float = 0.0
    cost_breakdown: dict = field(default_factory=dict)

    # Benchmark constants used
    bench: BenchmarkConstants = field(default_factory=BenchmarkConstants)


def compute_capacity(
    peak_rps: float,
    p99_budget_ms: float,
    redis_nodes: int,
    features: list[str],
    cloud_provider: str,
    region: str,
    bench: BenchmarkConstants,
) -> CapacityReport:
    """Compute capacity recommendations."""
    report = CapacityReport(
        peak_rps=peak_rps,
        p99_budget_ms=p99_budget_ms,
        redis_nodes=redis_nodes,
        features=features,
        cloud_provider=cloud_provider,
        region=region,
        bench=bench,
    )

    # ── Proxy sizing ─────────────────────────────────────────────────────
    # Minimum nodes to handle peak RPS with full signal path
    report.proxy_nodes_min = max(1, ceil(peak_rps / bench.go_full_conn_s))
    # N+1 for redundancy
    report.proxy_nodes_with_redundancy = report.proxy_nodes_min + 1

    # Estimate P99 latency (full signal path, increases with load)
    load_factor = peak_rps / (report.proxy_nodes_min * bench.go_full_conn_s)
    report.estimated_p99_ms = bench.go_p99_full_ms * (1 + load_factor * 0.5)

    # ── Redis sizing ─────────────────────────────────────────────────────
    # Estimate key count: bans + beaconing state + return visitors
    # Rough formula: ~500 keys per RPS of peak traffic
    est_key_count = int(peak_rps * 500)
    redis_memory_bytes = est_key_count * bench.redis_mem_per_key * bench.redis_overhead
    redis_memory_gb = redis_memory_bytes / (1024 ** 3)
    # 2× headroom for growth
    redis_memory_gb *= 2
    report.redis_memory_gb = round(redis_memory_gb, 1)

    # Select Redis instance
    if redis_memory_gb < 8:
        report.redis_instance = "r7g.large" if cloud_provider == "aws" else "Redis 8GB"
    elif redis_memory_gb < 16:
        report.redis_instance = "r7g.xlarge" if cloud_provider == "aws" else "Redis 16GB"
    else:
        report.redis_instance = "r7g.2xlarge" if cloud_provider == "aws" else "Redis 32GB"

    # ── Analytics sizing ─────────────────────────────────────────────────
    has_analytics = "analytics" in features
    report.analytics_cpu = "4 vCPU" if has_analytics else "N/A"
    report.analytics_ram = "16 GB" if has_analytics else "N/A"

    if has_analytics:
        retention_days = 90
        est_storage = bench.analytics_bytes_per_conn * peak_rps * 86400 * retention_days
        report.analytics_storage_gb = round(est_storage / (1024 ** 3), 1)
    else:
        report.analytics_storage_gb = 0

    # ── Cost estimation ──────────────────────────────────────────────────
    prices = CLOUD_PRICES.get(cloud_provider, CLOUD_PRICES["aws"])
    proxy_price = prices.get("c7g.xlarge", 125)
    redis_price = prices.get("r7g.xlarge", 217)
    analytics_price = prices.get("m7g.xlarge", 151)

    proxy_cost = report.proxy_nodes_with_redundancy * proxy_price
    redis_cost = redis_nodes * redis_price
    analytics_cost = analytics_price if has_analytics else 0
    report.total_monthly_cost_usd = proxy_cost + redis_cost + analytics_cost
    report.cost_breakdown = {
        f"{report.proxy_nodes_with_redundancy}x proxy": f"${proxy_cost}/mo",
        f"{redis_nodes}x Redis": f"${redis_cost}/mo",
        "analytics": f"${analytics_cost}/mo" if has_analytics else "disabled",
        "total": f"${report.total_monthly_cost_usd}/mo",
    }

    return report


def print_report(report: CapacityReport) -> None:
    """Print a formatted capacity report."""
    sep = "═" * 70
    print(f"\n{sep}")
    print("JA4proxy Capacity Recommendation")
    print(sep)
    print("\nInput parameters:")
    print(f"  Peak connections/second:  {report.peak_rps:,.0f}")
    print(f"  P99 latency budget:       {report.p99_budget_ms}ms")
    print(f"  Redis nodes:              {report.redis_nodes}")
    print(f"  Features enabled:         {', '.join(report.features) if report.features else 'core only'}")
    print(f"  Cloud provider:           {report.cloud_provider} ({report.region})")
    print("  Benchmark source:         docs/performance/benchmarks.md")

    print("\nProxy node sizing:")
    print(f"  Minimum node count:       {report.proxy_nodes_min}")
    print(f"  Recommended (N+1):        {report.proxy_nodes_with_redundancy}")
    print(f"  CPU per node:             {report.cpu_per_proxy}")
    print(f"  RAM per node:             {report.ram_per_proxy}")
    print(f"  Estimated P99 latency:    {report.estimated_p99_ms:.1f}ms "
          f"(budget: {report.p99_budget_ms}ms)")

    print("\nRedis sizing:")
    print(f"  Estimated memory:         {report.redis_memory_gb} GB (with 2× headroom)")
    print(f"  Recommended instance:     {report.redis_instance}")

    if report.analytics_storage_gb > 0:
        print("\nAnalytics node:")
        print(f"  CPU:                      {report.analytics_cpu}")
        print(f"  RAM:                      {report.analytics_ram}")
        print(f"  Storage (90-day):         {report.analytics_storage_gb} GB")

    print(f"\nEstimated cloud cost ({report.cloud_provider} {report.region}):")
    for item, cost in report.cost_breakdown.items():
        label = f"  {item}"
        print(f"{label:<35s} {cost}")

    # Validation
    print(f"\n{'─' * 70}")
    if report.estimated_p99_ms > report.p99_budget_ms:
        print(f"  ⚠ WARNING: Estimated P99 ({report.estimated_p99_ms:.1f}ms) exceeds "
              f"budget ({report.p99_budget_ms}ms). Add more proxy nodes or reduce peak RPS.")
    else:
        print(f"  ✓ P99 latency within budget ({report.estimated_p99_ms:.1f}ms < "
              f"{report.p99_budget_ms}ms)")

    required_throughput = report.proxy_nodes_min * report.bench.go_full_conn_s
    if required_throughput < report.peak_rps:
        print(f"  ⚠ WARNING: {report.proxy_nodes_min} node(s) cannot handle "
              f"{report.peak_rps:,.0f} RPS. Need at least "
              f"{ceil(report.peak_rps / report.bench.go_full_conn_s)} node(s).")
    else:
        print(f"  ✓ Throughput capacity sufficient "
              f"({required_throughput:,.0f} conn/s ≥ {report.peak_rps:,.0f} RPS)")

    print(sep)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JA4proxy capacity sizing calculator (Phase 86c).",
    )
    parser.add_argument("--peak-connections-per-second", type=float, required=True,
                        help="Peak sustained connections per second")
    parser.add_argument("--p99-latency-budget-ms", type=float, default=10,
                        help="P99 latency budget in ms (default: 10)")
    parser.add_argument("--redis-node-count", type=int, default=3,
                        help="Number of Redis nodes (default: 3)")
    parser.add_argument("--enable-analytics", action="store_true",
                        help="Enable analytics node sizing")
    parser.add_argument("--enable-beaconing-detection", action="store_true",
                        help="Enable beaconing detection (affects key count)")
    parser.add_argument("--enable-abuseipdb", action="store_true",
                        help="Enable AbuseIPDB enrichment (affects key count)")
    parser.add_argument("--cloud-provider", default="aws",
                        choices=["aws", "azure", "gcp"],
                        help="Cloud provider for cost estimation (default: aws)")
    parser.add_argument("--region", default="us-east-1",
                        help="Cloud region for cost estimation (default: us-east-1)")
    parser.add_argument("--go-full-conn-s", type=float, default=None,
                        help="Override: Go full signal path conn/s "
                             "(default: from BenchmarkConstants)")
    parser.add_argument("--go-bypass-conn-s", type=float, default=None,
                        help="Override: Go bypass path conn/s")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of formatted text")
    args = parser.parse_args()

    if args.peak_connections_per_second < 0:
        parser.error("--peak-connections-per-second must be non-negative")

    # Build feature list
    features = []
    if args.enable_analytics:
        features.append("analytics")
    if args.enable_beaconing_detection:
        features.append("beaconing")
    if args.enable_abuseipdb:
        features.append("abuseipdb")

    # Benchmark constants (allow CLI overrides)
    bench = BenchmarkConstants()
    if args.go_full_conn_s is not None:
        bench.go_full_conn_s = args.go_full_conn_s
    if args.go_bypass_conn_s is not None:
        bench.go_bypass_conn_s = args.go_bypass_conn_s

    report = compute_capacity(
        peak_rps=args.peak_connections_per_second,
        p99_budget_ms=args.p99_latency_budget_ms,
        redis_nodes=args.redis_node_count,
        features=features,
        cloud_provider=args.cloud_provider,
        region=args.region,
        bench=bench,
    )

    if args.json:
        print(json.dumps({
            "peak_rps": report.peak_rps,
            "p99_budget_ms": report.p99_budget_ms,
            "proxy_nodes_min": report.proxy_nodes_min,
            "proxy_nodes_recommended": report.proxy_nodes_with_redundancy,
            "estimated_p99_ms": report.estimated_p99_ms,
            "redis_memory_gb": report.redis_memory_gb,
            "redis_instance": report.redis_instance,
            "analytics_storage_gb": report.analytics_storage_gb,
            "total_monthly_cost_usd": report.total_monthly_cost_usd,
            "cost_breakdown": report.cost_breakdown,
            "benchmark_constants": {
                "go_full_conn_s": bench.go_full_conn_s,
                "go_bypass_conn_s": bench.go_bypass_conn_s,
                "go_p99_full_ms": bench.go_p99_full_ms,
                "go_p99_bypass_ms": bench.go_p99_bypass_ms,
                "redis_mem_per_key": bench.redis_mem_per_key,
                "analytics_bytes_per_conn": bench.analytics_bytes_per_conn,
            },
        }, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
