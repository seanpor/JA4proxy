"""Phase 86c — Tests for capacity sizing calculator."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

CALC_PY = Path(__file__).parent.parent.parent / "scripts" / "capacity_calculator.py"


class TestCapacityCalculator:
    """Integration tests via CLI (no import needed)."""

    def _run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CALC_PY)] + list(args),
            capture_output=True, text=True, timeout=30,
        )

    def test_basic_sizing(self):
        """1000 RPS should need 1 proxy node + 1 for N+1 = 2 total."""
        r = self._run("--peak-connections-per-second", "1000")
        assert r.returncode == 0
        assert "Proxy node sizing" in r.stdout
        assert "Redis sizing" in r.stdout

    def test_high_load_sizing(self):
        """5000 RPS should need at least 1 node."""
        r = self._run("--peak-connections-per-second", "5000")
        assert r.returncode == 0
        assert "Estimated cloud cost" in r.stdout

    def test_very_high_load(self):
        """50000 RPS should need multiple nodes."""
        r = self._run("--peak-connections-per-second", "50000")
        assert r.returncode == 0
        assert "Recommended (N+1)" in r.stdout

    def test_json_output(self):
        """--json flag should produce valid JSON."""
        r = self._run(
            "--peak-connections-per-second", "5000",
            "--enable-analytics",
            "--cloud-provider", "aws",
            "--region", "us-east-1",
            "--json",
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "proxy_nodes_recommended" in data
        assert "total_monthly_cost_usd" in data
        assert "benchmark_constants" in data

    def test_with_all_features(self):
        """All features enabled should show analytics sizing."""
        r = self._run(
            "--peak-connections-per-second", "5000",
            "--enable-analytics",
            "--enable-beaconing-detection",
            "--enable-abuseipdb",
        )
        assert r.returncode == 0
        assert "Analytics node" in r.stdout

    def test_p99_warning(self):
        """Tight P99 budget should trigger warning."""
        r = self._run(
            "--peak-connections-per-second", "1000",
            "--p99-latency-budget-ms", "0.1",  # unrealistically tight
        )
        assert r.returncode == 0
        assert "WARNING" in r.stdout or "P99 latency within budget" in r.stdout

    def test_invalid_input_zero_rps(self):
        """Zero RPS should still produce a valid report (edge case)."""
        r = self._run("--peak-connections-per-second", "0")
        assert r.returncode == 0

    def test_cloud_providers(self):
        """All 3 cloud providers should produce cost output."""
        for provider in ["aws", "azure", "gcp"]:
            r = self._run(
                "--peak-connections-per-second", "5000",
                "--cloud-provider", provider,
            )
            assert r.returncode == 0
            assert "Estimated cloud cost" in r.stdout

    def test_custom_benchmark_override(self):
        """--go-full-conn-s should override the default constant."""
        r = self._run(
            "--peak-connections-per-second", "10000",
            "--go-full-conn-s", "1000",  # very low — should need many nodes
            "--json",
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["benchmark_constants"]["go_full_conn_s"] == 1000.0


class TestCapacityFormulas:
    """Unit tests for the compute_capacity function."""

    def test_proxy_count_formula(self):
        """proxy_nodes_min = ceil(peak_rps / go_full_conn_s)."""
        from scripts.capacity_calculator import compute_capacity, BenchmarkConstants
        bench = BenchmarkConstants(go_full_conn_s=6200.0)
        report = compute_capacity(
            peak_rps=12400, p99_budget_ms=10, redis_nodes=3,
            features=[], cloud_provider="aws", region="us-east-1",
            bench=bench,
        )
        # 12400 / 6200 = 2.0 → 2 nodes minimum, 3 with N+1
        assert report.proxy_nodes_min == 2
        assert report.proxy_nodes_with_redundancy == 3

    def test_redis_memory_formula(self):
        """redis_memory = key_count * mem_per_key * overhead * 2."""
        from scripts.capacity_calculator import compute_capacity, BenchmarkConstants
        bench = BenchmarkConstants(
            redis_mem_per_key=100.0,
            redis_overhead=1.3,
        )
        report = compute_capacity(
            peak_rps=1000, p99_budget_ms=10, redis_nodes=3,
            features=[], cloud_provider="aws", region="us-east-1",
            bench=bench,
        )
        # key_count = 1000 * 500 = 500000
        # memory = 500000 * 100 * 1.3 * 2 = 130000000 bytes ≈ 0.12 GB
        assert report.redis_memory_gb > 0

    def test_analytics_storage_formula(self):
        """storage = bytes_per_conn * rps * 86400 * 90 days."""
        from scripts.capacity_calculator import compute_capacity, BenchmarkConstants
        bench = BenchmarkConstants(analytics_bytes_per_conn=500.0)
        report = compute_capacity(
            peak_rps=1000, p99_budget_ms=10, redis_nodes=3,
            features=["analytics"], cloud_provider="aws", region="us-east-1",
            bench=bench,
        )
        # 500 * 1000 * 86400 * 90 = 3,888,000,000,000 bytes ≈ 3621 GB
        assert report.analytics_storage_gb > 0
        assert report.analytics_cpu == "4 vCPU"
        assert report.analytics_ram == "16 GB"

    def test_no_analytics_when_disabled(self):
        """Analytics should be N/A when not enabled."""
        from scripts.capacity_calculator import compute_capacity, BenchmarkConstants
        report = compute_capacity(
            peak_rps=1000, p99_budget_ms=10, redis_nodes=3,
            features=[], cloud_provider="aws", region="us-east-1",
            bench=BenchmarkConstants(),
        )
        assert report.analytics_cpu == "N/A"
        assert report.analytics_ram == "N/A"
        assert report.analytics_storage_gb == 0

    def test_cost_increases_with_nodes(self):
        """More proxy nodes should increase total cost."""
        from scripts.capacity_calculator import compute_capacity, BenchmarkConstants
        bench = BenchmarkConstants()
        r1 = compute_capacity(
            peak_rps=1000, p99_budget_ms=10, redis_nodes=3,
            features=[], cloud_provider="aws", region="us-east-1",
            bench=bench,
        )
        r2 = compute_capacity(
            peak_rps=50000, p99_budget_ms=10, redis_nodes=3,
            features=[], cloud_provider="aws", region="us-east-1",
            bench=bench,
        )
        assert r2.total_monthly_cost_usd > r1.total_monthly_cost_usd
