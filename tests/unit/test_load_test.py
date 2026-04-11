"""Phase 86b — Tests for load testing harness."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

LOAD_TEST_PY = Path(__file__).parent.parent.parent / "scripts" / "load_test.py"


class TestLoadTestScript:
    """Static and unit tests for load_test.py."""

    def test_file_exists(self):
        assert LOAD_TEST_PY.exists()

    def test_valid_python(self):
        """Script must be valid Python (importable)."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("load_test", LOAD_TEST_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "main")
        assert hasattr(mod, "run_benchmark")
        assert hasattr(mod, "generate_summary")

    def test_generate_summary_has_required_fields(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("load_test", LOAD_TEST_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        results = {
            "target": "localhost:8080",
            "duration": 60,
            "target_rps": 1000,
            "scenario": "baseline",
            "timestamp": "20260410T120000",
            "elapsed_seconds": 65.5,
            "exit_code": 0,
            "report_text": "sample report",
            "raw_data": {"throughput": 5000},
        }
        summary = mod.generate_summary(results)
        assert "localhost:8080" in summary
        assert "baseline" in summary
        assert "60" in summary
        assert "1000" in summary
        assert "5000" in summary

    def test_run_benchmark_handles_missing_files(self):
        """run_benchmark should not crash if benchmark output files are absent."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("load_test", LOAD_TEST_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(exitcode=0, stdout="", stderr="")
            with tempfile.TemporaryDirectory() as tmpdir:
                # Point output to empty dir — no report files will exist
                results = mod.run_benchmark("127.0.0.1:1", 1, 100, "baseline")
                assert results["exit_code"] == 0
                assert results["target"] == "127.0.0.1:1"


# ── Phase 86i: scenario rewrite + Pushgateway support ───────────────────────


REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_SCENARIOS = {"bypass-only", "full-signal", "attack-wave", "mixed"}
REQUIRED_LOADTEST_METRICS = {
    "ja4proxy_loadtest_connections_attempted_total",
    "ja4proxy_loadtest_connections_completed_total",
    "ja4proxy_loadtest_errors_total",
    "ja4proxy_loadtest_latency_seconds",
    "ja4proxy_loadtest_throughput_cps",
}


def _load_load_test_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("load_test", LOAD_TEST_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPhase86iScenarios:
    """Phase 86i Gap 3 — replace stale scenarios with code-path-specific set."""

    def test_scenarios_include_required_four(self):
        """argparse must accept the four new scenarios."""
        import subprocess
        import sys
        for scenario in REQUIRED_SCENARIOS:
            r = subprocess.run(
                [sys.executable, str(LOAD_TEST_PY),
                 "--target", "127.0.0.1:1", "--scenario", scenario,
                 "--help"],
                capture_output=True, text=True, timeout=10,
            )
            # --help short-circuits, so exit should be 0, and scenario
            # string must appear in the argparse choices listing in stdout.
            assert r.returncode == 0, (
                f"load_test.py rejected --scenario {scenario}: {r.stderr}"
            )
            assert scenario in r.stdout, (
                f"scenario {scenario!r} missing from --help choices"
            )

    def test_scenario_fingerprint_distributions(self):
        """Each scenario's fingerprint distribution must sum to 100%."""
        mod = _load_load_test_module()
        assert hasattr(mod, "SCENARIOS"), (
            "Phase 86i: load_test.py must define SCENARIOS mapping"
        )
        for name in REQUIRED_SCENARIOS:
            assert name in mod.SCENARIOS, f"scenario {name} missing"
            dist = mod.SCENARIOS[name]
            total = sum(dist.values())
            assert total == 100, (
                f"scenario {name} distribution sums to {total}, not 100"
            )

    def test_load_test_imports_tls_traffic_generator(self):
        """load_test.py must reuse scripts/tls-traffic-generator.py
        instead of duplicating TLS client machinery."""
        source = LOAD_TEST_PY.read_text()
        assert "tls-traffic-generator" in source or "tls_traffic_generator" in source, (
            "Phase 86i: load_test.py must reference tls-traffic-generator"
        )

    def test_pushgateway_flag_emits_metrics(self):
        """--push-gateway flag must emit all 5 ja4proxy_loadtest_* metrics
        to the configured Pushgateway URL."""
        mod = _load_load_test_module()
        assert hasattr(mod, "push_loadtest_metrics"), (
            "Phase 86i: load_test.py must define push_loadtest_metrics()"
        )
        pushed = {"payload": ""}

        def fake_push(url, job, registry):
            # Capture the text-format payload from the registry.
            from prometheus_client import generate_latest
            pushed["payload"] = generate_latest(registry).decode()

        from unittest.mock import patch
        with patch("prometheus_client.push_to_gateway", side_effect=fake_push):
            mod.push_loadtest_metrics(
                url="http://mock-pgw:9091",
                attempted=10,
                completed=9,
                errors={"timeout": 1},
                latencies_seconds=[0.001, 0.005, 0.02],
                throughput_cps=5.0,
            )
        for name in REQUIRED_LOADTEST_METRICS:
            assert name in pushed["payload"], (
                f"metric {name} missing from Pushgateway payload"
            )
