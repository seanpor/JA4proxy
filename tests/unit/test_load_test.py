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
                [
                    sys.executable,
                    str(LOAD_TEST_PY),
                    "--target",
                    "127.0.0.1:1",
                    "--scenario",
                    scenario,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # --help short-circuits, so exit should be 0, and scenario
            # string must appear in the argparse choices listing in stdout.
            assert (
                r.returncode == 0
            ), f"load_test.py rejected --scenario {scenario}: {r.stderr}"
            assert (
                scenario in r.stdout
            ), f"scenario {scenario!r} missing from --help choices"

    def test_scenario_fingerprint_distributions(self):
        """Each scenario's fingerprint distribution must sum to 100%."""
        mod = _load_load_test_module()
        assert hasattr(
            mod, "SCENARIOS"
        ), "Phase 86i: load_test.py must define SCENARIOS mapping"
        for name in REQUIRED_SCENARIOS:
            assert name in mod.SCENARIOS, f"scenario {name} missing"
            dist = mod.SCENARIOS[name]
            total = sum(dist.values())
            assert (
                total == 100
            ), f"scenario {name} distribution sums to {total}, not 100"

    def test_load_test_imports_tls_traffic_generator(self):
        """load_test.py must reuse scripts/tls-traffic-generator.py
        instead of duplicating TLS client machinery."""
        source = LOAD_TEST_PY.read_text()
        assert (
            "tls-traffic-generator" in source or "tls_traffic_generator" in source
        ), "Phase 86i: load_test.py must reference tls-traffic-generator"

    def test_pushgateway_flag_emits_metrics(self):
        """--push-gateway flag must emit all 5 ja4proxy_loadtest_* metrics
        to the configured Pushgateway URL."""
        mod = _load_load_test_module()
        assert hasattr(
            mod, "push_loadtest_metrics"
        ), "Phase 86i: load_test.py must define push_loadtest_metrics()"
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
            assert (
                name in pushed["payload"]
            ), f"metric {name} missing from Pushgateway payload"

    def test_pushgateway_grouping_key_is_forwarded(self):
        """PHASE_101 M24 — when a ``grouping_key`` is supplied it must be
        passed straight through to ``push_to_gateway`` so parallel runs
        don't clobber each other's pushgateway group."""
        mod = _load_load_test_module()
        captured: dict = {}

        def fake_push(url, job, registry, grouping_key=None):
            captured["url"] = url
            captured["job"] = job
            captured["grouping_key"] = grouping_key

        from unittest.mock import patch

        with patch("prometheus_client.push_to_gateway", side_effect=fake_push):
            mod.push_loadtest_metrics(
                url="http://mock-pgw:9091",
                attempted=1,
                completed=1,
                errors={},
                latencies_seconds=[0.01],
                throughput_cps=1.0,
                grouping_key={
                    "instance": "host-a.lab",
                    "scenario": "mixed",
                    "run_id": "ab12cd34",
                },
            )
        assert captured.get("grouping_key") == {
            "instance": "host-a.lab",
            "scenario": "mixed",
            "run_id": "ab12cd34",
        }

    def test_sample_connect_latencies_returns_real_numbers(self):
        """PHASE_101 M24 — the sampling helper must produce a list of
        positive floats (one per successful connect) and silently skip
        failures. We bind a throwaway listener so the connects succeed."""
        import socket as _socket

        mod = _load_load_test_module()
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        port = srv.getsockname()[1]
        try:
            lats = mod.sample_connect_latencies(
                f"127.0.0.1:{port}", samples=5, timeout_s=1.0
            )
        finally:
            srv.close()
        assert len(lats) == 5, f"expected 5 samples, got {lats!r}"
        assert all(
            isinstance(x, float) and x > 0 for x in lats
        ), f"expected all positive floats, got {lats!r}"

    def test_sample_connect_latencies_survives_unreachable_target(self):
        """Unreachable targets must not raise — they just return ``[]``
        (or a shorter list of whatever happened to succeed)."""
        mod = _load_load_test_module()
        # Port 1 is well-known to be closed/filtered — connects will fail.
        lats = mod.sample_connect_latencies("127.0.0.1:1", samples=3, timeout_s=0.2)
        assert isinstance(lats, list)
        # Either empty or only sub-timeout samples; nothing should raise.
        assert all(x > 0 for x in lats)
