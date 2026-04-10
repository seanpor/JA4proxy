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
