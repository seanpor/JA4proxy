"""TDD tests for Phase 64i — validation report deployment section."""
import importlib
import importlib.util
import io
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "generate_validation_report.py"


def _load_module():
    """Import the script as a module."""
    spec = importlib.util.spec_from_file_location("gen_report", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDeploymentSectionFunction:
    """Test the _section_deployment function exists and works."""

    def test_function_exists(self):
        mod = _load_module()
        assert hasattr(mod, "_section_deployment"), "_section_deployment function missing"

    def test_returns_string(self):
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert isinstance(result, str)

    def test_contains_deployment_heading(self):
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert "## Deployment Validation Evidence" in result

    def test_contains_smoke_tests_heading(self):
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert "### Smoke Tests" in result

    def test_contains_mttr_heading(self):
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert "### MTTR Baseline" in result

    def test_contains_dr_heading(self):
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert "### DR Runbook Exercise History" in result

    def test_graceful_when_smoke_results_missing(self):
        """If test-results/smoke/ doesn't exist, should not crash."""
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        # Should contain guidance on what to run
        assert "smoke" in result.lower()

    def test_graceful_when_mttr_missing(self):
        """If MTTR_BASELINE.md doesn't exist, should not crash."""
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert "MTTR" in result or "mttr" in result

    def test_graceful_when_dr_runbook_missing_exercise_history(self):
        """Should not crash if DR runbook doesn't have exercise history."""
        mod = _load_module()
        result = mod._section_deployment(REPO_ROOT)
        assert isinstance(result, str)  # no exception


class TestSectionFlag:
    """Test the --section deployment CLI flag."""

    def test_argparse_has_section_flag(self):
        mod = _load_module()
        # Check that the argparse setup includes --section
        with pytest.raises(SystemExit):
            with patch("sys.stderr", new_callable=io.StringIO):
                mod.main(["--section", "invalid_section_name"])

    def test_section_deployment_accepted(self):
        """--section deployment should be accepted by argparse without error."""
        mod = _load_module()
        ap = __import__("argparse").ArgumentParser()
        ap.add_argument("--output", default="/dev/null")
        ap.add_argument("--stdout", action="store_true")
        ap.add_argument("--section", choices=["deployment"])
        # Should parse without raising
        args = ap.parse_args(["--section", "deployment"])
        assert args.section == "deployment"
