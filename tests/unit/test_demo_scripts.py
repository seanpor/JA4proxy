"""Unit tests for Phase 816 demo scripts and orchestration tooling."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from scripts.sync_reference_docs import _script_description, parse_makefile

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
DEMO_UP = SCRIPTS_DIR / "demo-up.sh"
DEMO_MGMT = SCRIPTS_DIR / "demo-mgmt.sh"
DEMO_VERIFY = SCRIPTS_DIR / "demo-verify.sh"
DEMO_DOC = REPO_ROOT / "docs" / "operations" / "DEMO_MANAGEMENT_CONSOLE.md"
MAKEFILE = REPO_ROOT / "Makefile"

DEMO_SCRIPTS = [DEMO_UP, DEMO_MGMT, DEMO_VERIFY]


class TestDemoScriptIntegrity:
    """Validate existence, permissions, syntax, and reference doc integration."""

    @pytest.mark.parametrize("script_path", DEMO_SCRIPTS, ids=lambda p: p.name)
    def test_scripts_exist_and_are_executable(self, script_path: Path):
        assert script_path.is_file(), f"Expected script {script_path.name} to exist"
        mode = script_path.stat().st_mode
        assert bool(mode & stat.S_IXUSR), f"Expected {script_path.name} to be user-executable"

    @pytest.mark.parametrize("script_path", DEMO_SCRIPTS, ids=lambda p: p.name)
    def test_scripts_pass_bash_syntax_check(self, script_path: Path):
        res = subprocess.run(
            ["bash", "-n", str(script_path)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert res.returncode == 0, f"Syntax error in {script_path.name}:\n{res.stderr}"

    @pytest.mark.parametrize("script_path", DEMO_SCRIPTS, ids=lambda p: p.name)
    def test_scripts_have_parseable_descriptions(self, script_path: Path):
        desc = _script_description(script_path)
        assert desc, f"Script {script_path.name} must have a parseable header description for SCRIPTS.md"
        assert len(desc) >= 10, f"Description too short for {script_path.name}: '{desc}'"

    @pytest.mark.parametrize("script_path", DEMO_SCRIPTS, ids=lambda p: p.name)
    def test_scripts_support_help_flag(self, script_path: Path):
        res = subprocess.run(
            ["bash", str(script_path), "--help"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert res.returncode == 0, f"{script_path.name} --help failed:\n{res.stderr}"
        assert "Usage:" in res.stdout or "usage:" in res.stdout.lower()


class TestDemoScriptDryRun:
    """Validate dry-run and configuration parsing logic."""

    def test_demo_up_dry_run(self):
        res = subprocess.run(
            ["bash", str(DEMO_UP), "--dry-run"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ, "DRY_RUN": "1"},
        )
        assert res.returncode == 0, f"demo-up.sh --dry-run failed:\n{res.stderr}\n{res.stdout}"
        assert "dry-run" in res.stdout.lower()

    def test_demo_mgmt_dry_run(self):
        res = subprocess.run(
            ["bash", str(DEMO_MGMT), "--dry-run"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ, "DRY_RUN": "1"},
        )
        assert res.returncode == 0, f"demo-mgmt.sh --dry-run failed:\n{res.stderr}\n{res.stdout}"
        assert "dry-run" in res.stdout.lower()

    def test_demo_verify_dry_run(self):
        res = subprocess.run(
            ["bash", str(DEMO_VERIFY), "--dry-run"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ, "DRY_RUN": "1"},
        )
        assert res.returncode == 0, f"demo-verify.sh --dry-run failed:\n{res.stderr}\n{res.stdout}"
        assert "dry-run" in res.stdout.lower()


class TestDemoMakefileTargets:
    """Validate Makefile targets for Phase 816."""

    def test_makefile_has_demo_targets(self):
        targets = parse_makefile(MAKEFILE.read_text(encoding="utf-8"))
        target_map = {t.name: t.description for t in targets}

        for expected in ["demo", "demo-verify", "demo-stop"]:
            assert expected in target_map, f"Target '{expected}' missing from Makefile"
            assert target_map[expected], f"Target '{expected}' must have a '##' description"


class TestDemoDocumentation:
    """Validate existence and coverage of the operator demo runbook."""

    def test_demo_runbook_structure(self):
        assert DEMO_DOC.is_file(), f"{DEMO_DOC} must exist"
        content = DEMO_DOC.read_text(encoding="utf-8")

        required_sections = [
            "Overview",
            "Prerequisites",
            "Quick Start",
            "Interactive Walkthrough",
            "Live Mitigation",
            "Blocking Dial",
            "Verification",
            "Teardown",
        ]
        for section in required_sections:
            assert re.search(rf"#+\s+.*{section}", content, re.IGNORECASE), (
                f"Section '{section}' missing from {DEMO_DOC.name}"
            )
