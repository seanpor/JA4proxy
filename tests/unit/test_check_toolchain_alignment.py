"""Unit tests for Phase 874: toolchain alignment and preflight/CI parity."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import check_toolchain_alignment as mod

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestGoToolchainCrossFileAlignment:
    """ci.yml, security-scan/Dockerfile, and Go builder Dockerfiles must agree."""

    def test_aligned_go_versions_pass(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module example.com/test\ngo 1.26.10\n")
        docker_dir = tmp_path / "deploy" / "docker"
        sec_dir = docker_dir / "security-scan"
        wf_dir = tmp_path / ".github" / "workflows"
        sec_dir.mkdir(parents=True)
        wf_dir.mkdir(parents=True)

        (docker_dir / "Dockerfile.go-proxy").write_text(
            "FROM golang:1.27.4-alpine@sha256:abc AS builder\n"
        )
        (sec_dir / "Dockerfile").write_text(
            "FROM golang:1.27.4-alpine@sha256:abc\n"
        )
        (wf_dir / "ci.yml").write_text('          go-version: "1.27.4"\n')
        (wf_dir / "fuzzing.yml").write_text('          go-version: "1.27.4"\n')

        with (
            patch.object(mod, "REPO_ROOT", tmp_path),
            patch.object(mod, "GO_MOD", tmp_path / "go.mod"),
            patch.object(mod, "DOCKERFILES_DIR", docker_dir),
            patch.object(mod, "WORKFLOWS_DIR", wf_dir),
        ):
            errors = mod.check_go_toolchain_alignment()

        assert errors == []

    def test_detects_ci_workflow_drift_from_builder_dockerfile(
        self, tmp_path: Path
    ) -> None:
        docker_dir = tmp_path / "deploy" / "docker"
        sec_dir = docker_dir / "security-scan"
        wf_dir = tmp_path / ".github" / "workflows"
        sec_dir.mkdir(parents=True)
        wf_dir.mkdir(parents=True)

        (docker_dir / "Dockerfile.go-proxy").write_text(
            "FROM golang:1.27.4-alpine@sha256:abc AS builder\n"
        )
        (sec_dir / "Dockerfile").write_text(
            "FROM golang:1.27.4-alpine@sha256:abc\n"
        )
        (wf_dir / "ci.yml").write_text('          go-version: "1.27.3"\n')

        with (
            patch.object(mod, "REPO_ROOT", tmp_path),
            patch.object(mod, "DOCKERFILES_DIR", docker_dir),
            patch.object(mod, "WORKFLOWS_DIR", wf_dir),
        ):
            errors = mod.check_go_toolchain_alignment()

        assert len(errors) == 1
        assert "1.27.3" in errors[0]
        assert "1.27.4" in errors[0]

    def test_detects_security_scan_dockerfile_drift(self, tmp_path: Path) -> None:
        docker_dir = tmp_path / "deploy" / "docker"
        sec_dir = docker_dir / "security-scan"
        wf_dir = tmp_path / ".github" / "workflows"
        sec_dir.mkdir(parents=True)
        wf_dir.mkdir(parents=True)

        (docker_dir / "Dockerfile.go-proxy").write_text(
            "FROM golang:1.27.4-alpine@sha256:abc AS builder\n"
        )
        (sec_dir / "Dockerfile").write_text(
            "FROM golang:1.26.10-alpine@sha256:abc\n"
        )
        (wf_dir / "ci.yml").write_text('          go-version: "1.27.4"\n')

        with (
            patch.object(mod, "REPO_ROOT", tmp_path),
            patch.object(mod, "DOCKERFILES_DIR", docker_dir),
            patch.object(mod, "WORKFLOWS_DIR", wf_dir),
        ):
            errors = mod.check_go_toolchain_alignment()

        assert len(errors) == 1
        assert "1.26.10" in errors[0]
        assert "security-scan/Dockerfile" in errors[0]


class TestPreflightAndSastParity:
    """Verify Makefile preflight parity targets and custom Opengrep rule presence."""

    def test_preflight_runs_scan_regression_and_lint_go_vuln(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        assert "lint-go-vuln:" in makefile
        assert "govulncheck" in makefile

        preflight_start = makefile.index("preflight:")
        preflight_block = makefile[preflight_start : preflight_start + 700]
        assert "scan-regression" in preflight_block
        assert "$(MAKE) lint" in preflight_block

        lint_go_line = next(
            line for line in makefile.splitlines() if line.startswith("lint-go:")
        )
        assert "lint-go-vuln" in lint_go_line

    def test_custom_opengrep_url_sanitization_rule_exists(self) -> None:
        rule_file = (
            REPO_ROOT
            / "security"
            / "sast"
            / "custom-rules"
            / "python-url-substring-sanitization.yml"
        )
        assert rule_file.is_file()
        data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        rules = data["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "ja4p-python-incomplete-url-substring-sanitization"
        regex = rule["patterns"][1]["metavariable-regex"]["regex"]
        assert re.match(regex, '"gcr.' + 'io/"')
        assert re.match(regex, "'docker." + "io/'")
        assert not re.match(regex, '"gcr.' + 'io"')
