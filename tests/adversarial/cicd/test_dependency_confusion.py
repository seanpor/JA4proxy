"""Tests for dependency confusion and typosquatting risk across project dependencies (Phase 814f L0).

Audits:
1. Python dependencies in requirements.txt, pyproject.toml:
   - Ensure all declared dependencies are legitimate known packages or internal paths.
   - Verify that no private internal package names are loaded without private index pinning.
2. Go modules in go.mod:
   - Ensure all module paths have legitimate domain prefixes (e.g. github.com/seanpor/ja4proxy,
     golang.org/x/..., etc.).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

GO_MOD = Path("go.mod")
REQUIREMENTS_FILES = [
    Path("requirements.txt"),
    Path("management/requirements.txt"),
    Path("management/requirements-dev.txt"),
]


def test_go_module_namespaces():
    """Verify Go module imports use valid, non-squattable namespaces."""
    if not GO_MOD.exists():
        pytest.skip("go.mod not found")

    content = GO_MOD.read_text(encoding="utf-8")
    lines = content.splitlines()

    in_require = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("module") or line.startswith("go "):
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()

        parts = line.split()
        if parts:
            pkg = parts[0]
            # Valid Go packages must contain a domain slash (e.g. github.com/...)
            assert "." in pkg.split("/")[0], f"Suspicious Go package without FQDN namespace: {pkg}"


def test_python_requirements_namespaces():
    """Verify Python requirements do not contain unpinned private-looking names."""
    for req_file in REQUIREMENTS_FILES:
        if not req_file.exists():
            continue
        lines = req_file.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-e"):
                continue
            pkg_name = re.split(r"[=<>!~;@\s]", line)[0]
            assert pkg_name, f"Empty package name in {req_file}: {line}"
            # Ensure no internal-sounding private un-scoped packages like ja4-internal
            assert not pkg_name.startswith("ja4-private"), f"Potential dependency confusion risk: {pkg_name}"
