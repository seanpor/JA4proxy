"""Unit tests for scripts/check_toolchain_alignment.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scripts.check_toolchain_alignment import (
    check_dockerfile_go_versions,
    get_go_mod_version,
    main,
    parse_semver,
)


def test_parse_semver():
    """Test parsing version strings into tuples."""
    assert parse_semver("1.26.6") == (1, 26, 6)
    assert parse_semver("v1.27.2") == (1, 27, 2)
    assert parse_semver("invalid") == ()


def test_get_go_mod_version():
    """Test reading Go version from go.mod."""
    version = get_go_mod_version()
    assert version is not None
    assert version[0] == 1
    assert version[1] in (26, 27)


def test_check_dockerfile_go_versions():
    """Test Dockerfile Go version scanning."""
    errors = check_dockerfile_go_versions()
    # All Dockerfiles should be upgraded to Go >= 1.27.2
    assert errors == []


def test_main_passes():
    """Test main returns 0 when toolchain is aligned."""
    assert main() == 0


def test_main_fails_on_exceeded_go_version():
    """Test main returns 1 when go.mod exceeds linter capability."""
    with patch("scripts.check_toolchain_alignment.get_go_mod_version", return_value=(1, 28, 0)):
        assert main() == 1
