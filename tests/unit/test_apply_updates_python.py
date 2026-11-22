"""Unit tests for scripts/apply_updates_python.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import apply_updates_python as mod


class _FakeHTTPResponse:
    """Minimal context-manager mock for urllib.request.urlopen."""

    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class TestLineParsingAndSelection:
    """Requirement line parsing, normalization, and upper-bound version selection."""

    def test_normalize_package_name(self) -> None:
        assert mod.normalize_pkg_name("PyYAML") == "pyyaml"
        assert mod.normalize_pkg_name("pytest_asyncio") == "pytest-asyncio"
        assert mod.normalize_pkg_name("python.multipart") == "python-multipart"

    def test_select_latest_respects_upper_bound_and_skips_prereleases(self) -> None:
        releases = ["1.4.1", "1.5.0", "1.6.0rc1", "2.0.0", "2.1.0a1"]
        chosen = mod.select_latest_compatible(
            releases=releases,
            current_min="1.4.1",
            upper_bounds=[",<2"],
        )
        assert chosen == "1.5.0"

    def test_select_latest_returns_none_when_up_to_date(self) -> None:
        releases = ["6.2.4", "7.0.0", "7.1.0"]
        chosen = mod.select_latest_compatible(
            releases=releases,
            current_min="6.2.4",
            upper_bounds=[",<7"],
        )
        assert chosen is None

    def test_fetch_pypi_releases_filters_yanked_files(self) -> None:
        payload = {
            "releases": {
                "1.0.0": [{"filename": "pkg-1.0.0.whl", "yanked": False}],
                "1.1.0": [{"filename": "pkg-1.1.0.whl", "yanked": True}],
                "1.2.0": [{"filename": "pkg-1.2.0.whl", "yanked": False}],
                "1.3.0": [],  # empty release entry
            }
        }
        with patch.object(
            mod.urllib.request, "urlopen", return_value=_FakeHTTPResponse(payload)
        ):
            releases = mod.fetch_pypi_releases("example-pkg")

        assert set(releases) == {"1.0.0", "1.2.0"}


class TestMultiEnvironmentParityUpdates:
    """Lockstep updates across multiple requirement files with constraint preservation."""

    def test_lockstep_update_across_three_files_preserves_format(
        self, tmp_path: Path
    ) -> None:
        req_root = tmp_path / "requirements.txt"
        req_analytics = tmp_path / "requirements-analytics.txt"
        req_mgmt = tmp_path / "management" / "requirements.txt"
        req_mgmt.parent.mkdir(parents=True)

        req_root.write_text(
            "# Core\n"
            "pyyaml==6.0.3\n"
            "fakeredis==2.40.0          # shared fixture\n"
            "pytest-asyncio>=1.4.1,<2     # 1.x compat\n"
            'uvloop>=0.21.0; sys_platform == "linux"  # phase-68\n'
        )
        req_analytics.write_text(
            "# Analytics\n"
            "pyyaml==6.0.3\n"
        )
        req_mgmt.write_text(
            "# Management\n"
            "pyyaml==6.0.3              # SSO role mapping\n"
            "fakeredis[aioredis]==2.40.0\n"
            "pytest-asyncio==1.4.1\n"
        )

        pypi_map = {
            "pyyaml": ["6.0.3", "6.0.4"],
            "fakeredis": ["2.40.0", "2.41.0", "2.42.0rc1"],
            "pytest-asyncio": ["1.4.1", "1.5.0", "2.0.0"],
            "uvloop": ["0.21.0", "0.22.1"],
        }

        with (
            patch.object(mod, "fetch_pypi_releases", side_effect=lambda pkg: pypi_map[pkg]),
            patch.object(mod, "_run_validation", return_value=True) as mock_val,
        ):
            rc = mod.update_python_requirements(
                req_files=[req_root, req_analytics, req_mgmt],
                repo_root=tmp_path,
            )

        assert rc == 0
        mock_val.assert_called_once()

        # Verify lockstep parity and exact formatting preservation
        root_text = req_root.read_text()
        analytics_text = req_analytics.read_text()
        mgmt_text = req_mgmt.read_text()

        assert "pyyaml==6.0.4\n" in root_text
        assert "pyyaml==6.0.4\n" in analytics_text
        assert "pyyaml==6.0.4              # SSO role mapping\n" in mgmt_text

        assert "fakeredis==2.41.0          # shared fixture\n" in root_text
        assert "fakeredis[aioredis]==2.41.0\n" in mgmt_text

        # pytest-asyncio must respect <2 from requirements.txt in BOTH files
        assert "pytest-asyncio>=1.5.0,<2     # 1.x compat\n" in root_text
        assert "pytest-asyncio==1.5.0\n" in mgmt_text

        # Environment marker preserved verbatim
        assert 'uvloop>=0.22.1; sys_platform == "linux"  # phase-68\n' in root_text

    def test_rolls_back_all_files_when_validation_fails(self, tmp_path: Path) -> None:
        req_a = tmp_path / "requirements.txt"
        req_b = tmp_path / "requirements-analytics.txt"
        orig_a = "pyyaml==6.0.3\n"
        orig_b = "pyyaml==6.0.3\n"
        req_a.write_text(orig_a)
        req_b.write_text(orig_b)

        with (
            patch.object(mod, "fetch_pypi_releases", return_value=["6.0.3", "6.0.4"]),
            patch.object(mod, "_run_validation", return_value=False),
        ):
            rc = mod.update_python_requirements(
                req_files=[req_a, req_b],
                repo_root=tmp_path,
            )

        assert rc == 1
        assert req_a.read_text() == orig_a
        assert req_b.read_text() == orig_b

    def test_dry_run_does_not_modify_files_or_run_validation(
        self, tmp_path: Path
    ) -> None:
        req_a = tmp_path / "requirements.txt"
        orig_a = "pyyaml==6.0.3\n"
        req_a.write_text(orig_a)

        with (
            patch.object(mod, "fetch_pypi_releases", return_value=["6.0.3", "6.0.4"]),
            patch.object(mod, "_run_validation") as mock_val,
        ):
            rc = mod.update_python_requirements(
                req_files=[req_a],
                repo_root=tmp_path,
                dry_run=True,
            )

        assert rc == 0
        assert req_a.read_text() == orig_a
        mock_val.assert_not_called()
