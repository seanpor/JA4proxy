"""TDD tests for management/api/proxy_config.py — Production Readiness Gap 6.

Covers
------
Section 1: get_sso_role_mapping()
  - Returns correct mapping from a valid proxy.yml file
  - Returns empty dict when file is missing
  - Returns empty dict when sso.role_mapping section is absent
  - Caches: second call within TTL does not re-read the file
  - Cache invalidation: _clear_cache() + new path → fresh read

Section 2: _load_proxy_config()
  - Handles malformed YAML gracefully (returns empty dict, never raises)
  - Handles empty YAML file (returns empty dict)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Import the module fresh (env vars set before import)
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import proxy_config  # noqa: E402


@pytest.fixture(autouse=True)
def clear_cache_before_each():
    """Ensure each test starts with a clean cache."""
    proxy_config._clear_cache()
    yield
    proxy_config._clear_cache()


# ── Section 1: get_sso_role_mapping() ─────────────────────────────────────────


def test_get_sso_role_mapping_from_yaml(tmp_path: Path) -> None:
    """get_sso_role_mapping() returns mapping from a valid proxy.yml file."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text(
        "sso:\n"
        "  role_mapping:\n"
        "    SOC-Analysts: analyst\n"
        "    Security-Admins: admin\n"
    )

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)
        mapping = proxy_config.get_sso_role_mapping()
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)

    assert mapping == {
        "SOC-Analysts": "analyst",
        "Security-Admins": "admin",
    }, f"Expected correct role mapping, got {mapping}"


def test_get_sso_role_mapping_missing_file() -> None:
    """get_sso_role_mapping() returns empty dict when config file is missing."""
    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = "/nonexistent/path/proxy.yml"
        mapping = proxy_config.get_sso_role_mapping()
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)

    assert mapping == {}, f"Expected empty dict for missing file, got {mapping}"


def test_get_sso_role_mapping_no_sso_section(tmp_path: Path) -> None:
    """get_sso_role_mapping() returns empty dict when sso.role_mapping absent."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("proxy:\n  listen_port: 8080\n")

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)
        mapping = proxy_config.get_sso_role_mapping()
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)

    assert mapping == {}, f"Expected empty dict when sso section absent, got {mapping}"


def test_get_sso_role_mapping_caches_result(tmp_path: Path) -> None:
    """Two calls within TTL use the cached value without re-reading the file."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("sso:\n  role_mapping:\n    Group-A: admin\n")

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)

        # First call reads the file
        mapping1 = proxy_config.get_sso_role_mapping()
        assert mapping1 == {"Group-A": "admin"}

        # Overwrite the file — second call should still return cached value
        cfg_file.write_text("sso:\n  role_mapping:\n    Group-B: analyst\n")
        mapping2 = proxy_config.get_sso_role_mapping()
        assert mapping2 == {
            "Group-A": "admin"
        }, "Second call within TTL should return cached value, not re-read file"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)


def test_get_sso_role_mapping_after_cache_clear(tmp_path: Path) -> None:
    """After _clear_cache(), get_sso_role_mapping() re-reads the file."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("sso:\n  role_mapping:\n    Group-A: admin\n")

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)

        mapping1 = proxy_config.get_sso_role_mapping()
        assert mapping1 == {"Group-A": "admin"}

        # Update file and clear cache
        cfg_file.write_text("sso:\n  role_mapping:\n    Group-B: analyst\n")
        proxy_config._clear_cache()

        mapping2 = proxy_config.get_sso_role_mapping()
        assert mapping2 == {
            "Group-B": "analyst"
        }, f"After _clear_cache(), should read updated file: {mapping2}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)


# ── Section 2: _load_proxy_config() ───────────────────────────────────────────


def test_load_proxy_config_malformed_yaml(tmp_path: Path) -> None:
    """Malformed YAML returns empty dict and never raises."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("{ invalid: yaml: content: [\n")

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)
        result = proxy_config._load_proxy_config()
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)

    assert isinstance(
        result, dict
    ), f"Expected dict on malformed YAML, got {type(result)}"
    # May return {} or partial data — most important: no exception raised


def test_load_proxy_config_empty_file(tmp_path: Path) -> None:
    """Empty YAML file returns empty dict."""
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("")

    saved = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg_file)
        result = proxy_config._load_proxy_config()
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)

    assert result == {}, f"Expected empty dict for empty file, got {result}"
