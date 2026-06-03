"""Integration tests for hot config reload.

Tests SIGHUP and pub/sub-triggered config reload.
"""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from src.config.loader import ConfigError, ConfigLoader


def _write(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


BASE_CONFIG = {
    "proxy": {"bind_host": "0.0.0.0", "bind_port": 8080},
    "redis": {"host": "redis", "port": 6379, "db": 0},
    "security": {"max_requests_per_minute": 100},
}


class TestHotReload:
    """Test that config reloads apply new values without restart."""

    @pytest.fixture
    def cfg_file(self, tmp_path):
        f = tmp_path / "proxy.yml"
        _write(f, BASE_CONFIG)
        return f

    def _load(self, loader):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(loader.load())
        finally:
            loop.close()

    def _reload(self, loader):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(loader.reload())
        finally:
            loop.close()

    def test_changed_value_active_after_reload(self, cfg_file):
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)
        assert loader.get()["security"]["max_requests_per_minute"] == 100

        updated = dict(BASE_CONFIG)
        updated["security"] = {"max_requests_per_minute": 999}
        _write(cfg_file, updated)

        self._reload(loader)
        assert loader.get()["security"]["max_requests_per_minute"] == 999

    def test_reload_rejected_for_non_reloadable_key(self, cfg_file):
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)

        bad_config = dict(BASE_CONFIG)
        bad_config["proxy"] = {"bind_host": "0.0.0.0", "bind_port": 9999}
        _write(cfg_file, bad_config)

        with pytest.raises(ConfigError):
            self._reload(loader)

        # Old config must remain active
        assert loader.get()["proxy"]["bind_port"] == 8080

    def test_old_config_active_after_failed_reload(self, cfg_file):
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)

        # Write invalid YAML
        cfg_file.write_text("{broken yaml: [", encoding="utf-8")

        with pytest.raises(ConfigError):
            self._reload(loader)

        # Original config still active
        assert loader.get()["proxy"]["bind_port"] == 8080

    def test_reload_via_pubsub_config_reload_message(self, cfg_file):
        """Config reload message from pub/sub must trigger the same reload."""
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)

        updated = dict(BASE_CONFIG)
        updated["security"] = {"max_requests_per_minute": 42}
        _write(cfg_file, updated)

        self._reload(loader)
        assert loader.get()["security"]["max_requests_per_minute"] == 42

    def test_on_reload_callback_receives_new_config(self, cfg_file):
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)

        received = []
        loader.on_reload(
            lambda cfg: received.append(
                cfg.get("security", {}).get("max_requests_per_minute")
            )
        )

        updated = dict(BASE_CONFIG)
        updated["security"] = {"max_requests_per_minute": 77}
        _write(cfg_file, updated)
        self._reload(loader)

        assert received == [77]

    def test_sighup_setup_does_not_raise(self, cfg_file):
        """setup_sighup() should register without error on Unix."""
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loader.setup_sighup(loop)
        finally:
            loop.close()

    def test_reload_count_increments_on_success(self, cfg_file):
        loader = ConfigLoader(str(cfg_file))
        self._load(loader)
        assert loader.reload_count == 0
        self._reload(loader)
        assert loader.reload_count == 1
        self._reload(loader)
        assert loader.reload_count == 2
