#!/usr/bin/env python3
"""
Additional ConfigLoader tests for previously uncovered branches.

Covers:
- _read_and_parse: non-mapping YAML raises ConfigError (line 228)
- setup_sighup: _handle_sighup closure is callable (line 182)
- setup_sighup: OSError/NotImplementedError logged as warning (lines 186-188)
- _reload_and_log_error: swallows ConfigError (lines 250-253)
"""

import asyncio
import signal
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from src.config.loader import ConfigLoader, ConfigError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_config(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _read_and_parse: non-mapping YAML (line 228)
# ---------------------------------------------------------------------------


class TestNonMappingYaml:
    def test_scalar_yaml_raises_config_error(self, tmp_path):
        """Line 228: YAML that parses to a non-dict raises ConfigError."""
        cfg_file = tmp_path / "scalar.yml"
        _write_yaml(cfg_file, "just a string\n")
        loader = ConfigLoader(str(cfg_file))
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            _run(loader.load())

    def test_list_yaml_raises_config_error(self, tmp_path):
        """YAML list also raises ConfigError (not a mapping)."""
        cfg_file = tmp_path / "list.yml"
        _write_yaml(cfg_file, "- item1\n- item2\n")
        loader = ConfigLoader(str(cfg_file))
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            _run(loader.load())

    def test_null_yaml_raises_config_error(self, tmp_path):
        """Empty YAML file parses to None, which is not a dict."""
        cfg_file = tmp_path / "empty.yml"
        _write_yaml(cfg_file, "\n")
        loader = ConfigLoader(str(cfg_file))
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            _run(loader.load())


# ---------------------------------------------------------------------------
# setup_sighup: _handle_sighup closure (line 182) and OSError path (186-188)
# ---------------------------------------------------------------------------


class TestSetupSighup:
    def test_sighup_unavailable_logs_warning(self, tmp_path, caplog):
        """Lines 186-188: add_signal_handler raises OSError → warning logged."""
        import logging

        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"key": "val"})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())

        loop = MagicMock()
        loop.add_signal_handler.side_effect = OSError("not supported")

        with caplog.at_level(logging.WARNING, logger="src.config.loader"):
            loader.setup_sighup(loop)

        assert any("sighup_unavailable" in r.message for r in caplog.records)

    def test_not_implemented_logs_warning(self, tmp_path, caplog):
        """NotImplementedError from add_signal_handler also logs warning."""
        import logging

        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"key": "val"})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())

        loop = MagicMock()
        loop.add_signal_handler.side_effect = NotImplementedError("windows")

        with caplog.at_level(logging.WARNING, logger="src.config.loader"):
            loader.setup_sighup(loop)

        assert any("sighup_unavailable" in r.message for r in caplog.records)

    def test_handle_sighup_closure_calls_create_task(self, tmp_path):
        """Line 182: add_signal_handler is given a callable _handle_sighup.

        We capture the handler and call it directly to verify it calls
        asyncio.create_task (lines 181-182).
        """
        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"key": "val"})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())

        captured_handler = {}

        loop = MagicMock()
        loop.add_signal_handler.side_effect = lambda sig, handler: (
            captured_handler.update({"h": handler})
        )
        loader.setup_sighup(loop)

        assert "h" in captured_handler, "add_signal_handler was not called"

        # Call the SIGHUP handler and verify asyncio.create_task is called
        with patch("asyncio.create_task") as mock_create_task:
            captured_handler["h"]()
            mock_create_task.assert_called_once()


# ---------------------------------------------------------------------------
# _reload_and_log_error (lines 250-253)
# ---------------------------------------------------------------------------


class TestReloadAndLogError:
    def test_config_error_is_swallowed(self, tmp_path):
        """Lines 250-253: ConfigError from reload() is caught and not re-raised."""
        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"proxy": {"bind_port": 8080}})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())

        # Make reload() raise ConfigError
        with patch.object(loader, "reload", new_callable=AsyncMock) as mock_reload:
            mock_reload.side_effect = ConfigError("bad config")
            # Must not raise — ConfigError is swallowed
            _run(loader._reload_and_log_error())

    def test_successful_reload_propagates_normally(self, tmp_path):
        """When reload() succeeds, _reload_and_log_error returns normally."""
        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"proxy": {"bind_port": 8080}})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())

        with patch.object(loader, "reload", new_callable=AsyncMock) as mock_reload:
            mock_reload.return_value = None
            # Must not raise
            _run(loader._reload_and_log_error())
            mock_reload.assert_called_once()
