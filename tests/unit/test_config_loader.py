"""Unit tests for src/config/loader.py — ConfigLoader and env-var expansion."""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from src.config.loader import ConfigLoader, ConfigError, _expand_env_vars, _get_nested


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("_run() should not be called from within an async context")
    except RuntimeError:
        return asyncio.new_event_loop().run_until_complete(coro)


def _write_config(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# _expand_env_vars
# ---------------------------------------------------------------------------


class TestExpandEnvVars:
    """Test env-var expansion with ${VAR:-default} syntax."""

    def test_no_placeholders_unchanged(self):
        assert _expand_env_vars("plain: value") == "plain: value"

    def test_set_variable_expanded(self):
        with patch.dict(os.environ, {"MY_VAR": "hello"}):
            assert _expand_env_vars("x: ${MY_VAR}") == "x: hello"

    def test_unset_variable_uses_default(self):
        env = dict(os.environ)
        env.pop("UNSET_VAR_XYZ", None)
        with patch.dict(os.environ, env, clear=True):
            assert _expand_env_vars("x: ${UNSET_VAR_XYZ:-fallback}") == "x: fallback"

    def test_set_variable_ignores_default(self):
        with patch.dict(os.environ, {"MY_VAR": "real"}):
            assert _expand_env_vars("x: ${MY_VAR:-default}") == "x: real"

    def test_unset_variable_no_default_empty(self):
        env = dict(os.environ)
        env.pop("UNSET_VAR_XYZ", None)
        with patch.dict(os.environ, env, clear=True):
            result = _expand_env_vars("x: ${UNSET_VAR_XYZ}")
            assert result == "x: "

    def test_multiple_placeholders(self):
        with patch.dict(os.environ, {"A": "1", "B": "2"}):
            result = _expand_env_vars("${A} and ${B}")
            assert result == "1 and 2"


# ---------------------------------------------------------------------------
# _get_nested
# ---------------------------------------------------------------------------


class TestGetNested:
    def test_top_level_key(self):
        assert _get_nested({"a": 1}, "a") == 1

    def test_nested_key(self):
        assert _get_nested({"a": {"b": 2}}, "a.b") == 2

    def test_missing_key_returns_none(self):
        assert _get_nested({}, "a") is None

    def test_missing_nested_returns_none(self):
        assert _get_nested({"a": {}}, "a.b") is None

    def test_none_intermediate_returns_none(self):
        assert _get_nested({"a": None}, "a.b") is None


# ---------------------------------------------------------------------------
# ConfigLoader.load
# ---------------------------------------------------------------------------


class TestConfigLoaderLoad:
    def test_load_parses_valid_yaml(self, tmp_path):
        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"proxy": {"bind_port": 8080}})
        loader = ConfigLoader(str(cfg_file))
        result = _run(loader.load())
        assert result["proxy"]["bind_port"] == 8080

    def test_load_missing_file_raises(self, tmp_path):
        loader = ConfigLoader(str(tmp_path / "nonexistent.yml"))
        with pytest.raises(ConfigError, match="Cannot read config file"):
            _run(loader.load())

    def test_load_invalid_yaml_raises(self, tmp_path):
        cfg_file = tmp_path / "bad.yml"
        cfg_file.write_text("{invalid yaml: [}", encoding="utf-8")
        loader = ConfigLoader(str(cfg_file))
        with pytest.raises(ConfigError, match="YAML parse error"):
            _run(loader.load())

    def test_get_returns_loaded_config(self, tmp_path):
        cfg_file = tmp_path / "proxy.yml"
        _write_config(cfg_file, {"key": "value"})
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())
        assert loader.get()["key"] == "value"

    def test_load_expands_env_vars(self, tmp_path):
        cfg_file = tmp_path / "proxy.yml"
        cfg_file.write_text("host: ${TEST_HOST_VAR:-localhost}", encoding="utf-8")
        with patch.dict(os.environ, {"TEST_HOST_VAR": "myhost"}):
            loader = ConfigLoader(str(cfg_file))
            result = _run(loader.load())
        assert result["host"] == "myhost"


# ---------------------------------------------------------------------------
# ConfigLoader.reload
# ---------------------------------------------------------------------------


class TestConfigLoaderReload:
    @pytest.fixture
    def loader_with_config(self, tmp_path):
        cfg_file = tmp_path / "proxy.yml"
        _write_config(
            cfg_file,
            {
                "proxy": {"bind_host": "0.0.0.0", "bind_port": 8080},
                "redis": {"host": "redis", "port": 6379, "db": 0},
                "security": {"max_requests_per_minute": 100},
            },
        )
        loader = ConfigLoader(str(cfg_file))
        _run(loader.load())
        return loader, cfg_file

    def test_reload_updates_config(self, loader_with_config):
        loader, cfg_file = loader_with_config
        _write_config(
            cfg_file,
            {
                "proxy": {"bind_host": "0.0.0.0", "bind_port": 8080},
                "redis": {"host": "redis", "port": 6379, "db": 0},
                "security": {"max_requests_per_minute": 200},  # Changed
            },
        )
        _run(loader.reload())
        assert loader.get()["security"]["max_requests_per_minute"] == 200

    def test_reload_increments_count(self, loader_with_config):
        loader, cfg_file = loader_with_config
        assert loader.reload_count == 0
        _run(loader.reload())
        assert loader.reload_count == 1

    def test_reload_non_reloadable_key_raises(self, loader_with_config):
        loader, cfg_file = loader_with_config
        # Change redis.host — non-reloadable
        _write_config(
            cfg_file,
            {
                "proxy": {"bind_host": "0.0.0.0", "bind_port": 8080},
                "redis": {"host": "newhost", "port": 6379, "db": 0},  # Changed
                "security": {"max_requests_per_minute": 100},
            },
        )
        with pytest.raises(ConfigError, match="non-reloadable key"):
            _run(loader.reload())

    def test_reload_non_reloadable_keeps_old_config(self, loader_with_config):
        loader, cfg_file = loader_with_config
        _write_config(
            cfg_file,
            {
                "proxy": {"bind_host": "0.0.0.0", "bind_port": 9999},  # Changed
                "redis": {"host": "redis", "port": 6379, "db": 0},
                "security": {},
            },
        )
        try:
            _run(loader.reload())
        except ConfigError:
            pass
        # Old config must still be active
        assert loader.get()["proxy"]["bind_port"] == 8080

    def test_reload_calls_callbacks(self, loader_with_config):
        loader, cfg_file = loader_with_config
        callback_received = []
        loader.on_reload(lambda cfg: callback_received.append(cfg))
        _run(loader.reload())
        assert len(callback_received) == 1
        assert isinstance(callback_received[0], dict)

    def test_reload_multiple_callbacks_all_called(self, loader_with_config):
        loader, cfg_file = loader_with_config
        calls = []
        loader.on_reload(lambda cfg: calls.append("cb1"))
        loader.on_reload(lambda cfg: calls.append("cb2"))
        _run(loader.reload())
        assert calls == ["cb1", "cb2"]

    def test_reload_callback_exception_does_not_abort(self, loader_with_config):
        loader, cfg_file = loader_with_config
        calls = []

        def bad_callback(cfg):
            raise RuntimeError("callback error")

        def good_callback(cfg):
            calls.append("ok")

        loader.on_reload(bad_callback)
        loader.on_reload(good_callback)
        _run(loader.reload())
        assert "ok" in calls  # Good callback still called despite bad one
