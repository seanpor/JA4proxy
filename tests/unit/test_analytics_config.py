"""Unit tests for analytics/config.py (Phase 12a).

So what: the analytics config loader is the entry point for the analytics
container. A broken loader silently prevents all cross-instance aggregation
(campaign detection, slow-scan detection, score drift alerts).
"""

import os
import textwrap

import pytest

from src.analytics.config import load_config


def _write_config(tmp_path, content: str) -> str:
    p = tmp_path / "config.yml"
    p.write_text(textwrap.dedent(content))
    return str(p)


class TestLoadConfig:
    def test_loads_minimal_yaml(self, tmp_path):
        """Minimal YAML file with only redis section → loads without error.
        So what: a bare config must not crash at startup; missing sections must
        receive defaults so the analytics node can boot."""
        path = _write_config(
            tmp_path,
            """\
            redis:
              host: redis-server
              port: 6379
            """,
        )
        cfg = load_config(path)
        assert cfg["redis"]["host"] == "redis-server"

    def test_defaults_applied_for_missing_sections(self, tmp_path):
        """Empty YAML → all defaults inserted.
        So what: the analytics node must boot with zero config, inheriting
        sensible defaults for stream keys, consumer group names, and batch sizes."""
        path = _write_config(tmp_path, "redis:\n  host: localhost\n")
        cfg = load_config(path)
        assert cfg["stream"]["key"] == "ja4proxy:events"
        assert cfg["stream"]["consumer_group"] == "analytics"
        assert cfg["stream"]["batch_size"] == 100
        assert cfg["aggregation"]["window_seconds"] == 300
        assert cfg["security"]["hmac_required"] is True

    def test_partial_section_merges_with_defaults(self, tmp_path):
        """YAML with partial stream section → missing keys filled from defaults.
        So what: partial config upgrades must not leave the node with missing
        consumer_name or timeout_ms, which would cause XREADGROUP errors."""
        path = _write_config(
            tmp_path,
            """\
            redis:
              host: localhost
            stream:
              key: custom:stream
            """,
        )
        cfg = load_config(path)
        assert cfg["stream"]["key"] == "custom:stream"
        assert cfg["stream"]["timeout_ms"] == 5000  # From defaults

    def test_env_var_redis_host_overrides_config(self, tmp_path, monkeypatch):
        """REDIS_HOST env var overrides YAML host value.
        So what: Docker Compose sets REDIS_HOST to the service name; if env
        override is broken the analytics node connects to the wrong host."""
        path = _write_config(
            tmp_path,
            """\
            redis:
              host: yaml-host
            """,
        )
        monkeypatch.setenv("REDIS_HOST", "env-host")
        cfg = load_config(path)
        assert cfg["redis"]["host"] == "env-host"

    def test_env_var_redis_port_overrides_as_int(self, tmp_path, monkeypatch):
        """REDIS_PORT env var overrides port and coerces to int.
        So what: Redis client constructors require an integer port; a string
        would silently fail with an obscure connection error."""
        path = _write_config(tmp_path, "redis:\n  host: localhost\n")
        monkeypatch.setenv("REDIS_PORT", "6380")
        cfg = load_config(path)
        assert cfg["redis"]["port"] == 6380
        assert isinstance(cfg["redis"]["port"], int)

    def test_env_var_redis_password_overrides(self, tmp_path, monkeypatch):
        """REDIS_PASSWORD env var overrides password value.
        So what: Redis AUTH requires the password from the environment in
        production; a missed override leaves the analytics node unauthenticated."""
        path = _write_config(tmp_path, "redis:\n  host: localhost\n")
        monkeypatch.setenv("REDIS_PASSWORD", "s3cr3t")
        cfg = load_config(path)
        assert cfg["redis"]["password"] == "s3cr3t"

    def test_env_vars_absent_do_not_override(self, tmp_path, monkeypatch):
        """When env vars absent, YAML values are preserved.
        So what: local development runs without env vars; the YAML host must
        not be replaced with None when the env var is unset."""
        path = _write_config(
            tmp_path,
            """\
            redis:
              host: yaml-host
              port: 6379
              password: yaml-pass
            """,
        )
        monkeypatch.delenv("REDIS_HOST", raising=False)
        monkeypatch.delenv("REDIS_PORT", raising=False)
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)
        cfg = load_config(path)
        assert cfg["redis"]["host"] == "yaml-host"
        assert cfg["redis"]["port"] == 6379
        assert cfg["redis"]["password"] == "yaml-pass"
