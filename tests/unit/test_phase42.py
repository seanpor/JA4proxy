"""
Unit tests for Phase 42 Zero-Downtime Data Upgrades.
"""

import asyncio
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from src.utils.atomic_swap import atomic_write, atomic_symlink_swap
from src.config.loader import ConfigLoader, ConfigError


def test_atomic_write(tmp_path):
    target = tmp_path / "test.txt"
    data = b"hello world"
    atomic_write(data, target)
    
    assert target.exists()
    assert target.read_bytes() == data
    # Check permissions
    assert (target.stat().st_mode & 0o777) == 0o644


def test_atomic_symlink_swap(tmp_path):
    dir1 = tmp_path / "v1"
    dir1.mkdir()
    (dir1 / "f.txt").write_text("v1")
    
    dir2 = tmp_path / "v2"
    dir2.mkdir()
    (dir2 / "f.txt").write_text("v2")
    
    symlink = tmp_path / "current"
    os.symlink(dir1, symlink)
    
    assert symlink.resolve() == dir1
    assert (symlink / "f.txt").read_text() == "v1"
    
    atomic_symlink_swap(symlink, dir2)
    
    assert symlink.resolve() == dir2
    assert (symlink / "f.txt").read_text() == "v2"


@pytest.mark.asyncio
async def test_config_loader_async_reload(tmp_path):
    cfg_file = tmp_path / "proxy.yml"
    cfg_file.write_text("proxy:\n  mode: passthrough\nsecurity:\n  val: 1")
    
    loader = ConfigLoader(str(cfg_file))
    await loader.load()
    assert loader.get()["security"]["val"] == 1
    
    # Update file
    cfg_file.write_text("proxy:\n  mode: passthrough\nsecurity:\n  val: 2")
    
    await loader.reload()
    assert loader.get()["security"]["val"] == 2
    assert loader.reload_count == 1


@pytest.mark.asyncio
async def test_proxy_server_on_config_reload():
    # Mock components
    mock_proxy = MagicMock()
    mock_proxy.config = {"geoip": {"database_path": "old.bin"}}
    mock_proxy.geoip = MagicMock()
    mock_proxy.geoip.current_path = "old.bin"
    mock_proxy.pipeline = MagicMock()
    mock_proxy.health_monitor = MagicMock()
    mock_proxy.logger = MagicMock()
    
    from proxy import ProxyServer
    
    # We want to test the _on_config_reload method logic
    # but ProxyServer is a complex class, so we patch needed parts
    
    new_config = {
        "geoip": {"database_path": "new.bin"},
        "security": {"thresholds": {}},
        "metrics": {"port": 9090}
    }
    
    with patch("src.security.risk_scorer.RiskScorer.from_config") as mock_scorer_cls, \
         patch("src.security.action_decider.ActionDecider.from_config") as mock_decider_cls:
        
        await ProxyServer._on_config_reload(mock_proxy, new_config)
        
    assert mock_proxy.config == new_config
    mock_proxy.geoip.reload.assert_called_with("new.bin")
    mock_proxy.pipeline.update_scorer.assert_called()
    assert mock_proxy.health_monitor.config == new_config
