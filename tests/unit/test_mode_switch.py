"""
Unit tests for proxy.py mode dispatch (G1-C — Phase 20).

Validates that main() routes to ProxyServer or TapSensor based on
proxy.mode in the config file, and exits with code 1 for unknown modes.
"""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _write_cfg(tmp_path, data: dict) -> str:
    cfg = tmp_path / "proxy.yml"
    cfg.write_text(yaml.dump(data), encoding="utf-8")
    return str(cfg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestModeSwitch:
    @pytest.mark.asyncio
    async def test_passthrough_mode_creates_proxy_server(self, tmp_path):
        """mode=passthrough → ProxyServer.create() called; TapSensor not called."""
        cfg_path = _write_cfg(tmp_path, {"proxy": {"mode": "passthrough"}})
        mock_server = AsyncMock()
        with (
            patch.object(sys, "argv", ["proxy.py", cfg_path]),
            patch("proxy.ProxyServer.create", return_value=mock_server) as mock_create,
            patch("proxy.TapSensor") as mock_ts,
        ):
            from proxy import main
            await main()

        mock_create.assert_called_once_with(cfg_path)
        mock_ts.assert_not_called()

    @pytest.mark.asyncio
    async def test_tap_mode_creates_tap_sensor(self, tmp_path):
        """mode=tap → TapSensor instantiated and run() awaited; ProxyServer not called."""
        cfg_path = _write_cfg(tmp_path, {"proxy": {"mode": "tap"}})
        mock_sensor = AsyncMock()
        with (
            patch.object(sys, "argv", ["proxy.py", cfg_path]),
            patch("proxy.TapSensor", return_value=mock_sensor) as mock_ts_cls,
            patch("proxy.ProxyServer.create") as mock_create,
        ):
            from proxy import main
            await main()

        mock_ts_cls.assert_called_once()
        mock_sensor.run.assert_awaited_once()
        mock_create.assert_not_called()

    def test_invalid_mode_exits_1(self, tmp_path):
        """Unknown mode → sys.exit(1)."""
        cfg_path = _write_cfg(tmp_path, {"proxy": {"mode": "bogus"}})
        with (
            patch.object(sys, "argv", ["proxy.py", cfg_path]),
            pytest.raises(SystemExit) as exc_info,
        ):
            from proxy import main
            asyncio.run(main())

        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_missing_mode_defaults_to_passthrough(self, tmp_path):
        """Absent proxy.mode key → defaults to passthrough (ProxyServer used)."""
        cfg_path = _write_cfg(tmp_path, {"proxy": {"bind_port": 8080}})
        mock_server = AsyncMock()
        with (
            patch.object(sys, "argv", ["proxy.py", cfg_path]),
            patch("proxy.ProxyServer.create", return_value=mock_server) as mock_create,
            patch("proxy.TapSensor") as mock_ts,
        ):
            from proxy import main
            await main()

        mock_create.assert_called_once_with(cfg_path)
        mock_ts.assert_not_called()
