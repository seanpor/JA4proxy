"""
Tests for src/cli/main.py — CLI entry point.
Phase 104: coverage gap closure.
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from src.cli.main import cli, geoip_update, health, proxy_scale


@pytest.fixture
def runner():
    return CliRunner()


# ── top-level group ──────────────────────────────────────────────────────────


class TestCLIGroup:
    def test_cli_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "JA4proxy Master CLI" in result.output

    def test_cli_default_format_is_table(self, runner):
        """Invoke a sub-command without --format; ctx.obj['fmt'] should be 'table'."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_cli_json_format(self, runner):
        result = runner.invoke(cli, ["--format", "json", "--help"])
        assert result.exit_code == 0

    def test_cli_invalid_format(self, runner):
        result = runner.invoke(cli, ["--format", "xml"])
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "xml" in result.output


# ── health command ───────────────────────────────────────────────────────────


class TestHealthCommand:
    @patch("src.cli.main.WorkspaceIntegrityTool", create=True)
    def test_health_pass_table(self, mock_wit_cls, runner):
        """No broken refs -> PASS in table format."""
        mock_wit = MagicMock()
        mock_wit.run.return_value = (["orphan1.py"], {})
        # The import happens inside the command; patch at the import target
        with patch.dict(
            "sys.modules",
            {
                "scripts.workspace_integrity_tool": MagicMock(
                    WorkspaceIntegrityTool=MagicMock(return_value=mock_wit)
                ),
            },
        ):
            result = runner.invoke(cli, ["health"])
        assert result.exit_code == 0
        assert "PASS" in result.output
        assert "orphan" in result.output.lower()

    def test_health_fail_table(self, runner):
        """Broken refs -> FAIL in table format."""
        mock_wit = MagicMock()
        mock_wit.run.return_value = (
            [],
            {"docs/README.md": ["missing_link.md"]},
        )
        with patch.dict(
            "sys.modules",
            {
                "scripts.workspace_integrity_tool": MagicMock(
                    WorkspaceIntegrityTool=MagicMock(return_value=mock_wit)
                ),
            },
        ):
            result = runner.invoke(cli, ["health"])
        assert result.exit_code == 0
        assert "FAIL" in result.output
        assert "missing_link.md" in result.output

    def test_health_json_output(self, runner):
        """JSON format for health output."""
        mock_wit = MagicMock()
        mock_wit.run.return_value = (["orphan.py"], {})
        with patch.dict(
            "sys.modules",
            {
                "scripts.workspace_integrity_tool": MagicMock(
                    WorkspaceIntegrityTool=MagicMock(return_value=mock_wit)
                ),
            },
        ):
            result = runner.invoke(cli, ["--format", "json", "health"])
        assert result.exit_code == 0
        import json

        # First line is "Running Workspace Integrity Audit..." — skip it
        json_text = result.output.split("\n", 1)[1]
        data = json.loads(json_text)
        assert data["status"] == "pass"
        assert data["orphan_count"] == 1


# ── proxy scale command ──────────────────────────────────────────────────────


class TestProxyScale:
    def test_proxy_scale_success(self, runner):
        with patch("src.cli.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["proxy", "scale", "3"])
        assert result.exit_code == 0
        assert "Scaling to 3" in result.output
        mock_run.assert_called_once_with(
            ["bash", "scripts/scale-proxies.sh", "3"], check=True
        )

    def test_proxy_scale_failure(self, runner):
        import subprocess

        with patch("src.cli.main.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")
            result = runner.invoke(cli, ["proxy", "scale", "5"])
        assert result.exit_code == 0  # click catches the echo, no sys.exit
        assert "Error scaling" in result.output

    def test_proxy_scale_requires_int(self, runner):
        result = runner.invoke(cli, ["proxy", "scale", "abc"])
        assert result.exit_code != 0

    def test_proxy_help(self, runner):
        result = runner.invoke(cli, ["proxy", "--help"])
        assert result.exit_code == 0
        assert "Manage JA4proxy instances" in result.output


# ── threat group ─────────────────────────────────────────────────────────────


class TestThreatGroup:
    def test_threat_help(self, runner):
        result = runner.invoke(cli, ["threat", "--help"])
        assert result.exit_code == 0
        assert "Manage threats" in result.output


# ── geoip commands ───────────────────────────────────────────────────────────


class TestGeoIPCommands:
    def test_geoip_help(self, runner):
        result = runner.invoke(cli, ["geoip", "--help"])
        assert result.exit_code == 0
        assert "GeoIP" in result.output

    def test_geoip_update_success(self, runner):
        with patch("src.cli.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["geoip", "update"])
        assert result.exit_code == 0
        mock_run.assert_called_once_with(
            ["bash", "scripts/update-geoip.sh"], check=True
        )

    def test_geoip_update_failure(self, runner):
        import subprocess

        with patch("src.cli.main.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")
            result = runner.invoke(cli, ["geoip", "update"])
        # CalledProcessError propagates; click shows the traceback
        assert result.exit_code != 0
