"""
Test suite for CLI backup command.
Tests argument parsing failures and successful backup execution.
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.cli.backup_cli import BackupCLI


def test_backup_command_success():
    """Test that backup command executes successfully."""
    cli = BackupCLI()
    
    # Mock the worker and config loader
    mock_worker = MagicMock()
    mock_worker.create_backup.return_value = "/tmp/backup_test.bin"
    
    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.return_value = {
        "backup": {
            "destination": "/tmp/backups"
        }
    }
    
    with patch.object(cli, 'worker', mock_worker), \
         patch.object(cli, 'config_loader', mock_config_loader):
        
        # Create args object
        args = MagicMock()
        args.destination = None
        
        # Execute backup command
        result = cli.backup_command(args)
        
        # Should return success
        assert result == 0
        assert mock_worker.create_backup.called


def test_backup_command_with_custom_destination():
    """Test that backup command uses custom destination."""
    cli = BackupCLI()
    
    # Mock the worker and config loader
    mock_worker = MagicMock()
    mock_worker.create_backup.return_value = "/custom/backup_test.bin"
    
    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.return_value = {
        "backup": {
            "destination": "/tmp/backups"  # This should be overridden
        }
    }
    
    with patch.object(cli, 'worker', mock_worker), \
         patch.object(cli, 'config_loader', mock_config_loader):
        
        # Create args object with custom destination
        args = MagicMock()
        args.destination = "/custom/backups"
        
        # Execute backup command
        result = cli.backup_command(args)
        
        # Should return success and use custom destination
        assert result == 0
        mock_worker.create_backup.assert_called_with("/custom/backups")


def test_backup_command_failure():
    """Test that backup command handles failures gracefully."""
    cli = BackupCLI()
    
    # Mock the worker to raise an exception
    mock_worker = MagicMock()
    mock_worker.create_backup.side_effect = Exception("Backup failed")
    
    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.return_value = {
        "backup": {
            "destination": "/tmp/backups"
        }
    }
    
    with patch.object(cli, 'worker', mock_worker), \
         patch.object(cli, 'config_loader', mock_config_loader):
        
        # Create args object
        args = MagicMock()
        args.destination = None
        
        # Execute backup command
        result = cli.backup_command(args)
        
        # Should return failure
        assert result == 1


def test_backup_command_config_loading_failure():
    """Test that backup command handles config loading failures."""
    cli = BackupCLI()
    
    # Mock the config loader to raise an exception
    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.side_effect = Exception("Config load failed")
    
    with patch.object(cli, 'config_loader', mock_config_loader):
        
        # Create args object
        args = MagicMock()
        args.destination = None
        
        # Execute backup command
        result = cli.backup_command(args)
        
        # Should return failure
        assert result == 1


def test_backup_cli_argument_parsing():
    """Test that backup CLI parses arguments correctly."""
    cli = BackupCLI()
    
    # Test with no arguments (should show help and return 1)
    with patch.object(sys, 'argv', ['backup-cli']):
        result = cli.run()
        assert result == 1
    
    # Test with backup command
    with patch.object(sys, 'argv', ['backup-cli', 'backup']):
        # Mock the worker to avoid actual backup
        mock_worker = MagicMock()
        mock_worker.create_backup.return_value = "/tmp/test.bin"
        
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {
            "backup": {
                "destination": "/tmp/backups"
            }
        }
        
        with patch.object(cli, 'worker', mock_worker), \
             patch.object(cli, 'config_loader', mock_config_loader):
            result = cli.run()
            assert result == 0


def test_backup_cli_with_custom_destination_arg():
    """Test that backup CLI accepts custom destination argument."""
    cli = BackupCLI()

    # Mock the worker
    mock_worker = MagicMock()
    mock_worker.create_backup.return_value = "/custom/test.bin"

    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.return_value = {
        "backup": {
            "destination": "/tmp/backups"
        }
    }

    with patch.object(cli, 'worker', mock_worker), \
         patch.object(cli, 'config_loader', mock_config_loader):

        # Test with custom destination
        with patch.object(sys, 'argv', ['backup-cli', 'backup', '--destination', '/custom/backups']):
            result = cli.run()
            assert result == 0
            mock_worker.create_backup.assert_called_with("/custom/backups")


# ---------------------------------------------------------------------------
# Coverage gap additions — lines 88-90, 144-147, 151-153, 195-197, 258-260,
#                          265-266, 270
# ---------------------------------------------------------------------------

import json
import shutil
import tempfile
from pathlib import Path

from src.backup.restorer import RestoreError


class TestBackupCLICoverageGaps:
    """Missing branches: unexpected exceptions, corrupted/missing manifest in list,
    Exception in validate, Exception in run(), and main() entry points."""

    def test_restore_command_unexpected_exception_returns_1(self):
        """Lines 88-90: non-RestoreError in restore_command → return 1.
        So what: without this except, an unexpected exception (e.g., AttributeError
        on the restorer object) propagates and crashes the CLI process instead of
        returning a structured exit code that scripts can handle."""
        cli = BackupCLI()
        args = MagicMock()
        args.backup_file = "/some/file.bin"
        args.force = False

        with patch("os.path.exists", return_value=True), \
             patch.object(cli.restorer, "restore_backup", side_effect=RuntimeError("boom")):
            result = cli.restore_command(args)

        assert result == 1

    def test_list_command_corrupted_manifest_prints_message(self, tmp_path):
        """Lines 144-145: JSON-invalid manifest → prints '(corrupted manifest)'.
        So what: without this except, one corrupted manifest aborts listing of all
        subsequent backups, making the list command useless during incident response."""
        bp = tmp_path / "backup_20260101T000000Z.bin"
        mp = tmp_path / "backup_20260101T000000Z.bin.manifest.json"
        bp.write_bytes(b"data")
        mp.write_text("{ invalid json !!!")

        cli = BackupCLI()
        args = MagicMock()
        args.directory = str(tmp_path)
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {}

        with patch.object(cli, "config_loader", mock_config_loader):
            import io
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                result = cli.list_command(args)

        assert result == 0
        assert "corrupted manifest" in captured.getvalue()

    def test_list_command_missing_manifest_prints_message(self, tmp_path):
        """Lines 146-147: backup file without manifest → prints '(missing manifest)'.
        So what: without this else branch, backup files missing their manifest are
        silently omitted from the list output, hiding partial/corrupt backup sets."""
        bp = tmp_path / "backup_20260101T000000Z.bin"
        bp.write_bytes(b"data")
        # No manifest file created

        cli = BackupCLI()
        args = MagicMock()
        args.directory = str(tmp_path)
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {}

        with patch.object(cli, "config_loader", mock_config_loader):
            import io
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                result = cli.list_command(args)

        assert result == 0
        assert "missing manifest" in captured.getvalue()

    def test_list_command_unexpected_exception_returns_1(self):
        """Lines 151-153: unexpected Exception in list_command → return 1.
        So what: without this except, e.g. a permissions error on glob() propagates
        and crashes the operator's listing session instead of printing a usable error."""
        cli = BackupCLI()
        args = MagicMock()
        args.directory = "/some/dir"
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {}

        with patch.object(cli, "config_loader", mock_config_loader), \
             patch("os.path.exists", return_value=True), \
             patch("src.cli.backup_cli.Path.glob", side_effect=PermissionError("denied")):
            result = cli.list_command(args)

        assert result == 1

    def test_validate_command_unexpected_exception_returns_1(self):
        """Lines 195-197: non-RestoreError in validate_command → return 1.
        So what: without this except, an unexpected error (e.g., checksum library bug)
        propagates unhandled, crashing the validation script used in backup verification jobs."""
        cli = BackupCLI()
        args = MagicMock()
        args.backup_file = "/some/file.bin"

        with patch("os.path.exists", return_value=True), \
             patch.object(cli.restorer, "load_manifest", side_effect=RuntimeError("unexpected")):
            result = cli.validate_command(args)

        assert result == 1

    def test_run_exception_in_arg_parsing_returns_1(self):
        """Lines 258-260: Exception during argparse.parse_args → return 1.
        So what: without this except, a SystemExit from argparse (e.g., unknown flag)
        propagates uncaught when run() is called programmatically instead of via CLI."""
        cli = BackupCLI()

        with patch("argparse.ArgumentParser.parse_args", side_effect=Exception("parse error")):
            result = cli.run(["--bad-flag"])

        assert result == 1

    def test_main_function_returns_int(self):
        """Lines 265-266: main() constructs BackupCLI and calls run().
        So what: if main() is broken, the `backup-cli` console_scripts entry point
        returns None instead of an exit code, silently succeeding even on failures."""
        with patch("src.cli.backup_cli.BackupCLI") as MockCLI:
            instance = MagicMock()
            instance.run.return_value = 0
            MockCLI.return_value = instance

            from src.cli.backup_cli import main
            result = main()

        assert result == 0

    # Line 270 (`if __name__ == "__main__": sys.exit(main())`) is standard Python
    # boilerplate — unreachable via import-based test collection. Accepted at 99%.
