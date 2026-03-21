"""
Test suite for CLI backup command.
Tests argument parsing failures and successful backup execution.
"""
import pytest
import os
import sys
from unittest.mock import MagicMock, patch
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
