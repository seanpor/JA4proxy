"""
Test suite for CLI restore command.
Tests argument-parsing failures, validation failures, and force path.
"""
import hashlib
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.cli.backup_cli import BackupCLI


def test_restore_command_success():
    """Test that restore command executes successfully."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_backup.bin"
    manifest_file = "/tmp/test_restore_backup.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_restore_backup.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer
        mock_restorer = MagicMock()
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object
            args = MagicMock()
            args.backup_file = backup_file
            args.force = False
            
            # Execute restore command
            result = cli.restore_command(args)
            
            # Should return success
            assert result == 0
            mock_restorer.restore_backup.assert_called_with(backup_file, manifest_file, destructive=False)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_restore_command_with_force():
    """Test that restore command with force flag performs destructive restore."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_force_backup.bin"
    manifest_file = "/tmp/test_restore_force_backup.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_restore_force_backup.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer
        mock_restorer = MagicMock()
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object with force flag
            args = MagicMock()
            args.backup_file = backup_file
            args.force = True
            
            # Execute restore command
            result = cli.restore_command(args)
            
            # Should return success
            assert result == 0
            mock_restorer.restore_backup.assert_called_with(backup_file, manifest_file, destructive=True)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_restore_command_missing_backup_file():
    """Test that restore command handles missing backup file."""
    cli = BackupCLI()
    
    # Create args object with non-existent file
    args = MagicMock()
    args.backup_file = "/tmp/nonexistent_backup.bin"
    args.force = False
    
    # Execute restore command
    result = cli.restore_command(args)
    
    # Should return failure
    assert result == 1


def test_restore_command_missing_manifest_file():
    """Test that restore command handles missing manifest file."""
    cli = BackupCLI()
    
    # Create backup file but no manifest
    backup_file = "/tmp/test_restore_no_manifest.bin"
    
    try:
        with open(backup_file, "wb") as f:
            f.write(b"test data")
        
        # Create args object
        args = MagicMock()
        args.backup_file = backup_file
        args.force = False
        
        # Execute restore command
        result = cli.restore_command(args)
        
        # Should return failure
        assert result == 1
        
    finally:
        # Clean up
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_restore_command_restore_failure():
    """Test that restore command handles restore failures."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_failure_backup.bin"
    manifest_file = "/tmp/test_restore_failure_backup.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_restore_failure_backup.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer to raise an exception
        mock_restorer = MagicMock()
        from src.backup.restorer import RestoreError
        mock_restorer.restore_backup.side_effect = RestoreError("Restore failed")
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object
            args = MagicMock()
            args.backup_file = backup_file
            args.force = False
            
            # Execute restore command
            result = cli.restore_command(args)
            
            # Should return failure
            assert result == 1
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_restore_cli_argument_parsing():
    """Test that restore CLI parses arguments correctly."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_cli_backup.bin"
    manifest_file = "/tmp/test_restore_cli_backup.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_restore_cli_backup.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer
        mock_restorer = MagicMock()
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Test restore command with file argument
            with patch.object(sys, 'argv', ['backup-cli', 'restore', backup_file]):
                result = cli.run()
                assert result == 0
                mock_restorer.restore_backup.assert_called_with(backup_file, manifest_file, destructive=False)
            
            # Test restore command with force flag
            with patch.object(sys, 'argv', ['backup-cli', 'restore', backup_file, '--force']):
                result = cli.run()
                assert result == 0
                mock_restorer.restore_backup.assert_called_with(backup_file, manifest_file, destructive=True)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)
