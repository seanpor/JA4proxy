"""
Test suite for CLI list and validate commands.
Tests missing directory, missing manifest, corrupted manifest scenarios.
"""
import pytest
import os
import sys
import json
import hashlib
from unittest.mock import MagicMock, patch
from src.cli.backup_cli import BackupCLI


def test_list_command_success():
    """Test that list command executes successfully."""
    cli = BackupCLI()
    
    # Create a temporary backup directory with test files
    backup_dir = "/tmp/test_backup_list"
    os.makedirs(backup_dir, exist_ok=True)
    
    try:
        # Create some test backup files
        for i in range(3):
            backup_file = os.path.join(backup_dir, f"backup_2026032{i+1}T160000Z.bin")
            manifest_file = os.path.join(backup_dir, f"backup_2026032{i+1}T160000Z.bin.manifest.json")
            
            # Create backup file
            with open(backup_file, "wb") as f:
                f.write(b"test data")
            
            # Create manifest
            manifest = {
                "filename": f"backup_2026032{i+1}T160000Z.bin",
                "created_at": f"2026-03-2{i+1}T16:00:00Z",
                "backup_type": "full",
                "keys_count": i + 1,
                "checksum_sha256": "test_checksum",
                "size_bytes": 100 + i,
                "included_patterns": [],
                "excluded_patterns": []
            }
            with open(manifest_file, "w") as f:
                json.dump(manifest, f)
        
        # Mock the config loader
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {
            "backup": {
                "destination": backup_dir
            }
        }
        
        with patch.object(cli, 'config_loader', mock_config_loader):
            # Create args object
            args = MagicMock()
            args.directory = None
            
            # Execute list command
            result = cli.list_command(args)
            
            # Should return success
            assert result == 0
        
    finally:
        # Clean up
        for f in os.listdir(backup_dir):
            os.remove(os.path.join(backup_dir, f))
        os.rmdir(backup_dir)


def test_list_command_with_custom_directory():
    """Test that list command uses custom directory."""
    cli = BackupCLI()
    
    # Create a temporary backup directory
    custom_dir = "/tmp/test_backup_custom"
    os.makedirs(custom_dir, exist_ok=True)
    
    try:
        # Create a test backup file
        backup_file = os.path.join(custom_dir, "backup_20260321T160000Z.bin")
        manifest_file = os.path.join(custom_dir, "backup_20260321T160000Z.bin.manifest.json")
        
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(b"test data")
        
        # Create manifest
        manifest = {
            "filename": "backup_20260321T160000Z.bin",
            "created_at": "2026-03-21T16:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": "test_checksum",
            "size_bytes": 100,
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the config loader (should be overridden by custom directory)
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {
            "backup": {
                "destination": "/tmp/wrong_directory"
            }
        }
        
        with patch.object(cli, 'config_loader', mock_config_loader):
            # Create args object with custom directory
            args = MagicMock()
            args.directory = custom_dir
            
            # Execute list command
            result = cli.list_command(args)
            
            # Should return success
            assert result == 0
        
    finally:
        # Clean up
        for f in os.listdir(custom_dir):
            os.remove(os.path.join(custom_dir, f))
        os.rmdir(custom_dir)


def test_list_command_missing_directory():
    """Test that list command handles missing directory."""
    cli = BackupCLI()
    
    # Mock the config loader to point to non-existent directory
    mock_config_loader = MagicMock()
    mock_config_loader._read_and_parse.return_value = {
        "backup": {
            "destination": "/tmp/nonexistent_backup_directory"
        }
    }
    
    with patch.object(cli, 'config_loader', mock_config_loader):
        # Create args object
        args = MagicMock()
        args.directory = None
        
        # Execute list command
        result = cli.list_command(args)
        
        # Should return failure
        assert result == 1


def test_list_command_empty_directory():
    """Test that list command handles empty directory."""
    cli = BackupCLI()
    
    # Create an empty backup directory
    empty_dir = "/tmp/test_backup_empty"
    os.makedirs(empty_dir, exist_ok=True)
    
    try:
        # Mock the config loader
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {
            "backup": {
                "destination": empty_dir
            }
        }
        
        with patch.object(cli, 'config_loader', mock_config_loader):
            # Create args object
            args = MagicMock()
            args.directory = None
            
            # Execute list command
            result = cli.list_command(args)
            
            # Should return success (empty directory is valid)
            assert result == 0
        
    finally:
        # Clean up
        os.rmdir(empty_dir)


def test_validate_command_success():
    """Test that validate command executes successfully."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data for validation"
    backup_file = "/tmp/test_validate_backup.bin"
    manifest_file = "/tmp/test_validate_backup.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_validate_backup.bin",
            "created_at": "2026-03-21T16:00:00Z",
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
        mock_restorer.load_manifest.return_value = manifest
        mock_restorer.verify_checksum.return_value = True
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object
            args = MagicMock()
            args.backup_file = backup_file
            
            # Execute validate command
            result = cli.validate_command(args)
            
            # Should return success
            assert result == 0
            mock_restorer.load_manifest.assert_called_with(manifest_file)
            mock_restorer.verify_checksum.assert_called_with(backup_file, checksum)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_validate_command_missing_backup_file():
    """Test that validate command handles missing backup file."""
    cli = BackupCLI()
    
    # Create args object with non-existent file
    args = MagicMock()
    args.backup_file = "/tmp/nonexistent_validate_backup.bin"
    
    # Execute validate command
    result = cli.validate_command(args)
    
    # Should return failure
    assert result == 1


def test_validate_command_missing_manifest_file():
    """Test that validate command handles missing manifest file."""
    cli = BackupCLI()
    
    # Create backup file but no manifest
    backup_file = "/tmp/test_validate_no_manifest.bin"
    
    try:
        with open(backup_file, "wb") as f:
            f.write(b"test data")
        
        # Create args object
        args = MagicMock()
        args.backup_file = backup_file
        
        # Execute validate command
        result = cli.validate_command(args)
        
        # Should return failure
        assert result == 1
        
    finally:
        # Clean up
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_validate_command_corrupted_manifest():
    """Test that validate command handles corrupted manifest."""
    cli = BackupCLI()
    
    # Create backup file and corrupted manifest
    backup_file = "/tmp/test_validate_corrupted.bin"
    manifest_file = "/tmp/test_validate_corrupted.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(b"test data")
        
        # Create corrupted manifest
        with open(manifest_file, "w") as f:
            f.write("{corrupted json}")
        
        # Mock the restorer to raise RestoreError
        mock_restorer = MagicMock()
        from src.backup.restorer import RestoreError
        mock_restorer.load_manifest.side_effect = RestoreError("Failed to load manifest")
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object
            args = MagicMock()
            args.backup_file = backup_file
            
            # Execute validate command
            result = cli.validate_command(args)
            
            # Should return failure
            assert result == 1
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_validate_command_checksum_failure():
    """Test that validate command handles checksum verification failure."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_validate_checksum.bin"
    manifest_file = "/tmp/test_validate_checksum.bin.manifest.json"
    
    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest with wrong checksum
        wrong_checksum = "0000000000000000000000000000000000000000000000000000000000000000"
        manifest = {
            "filename": "test_validate_checksum.bin",
            "created_at": "2026-03-21T16:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": wrong_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer
        mock_restorer = MagicMock()
        mock_restorer.load_manifest.return_value = manifest
        mock_restorer.verify_checksum.return_value = False
        
        with patch.object(cli, 'restorer', mock_restorer):
            # Create args object
            args = MagicMock()
            args.backup_file = backup_file
            
            # Execute validate command
            result = cli.validate_command(args)
            
            # Should return failure due to checksum mismatch
            assert result == 1
            mock_restorer.verify_checksum.assert_called_with(backup_file, wrong_checksum)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_list_validate_cli_argument_parsing():
    """Test that list and validate CLI parse arguments correctly."""
    cli = BackupCLI()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_list_validate_backup.bin"
    manifest_file = "/tmp/test_list_validate_backup.bin.manifest.json"
    backup_dir = "/tmp/test_list_validate_dir"
    
    os.makedirs(backup_dir, exist_ok=True)
    
    try:
        # Create backup file in directory
        full_backup_path = os.path.join(backup_dir, "backup_20260321T160000Z.bin")
        full_manifest_path = os.path.join(backup_dir, "backup_20260321T160000Z.bin.manifest.json")
        
        with open(full_backup_path, "wb") as f:
            f.write(test_data)
        
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "backup_20260321T160000Z.bin",
            "created_at": "2026-03-21T16:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(full_manifest_path, "w") as f:
            json.dump(manifest, f)
        
        # Mock the restorer and config loader
        mock_restorer = MagicMock()
        mock_restorer.load_manifest.return_value = manifest
        mock_restorer.verify_checksum.return_value = True
        
        mock_config_loader = MagicMock()
        mock_config_loader._read_and_parse.return_value = {
            "backup": {
                "destination": backup_dir
            }
        }
        
        with patch.object(cli, 'restorer', mock_restorer), \
             patch.object(cli, 'config_loader', mock_config_loader):
            
            # Test list command
            with patch.object(sys, 'argv', ['backup-cli', 'list']):
                result = cli.run()
                assert result == 0
            
            # Test validate command (use the actual backup file in the directory)
            with patch.object(sys, 'argv', ['backup-cli', 'validate', full_backup_path]):
                result = cli.run()
                assert result == 0
            
            # Test list command with custom directory
            with patch.object(sys, 'argv', ['backup-cli', 'list', '--directory', backup_dir]):
                result = cli.run()
                assert result == 0
        
    finally:
        # Clean up
        for f in os.listdir(backup_dir):
            os.remove(os.path.join(backup_dir, f))
        os.rmdir(backup_dir)
