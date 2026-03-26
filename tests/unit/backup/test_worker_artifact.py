"""
Test suite for backup artifact packaging and manifest.
Tests schema, checksum generation, and timestamp format.
"""
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.backup.worker import BackupWorker


def test_artifact_creation():
    """Test that backup artifact is created correctly."""
    worker = BackupWorker()
    
    # Mock Redis and key enumeration
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial", "ban:192.168.1.1"]),
        (0, []),  # No more keys
    ])
    mock_redis.dump = MagicMock(return_value=b"dummy_data")
    
    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted
    
    import os
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group
    
    # Mock Path operations
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir") as mock_mkdir, \
         patch("pathlib.Path.exists") as mock_exists, \
         patch("pathlib.Path.write_bytes") as mock_write_bytes, \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        mock_exists.return_value = False
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify file operations
        assert mock_mkdir.called
        assert mock_write_bytes.called
        assert mock_write_text.called
        
        # Verify manifest content from write_text call
        manifest_content = mock_write_text.call_args[0][0]
        manifest = json.loads(manifest_content)
        
        assert manifest["filename"] == backup_path.name
        assert manifest["backup_type"] == "full"
        assert manifest["keys_count"] == 2
        assert "created_at" in manifest
        assert "checksum_sha256" in manifest


def test_manifest_schema():
    """Test that manifest has required fields."""
    worker = BackupWorker()
    
    # Mock Redis and key enumeration
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial"]),
        (0, []),  # No more keys
    ])
    mock_redis.dump = MagicMock(return_value=b"test_data")
    
    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted
    
    import os
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group
    
    # Mock Path operations
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir") as mock_mkdir, \
         patch("pathlib.Path.exists") as mock_exists, \
         patch("pathlib.Path.write_bytes") as mock_write_bytes, \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        mock_exists.return_value = False
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify manifest schema from write_text call
        manifest_content = mock_write_text.call_args[0][0]
        manifest = json.loads(manifest_content)
        
        required_fields = [
            "filename",
            "created_at",
            "backup_type",
            "keys_count",
            "checksum_sha256",
            "size_bytes",
            "included_patterns",
            "excluded_patterns",
        ]
        
        for field in required_fields:
            assert field in manifest


def test_checksum_generation():
    """Test that checksum is generated correctly."""
    worker = BackupWorker()
    
    # Mock Redis and key enumeration
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial"]),
        (0, []),  # No more keys
    ])
    test_data = b"test_data_for_checksum"
    # Configure pipeline mock so _dump_keys_batched returns test_data for the key
    pipe_mock = mock_redis.pipeline.return_value
    pipe_mock.execute.side_effect = lambda raise_on_error=True: [
        test_data for _ in pipe_mock.dump.call_args_list
    ]

    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted

    import os
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group

    # Mock Path operations
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir") as mock_mkdir, \
         patch("pathlib.Path.exists") as mock_exists, \
         patch("pathlib.Path.write_bytes") as mock_write_bytes, \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        mock_exists.return_value = False
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify checksum from write_text call
        manifest_content = mock_write_text.call_args[0][0]
        manifest = json.loads(manifest_content)
        
        # The backup now encodes key+dump together; checksum covers the encoded entry.
        from src.backup.format import encode_entry
        expected_checksum = hashlib.sha256(encode_entry("config:dial", test_data)).hexdigest()
        assert manifest["checksum_sha256"] == expected_checksum


def test_timestamp_format():
    """Test that timestamp is in ISO format."""
    worker = BackupWorker()
    
    # Mock Redis and key enumeration
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial"]),
        (0, []),  # No more keys
    ])
    mock_redis.dump = MagicMock(return_value=b"test_data")
    
    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted
    
    import os
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group
    
    # Mock Path operations
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir") as mock_mkdir, \
         patch("pathlib.Path.exists") as mock_exists, \
         patch("pathlib.Path.write_bytes") as mock_write_bytes, \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        mock_exists.return_value = False
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify timestamp format from write_text call
        manifest_content = mock_write_text.call_args[0][0]
        manifest = json.loads(manifest_content)
        
        # Should be ISO format
        assert "T" in manifest["created_at"]
        assert "Z" in manifest["created_at"]
