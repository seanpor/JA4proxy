"""
Test suite for Redis control key updates.
Tests success path and failure path assertions.
"""
from unittest.mock import MagicMock, patch

import pytest

from src.backup.worker import BackupWorker


def test_control_keys_success_path():
    """Test that control keys are updated on success."""
    worker = BackupWorker()
    
    # Mock Redis operations
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial", "ban:192.168.1.1"]),
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
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.exists"), \
         patch("pathlib.Path.write_bytes"), \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify control keys were updated
        assert mock_redis.set.called
        
        # Check the set calls
        set_calls = mock_redis.set.call_args_list
        assert len(set_calls) >= 2
        
        # Check for backup:latest update
        latest_calls = [call for call in set_calls if call[0][0] == 'backup:latest']
        assert len(latest_calls) > 0
        
        # Check for backup:last_success update
        success_calls = [call for call in set_calls if call[0][0] == 'backup:last_success']
        assert len(success_calls) > 0


def test_control_keys_failure_path():
    """Test that control keys are updated on failure."""
    worker = BackupWorker()
    
    # Mock Redis operations to fail during dump
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial"]),
        (0, []),  # No more keys
    ])
    mock_redis.dump.side_effect = Exception("Redis dump error")
    
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
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.exists"), \
         patch("pathlib.Path.write_bytes"), \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        # Try to create backup (should fail during dump)
        with pytest.raises(Exception):
            worker.create_backup("/tmp/test_backups")
        
        # Verify failure control key was updated
        assert mock_redis.set.called
        
        # Check the set calls
        set_calls = mock_redis.set.call_args_list
        assert len(set_calls) > 0
        
        # Check for backup:last_failure update
        failure_calls = [call for call in set_calls if call[0][0] == 'backup:last_failure']
        assert len(failure_calls) > 0
