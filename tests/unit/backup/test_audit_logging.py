"""
Test suite for backup/restore audit logging.
Tests that audit log entries are written to Redis for all backup/restore operations.
"""
import pytest
import json
from unittest.mock import MagicMock, patch
from src.backup.worker import BackupWorker
from src.backup.restorer import BackupRestorer


def test_backup_audit_log_success():
    """Test that successful backup operations write audit log entries."""
    worker = BackupWorker()
    
    # Mock Redis
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
    
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.exists"), \
         patch("pathlib.Path.write_bytes"), \
         patch("pathlib.Path.write_text") as mock_write_text:
        
        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")
        
        # Verify audit log entry was written
        assert mock_redis.lpush.called
        
        # Check the audit log call
        lpush_calls = [call for call in mock_redis.method_calls if call[0] == 'lpush']
        assert len(lpush_calls) > 0
        
        # Get the audit log entry
        audit_call = lpush_calls[0]
        assert audit_call[0] == 'lpush'
        assert audit_call[1][0] == 'management:audit_log'
        
        # Parse the audit log entry
        audit_entry = json.loads(audit_call[1][1])
        
        # Verify audit log structure
        assert audit_entry["event"] == "backup_completed"
        assert "actor_ip" in audit_entry
        assert "timestamp" in audit_entry
        assert "detail" in audit_entry
        
        # Verify detail fields
        detail = audit_entry["detail"]
        assert detail["type"] == "full"
        assert detail["keys_exported"] == 2
        assert "filename" in detail
        assert "size_bytes" in detail
        assert "duration_seconds" in detail
        assert detail["triggered_by"] == "manual"


def test_backup_audit_log_failure():
    """Test that failed backup operations write audit log entries."""
    worker = BackupWorker()
    
    # Mock Redis to fail after connection is established
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(side_effect=[
        (0, ["config:dial"]),  # First scan succeeds
        Exception("Redis connection failed")  # Second scan fails
    ])
    mock_redis.dump.side_effect = Exception("Redis connection failed")
    
    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted
    
    import os
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group
    
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat):
        # Try to create backup (should fail)
        try:
            worker.create_backup("/tmp/test_backups")
        except Exception:
            pass  # Expected to fail
        
        # Verify audit log entry was written even on failure
        assert mock_redis.lpush.called
        
        # Check the audit log call
        lpush_calls = [call for call in mock_redis.method_calls if call[0] == 'lpush']
        assert len(lpush_calls) > 0
        
        # Get the audit log entry
        audit_call = lpush_calls[0]
        assert audit_call[0] == 'lpush'
        assert audit_call[1][0] == 'management:audit_log'
        
        # Parse the audit log entry
        audit_entry = json.loads(audit_call[1][1])
        
        # Verify audit log structure
        assert audit_entry["event"] == "backup_failed"
        assert "actor_ip" in audit_entry
        assert "timestamp" in audit_entry
        assert "detail" in audit_entry
        
        # Verify detail fields
        detail = audit_entry["detail"]
        assert "error" in detail
        assert detail["triggered_by"] == "manual"


def test_restore_audit_log_success():
    """Test that successful restore operations write audit log entries."""
    import tempfile
    import os
    import hashlib
    
    restorer = BackupRestorer()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    checksum = hashlib.sha256(test_data).hexdigest()
    
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as backup_f:
        backup_file = backup_f.name
        backup_f.write(test_data)
    
    manifest_file = backup_file + ".manifest.json"
    manifest = {
        "filename": "backup_20260321T150000Z.bin",
        "created_at": "2026-03-21T15:00:00Z",
        "backup_type": "full",
        "keys_count": 1,
        "checksum_sha256": checksum,
        "size_bytes": len(test_data),
        "included_patterns": [],
        "excluded_patterns": []
    }
    
    try:
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock Redis
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        
        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Perform restore
            restorer.restore_backup(backup_file, manifest_file, destructive=False)
        
        # Verify audit log entry was written
        assert mock_redis.lpush.called
        
        # Check the audit log call
        lpush_calls = [call for call in mock_redis.method_calls if call[0] == 'lpush']
        assert len(lpush_calls) > 0
        
        # Get the audit log entry
        audit_call = lpush_calls[0]
        assert audit_call[0] == 'lpush'
        assert audit_call[1][0] == 'management:audit_log'
        
        # Parse the audit log entry
        audit_entry = json.loads(audit_call[1][1])
        
        # Verify audit log structure
        assert audit_entry["event"] == "restore_completed"
        assert "actor_ip" in audit_entry
        assert "timestamp" in audit_entry
        assert "detail" in audit_entry
        
        # Verify detail fields
        detail = audit_entry["detail"]
        assert detail["backup_filename"] == "backup_20260321T150000Z.bin"
        assert detail["destructive"] == False
        assert detail["keys_restored"] > 0
        assert detail["validation_passed"] == True
        assert detail["triggered_by"] == "manual"
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_restore_audit_log_failure():
    """Test that failed restore operations write audit log entries."""
    import tempfile
    import os
    import hashlib
    
    restorer = BackupRestorer()
    
    # Create test backup and manifest files
    test_data = b"test backup data"
    checksum = hashlib.sha256(test_data).hexdigest()
    
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as backup_f:
        backup_file = backup_f.name
        backup_f.write(test_data)
    
    manifest_file = backup_file + ".manifest.json"
    manifest = {
        "filename": "backup_20260321T150000Z.bin",
        "created_at": "2026-03-21T15:00:00Z",
        "backup_type": "full",
        "keys_count": 1,
        "checksum_sha256": checksum,
        "size_bytes": len(test_data),
        "included_patterns": [],
        "excluded_patterns": []
    }
    
    try:
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Mock Redis to fail
        mock_redis = MagicMock()
        mock_redis.ping.side_effect = Exception("Redis connection failed")
        
        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Try to perform restore (should fail)
            try:
                restorer.restore_backup(backup_file, manifest_file, destructive=False)
            except Exception:
                pass  # Expected to fail
        
        # Verify audit log entry was written even on failure
        assert mock_redis.lpush.called
        
        # Check the audit log call
        lpush_calls = [call for call in mock_redis.method_calls if call[0] == 'lpush']
        assert len(lpush_calls) > 0
        
        # Get the audit log entry
        audit_call = lpush_calls[0]
        assert audit_call[0] == 'lpush'
        assert audit_call[1][0] == 'management:audit_log'
        
        # Parse the audit log entry
        audit_entry = json.loads(audit_call[1][1])
        
        # Verify audit log structure
        assert audit_entry["event"] == "restore_failed"
        assert "actor_ip" in audit_entry
        assert "timestamp" in audit_entry
        assert "detail" in audit_entry
        
        # Verify detail fields
        detail = audit_entry["detail"]
        assert "error" in detail
        assert detail["triggered_by"] == "manual"
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_audit_log_size_management():
    """Test that audit log size is managed (LTRIM to 1000 entries)."""
    worker = BackupWorker()
    
    # Mock Redis
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
    
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.exists"), \
         patch("pathlib.Path.write_bytes"), \
         patch("pathlib.Path.write_text"):
        
        # Create backup
        worker.create_backup("/tmp/test_backups")
        
        # Verify LTRIM was called to manage audit log size
        assert mock_redis.ltrim.called
        
        # Check LTRIM parameters
        ltrim_calls = [call for call in mock_redis.method_calls if call[0] == 'ltrim']
        assert len(ltrim_calls) > 0
        
        ltrim_call = ltrim_calls[0]
        assert ltrim_call[0] == 'ltrim'
        assert ltrim_call[1][0] == 'management:audit_log'
        assert ltrim_call[1][1] == -1000
        assert ltrim_call[1][2] == -1


def test_audit_log_actor_ip_format():
    """Test that actor_ip follows the correct format."""
    worker = BackupWorker()
    
    # Mock Redis
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
    
    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
         patch("os.access", side_effect=mock_access), \
         patch("os.stat", return_value=mock_stat), \
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.exists"), \
         patch("pathlib.Path.write_bytes"), \
         patch("pathlib.Path.write_text"):
        
        # Create backup
        worker.create_backup("/tmp/test_backups")
        
        # Verify audit log entry was written
        lpush_calls = [call for call in mock_redis.method_calls if call[0] == 'lpush']
        audit_call = lpush_calls[0]
        assert audit_call[0] == 'lpush'
        assert audit_call[1][0] == 'management:audit_log'
        
        # Parse the audit log entry
        audit_entry = json.loads(audit_call[1][1])
        
        # Verify actor_ip format (should be user@hostname for CLI operations)
        actor_ip = audit_entry["actor_ip"]
        assert "@" in actor_ip  # Should contain @ separator
        assert ":" not in actor_ip  # Should not be an IP address for CLI operations
