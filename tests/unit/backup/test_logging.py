"""
Test suite for backup and restore structured logging.
Tests that JSON logs are properly emitted during operations.
"""
import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from src.backup.restorer import BackupRestorer
from src.backup.restorer import logger as restorer_logger
from src.backup.worker import BackupWorker
from src.backup.worker import logger as worker_logger

# Configure loggers to propagate to root logger that caplog captures
worker_logger.propagate = True
restorer_logger.propagate = True


def test_backup_logging_success(caplog):
    """Test that backup operations emit proper structured logs on success."""
    # Set up logging capture
    with caplog.at_level(logging.INFO):
        worker = BackupWorker()
        
        # Mock Redis and file operations
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
        
        # Verify logs were emitted
        log_records = caplog.records
        assert len(log_records) >= 2  # At least start and success logs
        
        # Check start log and keys enumerated log
        start_log = None
        keys_log = None
        success_log = None
        
        for record in log_records:
            log_data = json.loads(record.getMessage())
            if log_data.get("event") == "backup_started":
                start_log = log_data
            elif log_data.get("event") == "keys_enumerated":
                keys_log = log_data
            elif log_data.get("event") == "backup_succeeded":
                success_log = log_data
        
        # Verify start log structure
        assert start_log is not None
        assert start_log["type"] == "system"
        assert start_log["level"] == "INFO"
        assert start_log["subsystem"] == "backup"
        assert start_log["event"] == "backup_started"
        assert "ts" in start_log
        
        # Verify keys enumerated log structure
        assert keys_log is not None
        assert keys_log["type"] == "system"
        assert keys_log["level"] == "INFO"
        assert keys_log["subsystem"] == "backup"
        assert keys_log["event"] == "keys_enumerated"
        assert "ts" in keys_log
        assert "keys_expected" in keys_log
        
        # Verify success log structure
        assert success_log is not None
        assert success_log["type"] == "system"
        assert success_log["level"] == "INFO"
        assert success_log["subsystem"] == "backup"
        assert success_log["event"] == "backup_succeeded"
        assert "ts" in success_log
        assert "keys_processed" in success_log
        assert "size_bytes" in success_log
        assert "duration_ms" in success_log
        assert "artifact_path" in success_log


def test_backup_logging_failure(caplog):
    """Test that backup operations emit proper structured logs on failure."""
    # Set up logging capture
    with caplog.at_level(logging.INFO):
        worker = BackupWorker()
        
        # Mock Redis to fail
        mock_redis = MagicMock()
        mock_redis.scan.side_effect = Exception("Redis connection failed")
        
        # Mock filesystem validation to pass
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
        
        # Verify logs were emitted
        log_records = caplog.records
        assert len(log_records) >= 2  # At least start and failure logs
        
        # Check start log
        start_log = None
        failure_log = None
        
        for record in log_records:
            log_data = json.loads(record.getMessage())
            if log_data.get("event") == "backup_started":
                start_log = log_data
            elif log_data.get("event") == "backup_failed":
                failure_log = log_data
        
        # Verify start log structure
        assert start_log is not None
        assert start_log["type"] == "system"
        assert start_log["level"] == "INFO"
        assert start_log["subsystem"] == "backup"
        assert start_log["event"] == "backup_started"
        
        # Verify failure log structure
        assert failure_log is not None
        assert failure_log["type"] == "system"
        assert failure_log["level"] == "ERROR"
        assert failure_log["subsystem"] == "backup"
        assert failure_log["event"] == "backup_failed"
        assert "ts" in failure_log
        assert "error" in failure_log
        assert "duration_ms" in failure_log


def test_restore_logging_success(caplog):
    """Test that restore operations emit proper structured logs on success."""
    import hashlib
    import os
    import tempfile
    
    # Set up logging capture
    with caplog.at_level(logging.INFO):
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
            
            # Verify logs were emitted
            log_records = caplog.records
            assert len(log_records) >= 2  # At least start and success logs
            
            # Check start log and manifest loaded log
            start_log = None
            manifest_log = None
            success_log = None
            
            for record in log_records:
                log_data = json.loads(record.getMessage())
                if log_data.get("event") == "restore_started":
                    start_log = log_data
                elif log_data.get("event") == "manifest_loaded":
                    manifest_log = log_data
                elif log_data.get("event") == "restore_succeeded":
                    success_log = log_data
            
            # Verify start log structure
            assert start_log is not None
            assert start_log["type"] == "system"
            assert start_log["level"] == "INFO"
            assert start_log["subsystem"] == "restore"
            assert start_log["event"] == "restore_started"
            assert "ts" in start_log
            assert "restore_type" in start_log
            assert start_log["restore_type"] == "non-destructive"
            
            # Verify manifest loaded log structure
            assert manifest_log is not None
            assert manifest_log["type"] == "system"
            assert manifest_log["level"] == "INFO"
            assert manifest_log["subsystem"] == "restore"
            assert manifest_log["event"] == "manifest_loaded"
            assert "ts" in manifest_log
            assert "keys_expected" in manifest_log
            
            # Verify success log structure
            assert success_log is not None
            assert success_log["type"] == "system"
            assert success_log["level"] == "INFO"
            assert success_log["subsystem"] == "restore"
            assert success_log["event"] == "restore_succeeded"
            assert "ts" in success_log
            assert "keys_restored" in success_log
            assert "duration_ms" in success_log
            assert "restore_type" in success_log
            assert success_log["restore_type"] == "non-destructive"
            
        finally:
            # Clean up
            for f in [backup_file, manifest_file]:
                if os.path.exists(f):
                    os.remove(f)


def test_restore_logging_failure(caplog):
    """Test that restore operations emit proper structured logs on failure."""
    import hashlib
    import os
    import tempfile
    
    # Set up logging capture
    with caplog.at_level(logging.INFO):
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
            
            # Verify logs were emitted
            log_records = caplog.records
            assert len(log_records) >= 2  # At least start and failure logs
            
            # Check start log
            start_log = None
            failure_log = None
            
            for record in log_records:
                log_data = json.loads(record.getMessage())
                if log_data.get("event") == "restore_started":
                    start_log = log_data
                elif log_data.get("event") == "restore_failed":
                    failure_log = log_data
            
            # Verify start log structure
            assert start_log is not None
            assert start_log["type"] == "system"
            assert start_log["level"] == "INFO"
            assert start_log["subsystem"] == "restore"
            assert start_log["event"] == "restore_started"
            
            # Verify failure log structure
            assert failure_log is not None
            assert failure_log["type"] == "system"
            assert failure_log["level"] == "ERROR"
            assert failure_log["subsystem"] == "restore"
            assert failure_log["event"] == "restore_failed"
            assert "ts" in failure_log
            assert "error" in failure_log
            assert "duration_ms" in failure_log
            
        finally:
            # Clean up
            for f in [backup_file, manifest_file]:
                if os.path.exists(f):
                    os.remove(f)