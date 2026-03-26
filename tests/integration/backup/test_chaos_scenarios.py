"""
Chaos tests for backup/restore operations.
Tests resilience to Redis timeouts, network issues, disk failures, and corrupted artifacts.
"""
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.backup.restorer import BackupRestorer, RestoreError
from src.backup.worker import BackupWorker


class TestChaosScenarios:
    """Chaos tests for backup/restore resilience."""
    
    def setup_method(self):
        """Set up test fixtures and temporary directories."""
        self.backup_dir = tempfile.mkdtemp(prefix="backup_chaos_test_")
        
        # Test data
        self.test_data = {
            "config:dial": b"127.0.0.1:8080",
            "ban:192.168.1.1": b"2024-01-01T00:00:00Z",
            "ja4:whitelist": b"allowed",
        }
    
    def teardown_method(self):
        """Clean up temporary directories."""
        if hasattr(self, 'backup_dir') and Path(self.backup_dir).exists():
            shutil.rmtree(self.backup_dir)
    
    def test_redis_timeout_during_backup(self):
        """Test backup resilience to Redis timeout during key enumeration."""
        # Mock the enumerate_keys method to simulate Redis timeout
        def mock_enumerate_keys():
            # Simulate partial enumeration followed by timeout
            raise Exception("Redis timeout: connection lost")
        
        # Mock filesystem validation
        def mock_access(path, mode):
            return True
        
        import os
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()
        
        # Test that backup fails gracefully with proper error handling
        with patch.object(BackupWorker, 'enumerate_keys', side_effect=mock_enumerate_keys), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"):
            
            worker = BackupWorker()
            
            # Backup should fail with Redis timeout
            with pytest.raises(Exception) as exc_info:
                worker.create_backup(self.backup_dir)
            
            # Verify it's a Redis-related error
            assert "Redis timeout" in str(exc_info.value) or "connection" in str(exc_info.value).lower()
    
    def test_network_interruption_during_backup(self):
        """Test backup resilience to network interruption during enumeration.

        With pipeline batching, individual key-dump failures are absorbed (the key
        is skipped rather than aborting the whole backup). A failure during
        *enumeration* (scan) does abort the backup, which is the behaviour tested here.
        """
        mock_redis = MagicMock()
        # Simulate network failure during SCAN enumeration
        mock_redis.scan.side_effect = Exception("Network interruption: connection reset by peer")

        # Mock filesystem validation
        def mock_access(path, mode):
            return True

        import os
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()

        # Backup should fail when enumeration fails
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists"), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):

            worker = BackupWorker()

            with pytest.raises(Exception) as exc_info:
                worker.create_backup(self.backup_dir)

            # Verify it's a network-related error
            assert "network" in str(exc_info.value).lower() or "connection" in str(exc_info.value).lower()
    
    def test_disk_full_during_backup(self):
        """Test backup resilience to disk full conditions."""
        # Mock Redis operations
        mock_redis = MagicMock()
        mock_redis.scan.side_effect = [
            (0, list(self.test_data.keys())),
            (0, []),
        ]
        
        def mock_dump(key):
            return self.test_data.get(key, b"")
        
        mock_redis.dump.side_effect = mock_dump
        
        # Mock filesystem validation
        def mock_access(path, mode):
            return True
        
        import os
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()
        
        # Mock disk full condition during file write
        def mock_write_bytes(data):
            raise OSError("[Errno 28] No space left on device")
        
        # Test that backup fails gracefully with disk full error
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists"), \
             patch("pathlib.Path.write_bytes", side_effect=mock_write_bytes), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            
            # Backup should fail with disk full error
            with pytest.raises(Exception) as exc_info:
                worker.create_backup(self.backup_dir)
            
            # Verify it's a disk space error
            assert "space" in str(exc_info.value).lower() or "disk" in str(exc_info.value).lower()
    
    def test_corrupted_backup_artifact(self):
        """Test restore resilience to corrupted backup artifacts."""
        # Create a corrupted backup file with proper filename format
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        corrupted_data = b"This is not a valid Redis dump file"
        backup_file.write_bytes(corrupted_data)
        
        # Create a valid manifest with proper filename
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 3,
            "checksum_sha256": "invalid_checksum_for_corrupted_data",
            "size_bytes": len(corrupted_data),
            "included_patterns": ["config:*", "ban:*", "ja4:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test that restore detects the corruption
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # Restore should fail due to checksum mismatch
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a checksum verification error
            assert "checksum" in str(exc_info.value).lower() or "verification" in str(exc_info.value).lower()
    
    def test_partial_backup_file_corruption(self):
        """Test restore resilience to partially corrupted backup files."""
        # Create a backup file that's partially valid
        backup_file = Path(self.backup_dir) / "partial_backup.bin"
        
        # Create data that starts valid but gets corrupted
        valid_data = b"\x00\x05config\x00\x0b127.0.0.1:8080"  # Valid Redis dump format
        corrupted_data = valid_data + b"CORRUPTED_DATA_HERE"
        backup_file.write_bytes(corrupted_data)
        
        # Create manifest
        import hashlib
        actual_checksum = hashlib.sha256(corrupted_data).hexdigest()
        
        manifest = {
            "filename": "partial_backup.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": actual_checksum,  # Match the actual corrupted data
            "size_bytes": len(corrupted_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "partial_backup.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test restore with corrupted data
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            # Mock restore to fail on corrupted data
            def mock_restore(key, ttl, value, replace=False):
                if b"CORRUPTED" in value:
                    raise Exception("Invalid Redis dump format")
                return True
            
            mock_redis.execute_command.side_effect = mock_restore
            
            restorer = BackupRestorer()
            
            # Restore should fail due to corrupted data format
            with pytest.raises(Exception) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a data format error
            assert "format" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()
    
    def test_redis_unavailable_during_restore(self):
        """Test restore resilience to Redis being unavailable."""
        # Create valid backup files with proper filename format
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_backup_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test restore with unavailable Redis
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = False  # Redis unavailable
            
            restorer = BackupRestorer()
            
            # Restore should fail due to Redis unavailability
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a Redis connection error
            assert "connection" in str(exc_info.value).lower() or "unavailable" in str(exc_info.value).lower()
    
    def test_network_latency_during_backup(self):
        """Test backup resilience to high network latency."""
        import time
        
        # Mock Redis with slow responses
        mock_redis = MagicMock()
        
        def slow_scan(cursor, match="*", count=None):
            time.sleep(0.1)  # Simulate network latency
            if cursor == 0:
                return (0, list(self.test_data.keys()))  # Return all keys
            else:
                return (0, [])  # No more keys
        
        def slow_dump(key):
            time.sleep(0.1)  # Simulate network latency
            return self.test_data.get(key, b"")

        mock_redis.scan.side_effect = slow_scan
        # Configure pipeline mock: execute simulates per-key latency and returns data
        pipe_mock = mock_redis.pipeline.return_value
        pipe_mock.execute.side_effect = lambda raise_on_error=True: [
            slow_dump(call[0][0]) for call in pipe_mock.dump.call_args_list
        ]
        
        # Mock filesystem validation
        def mock_access(path, mode):
            return True
        
        import os
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()
        
        # Test that backup completes despite latency
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists"), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            
            # Backup should complete successfully despite latency
            with patch("pathlib.Path.write_bytes") as mock_write_bytes, \
                 patch("pathlib.Path.write_text") as mock_write_text:
                
                backup_path = worker.create_backup(self.backup_dir)
                
                # Verify backup was created (mocked)
                assert mock_write_bytes.called
                assert mock_write_text.called
                
                # Verify backup data was written
                backup_data = mock_write_bytes.call_args[0][0]
                assert len(backup_data) > 0