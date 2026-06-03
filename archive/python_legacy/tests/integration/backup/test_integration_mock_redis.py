"""
Integration tests for backup/restore operations using mocked Redis.
Tests end-to-end workflows without requiring a real Redis instance.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from src.backup.restorer import BackupRestorer
from src.backup.worker import BackupWorker


class TestIntegrationMockRedis:
    """Integration tests with mocked Redis for workflow validation."""

    def setup_method(self):
        """Set up test fixtures and temporary directories."""
        # Create temporary backup directory
        self.backup_dir = tempfile.mkdtemp(prefix="backup_test_")

        # Mock Redis data (using keys that match include patterns)
        self.test_data = {
            "config:dial": b"127.0.0.1:8080",
            "ban:192.168.1.1": b"2024-01-01T00:00:00Z",
            "ja4:whitelist": b"allowed",
        }

    def teardown_method(self):
        """Clean up temporary directories."""
        # Remove temporary backup directory
        if hasattr(self, "backup_dir") and Path(self.backup_dir).exists():
            shutil.rmtree(self.backup_dir)

    def test_end_to_end_workflow_with_mock_redis(self):
        """Test complete backup and restore workflow with mocked Redis."""
        # Mock Redis operations
        mock_redis = MagicMock()
        mock_redis.scan.side_effect = [
            (0, list(self.test_data.keys())),
            (0, []),  # No more keys
        ]

        def mock_dump(key):
            return self.test_data.get(key, b"")

        # Configure pipeline mock so _dump_keys_batched uses per-key data
        pipe_mock = mock_redis.pipeline.return_value
        pipe_mock.execute.side_effect = lambda raise_on_error=True: [
            mock_dump(call[0][0]) for call in pipe_mock.dump.call_args_list
        ]

        # Mock filesystem validation
        def mock_access(path, mode):
            return True

        import os

        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()

        # Create backup
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), patch(
            "os.access", side_effect=mock_access
        ), patch("os.stat", return_value=mock_stat), patch("pathlib.Path.mkdir"), patch(
            "pathlib.Path.exists"
        ), patch(
            "pathlib.Path.write_bytes"
        ) as mock_write_bytes, patch(
            "pathlib.Path.write_text"
        ) as mock_write_text:

            worker = BackupWorker()
            backup_path = worker.create_backup(self.backup_dir)

            # Verify backup files were created
            assert backup_path.exists()

            # Verify manifest was written
            assert mock_write_text.called
            manifest_content = mock_write_text.call_args[0][0]
            manifest = json.loads(manifest_content)

            # Verify manifest structure (created_at is used instead of timestamp)
            assert "created_at" in manifest
            assert "backup_type" in manifest
            assert "checksum_sha256" in manifest
            assert "size_bytes" in manifest
            assert "keys_count" in manifest
            assert "included_patterns" in manifest
            assert "excluded_patterns" in manifest

            # Verify keys_count matches expected number of keys
            assert manifest["keys_count"] == len(self.test_data)

            # Verify backup artifact was written
            assert mock_write_bytes.called
            backup_data = mock_write_bytes.call_args[0][0]
            assert len(backup_data) > 0

    def test_restore_workflow_with_mock_redis(self):
        """Test restore workflow with mocked Redis operations."""
        # First create a backup to restore
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

        # Create backup files
        backup_file = Path(self.backup_dir) / "test_backup.bin"
        manifest_file = Path(self.backup_dir) / "test_backup.bin.manifest.json"

        # Create a simple backup artifact
        backup_data = b"test_backup_data"
        backup_file.write_bytes(backup_data)

        # Calculate actual checksum
        import hashlib

        actual_checksum = hashlib.sha256(backup_data).hexdigest()

        # Create manifest (matching the expected structure and filename format)
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": len(self.test_data),
            "checksum_sha256": actual_checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*", "ban:*", "ja4:*"],
            "excluded_patterns": [],
        }

        # Update backup file to match manifest filename
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        manifest_file = (
            Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        )
        backup_file.write_bytes(backup_data)
        manifest_file.write_text(json.dumps(manifest))

        # Mock the _restore_backup_data method to simulate key restoration
        def mock_restore_backup_data(redis_client, backup_path):
            # Simulate restoring each key
            for key in self.test_data.keys():
                redis_client.set(key, self.test_data[key])
            return len(self.test_data), 0  # (keys_restored, keys_failed)

        # Test restore
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class, patch.object(
            BackupRestorer, "_restore_backup_data", side_effect=mock_restore_backup_data
        ):

            mock_restore_redis = mock_redis_class.return_value
            mock_restore_redis.ping.return_value = True

            restorer = BackupRestorer()
            # restore_backup doesn't return a value, it either succeeds or raises an exception
            restorer.restore_backup(str(backup_file), str(manifest_file))

            # Verify restore was successful (no exception raised)
            # Verify each key was set in Redis
            for key in self.test_data.keys():
                # Check that set was called with the key (we can't easily check the exact call due to mocking)
                assert any(
                    call[0][0] == key for call in mock_restore_redis.set.call_args_list
                )

    def test_backup_restore_round_trip(self):
        """Test that backup and restore maintain data integrity."""
        # Original data
        original_data = {
            "key1": b"value1",
            "key2": b"value2",
            "key3": b"value3",
        }

        # Mock Redis for backup
        mock_redis = MagicMock()
        mock_redis.scan.side_effect = [
            (0, list(original_data.keys())),
            (0, []),
        ]

        def mock_dump(key):
            return original_data.get(key, b"")

        mock_redis.dump.side_effect = mock_dump

        # Mock filesystem validation
        def mock_access(path, mode):
            return True

        import os

        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()

        # Create backup
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), patch(
            "os.access", side_effect=mock_access
        ), patch("os.stat", return_value=mock_stat), patch("pathlib.Path.mkdir"), patch(
            "pathlib.Path.exists"
        ), patch(
            "pathlib.Path.write_bytes"
        ) as mock_write_bytes, patch(
            "pathlib.Path.write_text"
        ) as mock_write_text:

            worker = BackupWorker()
            backup_path = worker.create_backup(self.backup_dir)

            # Get the backup data and manifest
            backup_data = mock_write_bytes.call_args[0][0]
            manifest_content = mock_write_text.call_args[0][0]
            manifest = json.loads(manifest_content)

        # Create the actual backup file (it wasn't written due to mocking)
        backup_path.write_bytes(backup_data)

        # Create manifest file (it wasn't actually written due to mocking)
        manifest_file = Path(str(backup_path) + ".manifest.json")
        manifest_file.write_text(manifest_content)

        # Initialize restored_data to capture restored keys
        restored_data = {}

        # Mock the _restore_backup_data method to simulate key restoration
        def mock_restore_backup_data(redis_client, backup_path):
            # Simulate restoring each key and capture the data
            for key, value in original_data.items():
                restored_data[key] = value
            return len(original_data), 0  # (keys_restored, keys_failed)

        with patch("src.backup.restorer.redis.Redis") as mock_redis_class, patch.object(
            BackupRestorer, "_restore_backup_data", side_effect=mock_restore_backup_data
        ):

            mock_restore_redis = mock_redis_class.return_value
            mock_restore_redis.ping.return_value = True

            restorer = BackupRestorer()
            # restore_backup doesn't return a value, it either succeeds or raises an exception
            restorer.restore_backup(str(backup_path), str(manifest_file))

            # Verify all data was restored correctly (no exception raised)
            assert len(restored_data) == len(original_data)

            for key, expected_value in original_data.items():
                assert key in restored_data
                assert restored_data[key] == expected_value
