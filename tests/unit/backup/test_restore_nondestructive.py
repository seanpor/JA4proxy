"""
Test suite for non-destructive restore.
Tests that pre-existing keys remain after restore.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.backup.restorer import BackupRestorer, RestoreError


def test_nondestructive_restore_preserves_existing_keys():
    """Test that non-destructive restore preserves existing Redis keys."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data for non-destructive restore"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T140000Z_nondestructive.bin"
    manifest_file = "/tmp/backup_20260321T140000Z_nondestructive.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T140000Z_nondestructive.bin",
            "created_at": "2026-03-21T14:00:00Z",
            "backup_type": "full",
            "keys_count": 5,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": ["session:*"],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis to simulate existing data
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True

        # Add some existing keys
        mock_redis.keys.return_value = [
            b"existing_key",
            b"config:dial",
            b"ban:192.168.1.1",
        ]
        mock_redis.get.side_effect = lambda key: (
            b"existing_value" if key == b"existing_key" else None
        )

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Perform non-destructive restore
            restorer.restore_backup(backup_file, manifest_file, destructive=False)

            # Verify that existing key was not deleted
            # The restore should set control keys but not wipe existing data
            assert mock_redis.set.called

            # Check that the restore markers were set
            set_calls = [call[0][0] for call in mock_redis.set.call_args_list]
            assert "backup:last_restore" in set_calls
            assert "backup:restored_from" in set_calls

            # Verify that existing user data was not wiped
            assert not mock_redis.flushdb.called
            # Only the distributed lock key should have been deleted (lock release)
            delete_calls = [call[0][0] for call in mock_redis.delete.call_args_list]
            assert all(
                "operation_lock" in k for k in delete_calls
            ), f"Unexpected delete calls: {delete_calls}"

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_nondestructive_restore_with_missing_manifest():
    """Test that restore fails gracefully when manifest is missing."""
    restorer = BackupRestorer()

    backup_file = "/tmp/backup_20260321T140000Z_missing_manifest.bin"
    manifest_file = "/tmp/backup_20260321T140000Z_missing_manifest.bin.manifest.json"

    try:
        # Create backup file but no manifest
        with open(backup_file, "wb") as f:
            f.write(b"test data")

        # Should fail during manifest loading
        with pytest.raises(RestoreError) as exc_info:
            restorer.restore_backup(backup_file, manifest_file, destructive=False)
        assert "Failed to load manifest" in str(exc_info.value)

    finally:
        # Clean up
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_nondestructive_restore_with_invalid_redis():
    """Test that restore fails gracefully when Redis is unavailable."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T140000Z_invalid_redis.bin"
    manifest_file = "/tmp/backup_20260321T140000Z_invalid_redis.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T140000Z_invalid_redis.bin",
            "created_at": "2026-03-21T14:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis to be unavailable
        mock_redis = MagicMock()
        mock_redis.ping.return_value = False

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Should fail during Redis connection check
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(backup_file, manifest_file, destructive=False)
            assert "Redis connection failed" in str(exc_info.value)

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)
