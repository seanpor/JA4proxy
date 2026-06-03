"""
Test suite for destructive restore.
Tests that destructive flag is required for wipe operations.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from src.backup.restorer import BackupRestorer, RestoreError


def test_destructive_restore_wipes_data():
    """Test that destructive restore wipes existing Redis data."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data for destructive restore"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T150000Z_destructive.bin"
    manifest_file = "/tmp/backup_20260321T150000Z_destructive.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T150000Z_destructive.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 10,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": ["config:*", "ban:*"],
            "excluded_patterns": ["session:*", "lifespan:*"],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Perform destructive restore
            restorer.restore_backup(backup_file, manifest_file, destructive=True)

            # Verify that FLUSHDB was called to wipe data
            assert mock_redis.flushdb.called

            # Verify that restore markers were set
            set_calls = [call[0][0] for call in mock_redis.set.call_args_list]
            assert "backup:last_restore" in set_calls
            assert "backup:restored_from" in set_calls

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_non_destructive_restore_does_not_wipe():
    """Test that non-destructive restore never wipes data even if destructive=True is not set."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data for non-destructive test"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T150000Z_non_destructive_test.bin"
    manifest_file = (
        "/tmp/backup_20260321T150000Z_non_destructive_test.bin.manifest.json"
    )

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T150000Z_non_destructive_test.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 5,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Perform non-destructive restore (default)
            restorer.restore_backup(backup_file, manifest_file, destructive=False)

            # Verify that FLUSHDB was NOT called
            assert not mock_redis.flushdb.called

            # Verify that restore markers were still set
            assert mock_redis.set.called

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_destructive_restore_requires_explicit_flag():
    """Test that wipe never happens without explicit destructive flag."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data for explicit flag test"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T150000Z_explicit_flag.bin"
    manifest_file = "/tmp/backup_20260321T150000Z_explicit_flag.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T150000Z_explicit_flag.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Perform restore with destructive=False (default)
            restorer.restore_backup(backup_file, manifest_file)

            # Verify that FLUSHDB was NOT called (no explicit destructive flag)
            assert not mock_redis.flushdb.called

            # Verify that restore still completed
            assert mock_redis.set.called

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_destructive_restore_with_redis_error():
    """Test that destructive restore handles Redis errors gracefully."""
    restorer = BackupRestorer()

    # Create test backup and manifest
    test_data = b"backup data for error handling"
    expected_checksum = hashlib.sha256(test_data).hexdigest()

    backup_file = "/tmp/backup_20260321T150000Z_error_handling.bin"
    manifest_file = "/tmp/backup_20260321T150000Z_error_handling.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        manifest = {
            "filename": "backup_20260321T150000Z_error_handling.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis to fail during flushdb
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.flushdb.side_effect = Exception("Redis flush failed")

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Should raise RestoreError
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(backup_file, manifest_file, destructive=True)
            assert "Restore failed" in str(exc_info.value)

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)
