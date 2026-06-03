"""
Test suite for backup and restore metrics.
Tests that Prometheus metrics are properly updated during operations.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.backup.restorer import (
    RESTORE_CURRENTLY_RUNNING,
    RESTORE_DURATION_SECONDS,
    RESTORE_KEYS_RESTORED_TOTAL,
    RESTORE_LAST_FAILURE_TIMESTAMP,
    RESTORE_LAST_SUCCESS_TIMESTAMP,
    RESTORE_OPERATIONS_TOTAL,
    BackupRestorer,
)
from src.backup.worker import (
    BACKUP_CURRENTLY_RUNNING,
    BACKUP_DURATION_SECONDS,
    BACKUP_KEYS_PROCESSED_TOTAL,
    BACKUP_LAST_FAILURE_TIMESTAMP,
    BACKUP_LAST_SUCCESS_TIMESTAMP,
    BACKUP_OPERATIONS_TOTAL,
    BACKUP_SIZE_BYTES,
    BackupWorker,
)


def test_backup_metrics_success():
    """Test that backup metrics are updated on success."""
    # Reset metrics
    BACKUP_OPERATIONS_TOTAL._metrics.clear()
    BACKUP_KEYS_PROCESSED_TOTAL._value.set(0)
    BACKUP_LAST_SUCCESS_TIMESTAMP._value.set(0)
    BACKUP_LAST_FAILURE_TIMESTAMP._value.set(0)
    BACKUP_CURRENTLY_RUNNING._value.set(0)

    worker = BackupWorker()

    # Mock Redis and file operations
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(
        side_effect=[
            (0, ["config:dial", "ban:192.168.1.1"]),
            (0, []),  # No more keys
        ]
    )
    mock_redis.dump = MagicMock(return_value=b"test_data")

    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted

    import os

    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), patch(
        "os.access", side_effect=mock_access
    ), patch("os.stat", return_value=mock_stat), patch("pathlib.Path.mkdir"), patch(
        "pathlib.Path.exists"
    ), patch(
        "pathlib.Path.write_bytes"
    ), patch(
        "pathlib.Path.write_text"
    ) as mock_write_text:

        # Create backup
        backup_path = worker.create_backup("/tmp/test_backups")

        # Verify metrics were updated
        started_counter = BACKUP_OPERATIONS_TOTAL._metrics.get(("started",))
        success_counter = BACKUP_OPERATIONS_TOTAL._metrics.get(("success",))
        started_ops = started_counter._value.get() if started_counter else 0
        success_ops = success_counter._value.get() if success_counter else 0
        keys_processed = BACKUP_KEYS_PROCESSED_TOTAL._value.get()
        last_success = BACKUP_LAST_SUCCESS_TIMESTAMP._value.get()
        currently_running = BACKUP_CURRENTLY_RUNNING._value.get()

        assert started_ops == 1
        assert success_ops == 1
        assert keys_processed == 2
        assert last_success > 0
        assert currently_running == 0


def test_backup_metrics_failure():
    """Test that backup metrics are updated on failure."""
    # Reset metrics
    BACKUP_OPERATIONS_TOTAL._metrics.clear()
    BACKUP_KEYS_PROCESSED_TOTAL._value.set(0)
    BACKUP_LAST_SUCCESS_TIMESTAMP._value.set(0)
    BACKUP_LAST_FAILURE_TIMESTAMP._value.set(0)
    BACKUP_CURRENTLY_RUNNING._value.set(0)

    worker = BackupWorker()

    # Mock Redis to fail
    mock_redis = MagicMock()
    mock_redis.scan.side_effect = Exception("Redis error")

    # Mock filesystem validation
    def mock_access(path, mode):
        return True  # All permissions granted

    import os

    mock_stat = MagicMock()
    mock_stat.st_mode = 0o700  # Secure permissions (owner only)
    mock_stat.st_uid = os.getuid()  # Current user
    mock_stat.st_gid = os.getgid()  # Current group

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), patch(
        "os.access", side_effect=mock_access
    ), patch("os.stat", return_value=mock_stat), patch("pathlib.Path.mkdir"), patch(
        "pathlib.Path.exists"
    ), patch(
        "pathlib.Path.write_bytes"
    ), patch(
        "pathlib.Path.write_text"
    ) as mock_write_text:

        # Try to create backup (should fail)
        with pytest.raises(Exception):
            worker.create_backup("/tmp/test_backups")

        # Verify metrics were updated
        started_counter = BACKUP_OPERATIONS_TOTAL._metrics.get(("started",))
        failure_counter = BACKUP_OPERATIONS_TOTAL._metrics.get(("failure",))
        started_ops = started_counter._value.get() if started_counter else 0
        failure_ops = failure_counter._value.get() if failure_counter else 0
        last_failure = BACKUP_LAST_FAILURE_TIMESTAMP._value.get()
        currently_running = BACKUP_CURRENTLY_RUNNING._value.get()

        assert started_ops == 1
        assert failure_ops == 1
        assert last_failure > 0
        assert currently_running == 0


def test_restore_metrics_success():
    """Test that restore metrics are updated on success."""
    # Reset metrics
    RESTORE_OPERATIONS_TOTAL._metrics.clear()
    RESTORE_KEYS_RESTORED_TOTAL._value.set(0)
    RESTORE_LAST_SUCCESS_TIMESTAMP._value.set(0)
    RESTORE_LAST_FAILURE_TIMESTAMP._value.set(0)
    RESTORE_CURRENTLY_RUNNING._value.set(0)

    restorer = BackupRestorer()

    # Create test backup and manifest files using the real encoding format so
    # that _restore_backup_data can decode at least one entry and increment
    # RESTORE_KEYS_RESTORED_TOTAL above zero.
    from src.backup.format import encode_entry

    test_data = encode_entry("ban:10.0.0.1", b"fake_dump_data_for_metrics_test")
    backup_file = "/tmp/test_restore_metrics_backup.bin"
    manifest_file = "/tmp/test_restore_metrics_backup.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "backup_20260321T150000Z.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
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
            # Perform restore
            restorer.restore_backup(backup_file, manifest_file, destructive=False)

            # Verify metrics were updated
            started_counter = RESTORE_OPERATIONS_TOTAL._metrics.get(
                ("started", "non-destructive")
            )
            success_counter = RESTORE_OPERATIONS_TOTAL._metrics.get(
                ("success", "non-destructive")
            )
            started_ops = started_counter._value.get() if started_counter else 0
            success_ops = success_counter._value.get() if success_counter else 0
            keys_restored = RESTORE_KEYS_RESTORED_TOTAL._value.get()
            last_success = RESTORE_LAST_SUCCESS_TIMESTAMP._value.get()
            currently_running = RESTORE_CURRENTLY_RUNNING._value.get()

            assert started_ops == 1
            assert success_ops == 1
            assert keys_restored > 0
            assert last_success > 0
            assert currently_running == 0

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_restore_metrics_failure():
    """Test that restore metrics are updated on failure."""
    # Reset metrics
    RESTORE_OPERATIONS_TOTAL._metrics.clear()
    RESTORE_KEYS_RESTORED_TOTAL._value.set(0)
    RESTORE_LAST_SUCCESS_TIMESTAMP._value.set(0)
    RESTORE_LAST_FAILURE_TIMESTAMP._value.set(0)
    RESTORE_CURRENTLY_RUNNING._value.set(0)

    restorer = BackupRestorer()

    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_failure_metrics_backup.bin"
    manifest_file = "/tmp/test_restore_failure_metrics_backup.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "backup_20260321T150000Z.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis to fail
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.flushdb.side_effect = Exception("Redis flush failed")

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Try to perform destructive restore (should fail)
            with pytest.raises(Exception):
                restorer.restore_backup(backup_file, manifest_file, destructive=True)

            # Verify metrics were updated
            started_counter = RESTORE_OPERATIONS_TOTAL._metrics.get(
                ("started", "destructive")
            )
            failure_counter = RESTORE_OPERATIONS_TOTAL._metrics.get(
                ("failure", "destructive")
            )
            started_ops = started_counter._value.get() if started_counter else 0
            failure_ops = failure_counter._value.get() if failure_counter else 0
            last_failure = RESTORE_LAST_FAILURE_TIMESTAMP._value.get()
            currently_running = RESTORE_CURRENTLY_RUNNING._value.get()

            assert started_ops == 1
            assert failure_ops == 1
            assert last_failure > 0
            assert currently_running == 0

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_metrics_currently_running():
    """Test that currently_running metrics are properly managed."""
    # Reset metrics
    BACKUP_CURRENTLY_RUNNING._value.set(0)
    RESTORE_CURRENTLY_RUNNING._value.set(0)

    # Test backup currently_running
    worker = BackupWorker()

    # Mock Redis to fail after setting currently_running
    mock_redis = MagicMock()
    mock_redis.scan.side_effect = Exception("Redis error")

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis), patch(
        "pathlib.Path.mkdir"
    ), patch("pathlib.Path.exists"), patch("pathlib.Path.write_bytes"), patch(
        "pathlib.Path.write_text"
    ) as mock_write_text:

        # Start backup (should set currently_running to 1)
        try:
            worker.create_backup("/tmp/test_backups")
        except Exception:
            pass

        # currently_running should be 0 after failure
        assert BACKUP_CURRENTLY_RUNNING._value.get() == 0.0

    # Test restore currently_running
    restorer = BackupRestorer()

    # Create test backup and manifest files
    test_data = b"test backup data"
    backup_file = "/tmp/test_restore_running_backup.bin"
    manifest_file = "/tmp/test_restore_running_backup.bin.manifest.json"

    try:
        # Create backup file
        with open(backup_file, "wb") as f:
            f.write(test_data)

        # Create manifest
        checksum = hashlib.sha256(test_data).hexdigest()
        manifest = {
            "filename": "test_restore_running_backup.bin",
            "created_at": "2026-03-21T15:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": [],
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        # Mock Redis to fail
        mock_redis = MagicMock()
        mock_redis.ping.return_value = False

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Try to restore (should fail and set currently_running to 0)
            try:
                restorer.restore_backup(backup_file, manifest_file, destructive=False)
            except Exception:
                pass

            # currently_running should be 0 after failure
            assert RESTORE_CURRENTLY_RUNNING._value.get() == 0.0

    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)
