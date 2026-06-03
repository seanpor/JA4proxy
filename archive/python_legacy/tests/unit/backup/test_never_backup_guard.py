"""
Test suite for never-backup key guard functionality.
Tests that sensitive keys are never included in backups.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.backup.policy import KeyPolicy
from src.backup.worker import BackupWorker


def test_never_backup_patterns_defined():
    """Test that never-backup patterns are properly defined."""
    from src.backup.worker import _KEY_PATTERNS_NEVER_BACKUP

    # Verify the patterns exist and are non-empty
    assert _KEY_PATTERNS_NEVER_BACKUP is not None
    assert len(_KEY_PATTERNS_NEVER_BACKUP) > 0

    # Verify expected patterns are present
    expected_patterns = [
        "abuseipdb:*",  # Covers abuseipdb:api_key and other abuseipdb keys
        "config:redis_password",
        "*:auth_token",
    ]

    for pattern in expected_patterns:
        assert pattern in _KEY_PATTERNS_NEVER_BACKUP


def test_never_backup_keys_excluded_from_backup():
    """Test that keys matching never-backup patterns are excluded from backup."""
    worker = BackupWorker()

    # Mock Redis with sensitive keys
    mock_redis = MagicMock()
    sensitive_keys = [
        "abuseipdb:api_key",
        "config:redis_password",
        "service:auth_token",
    ]
    normal_keys = ["config:dial", "ban:192.168.1.1"]
    all_keys = sensitive_keys + normal_keys

    mock_redis.scan = MagicMock(
        side_effect=[
            (0, all_keys),
            (0, []),  # No more keys
        ]
    )
    # Configure pipeline mock so _dump_keys_batched returns test_data per key
    pipe_mock = mock_redis.pipeline.return_value
    pipe_mock.execute.side_effect = lambda raise_on_error=True: [
        b"test_data" for _ in pipe_mock.dump.call_args_list
    ]

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

        # Verify that dump was only called for normal keys, not sensitive ones
        # Dump calls go through the pipeline mock, not mock_redis directly
        dumped_keys = [call[0][0] for call in pipe_mock.dump.call_args_list]

        # Check that sensitive keys were not dumped
        for sensitive_key in sensitive_keys:
            assert (
                sensitive_key not in dumped_keys
            ), f"Sensitive key {sensitive_key} was backed up!"

        # Check that normal keys were dumped (only keys that pass policy AND never-backup filter)
        # abuseipdb:api_key is excluded by KeyPolicy (not in include patterns)
        # service:auth_token is excluded by KeyPolicy (not in include patterns)
        # config:redis_password passes KeyPolicy (config:* include) but excluded by _is_never_backup_key
        # config:dial and ban:192.168.1.1 should both be dumped
        for normal_key in normal_keys:
            assert (
                normal_key in dumped_keys
            ), f"Normal key {normal_key} was not backed up!"


def test_never_backup_warning_logged():
    """Test that a warning is logged when never-backup keys are detected."""
    import logging
    from unittest.mock import MagicMock, patch

    from src.backup.worker import BackupWorker
    from src.backup.worker import logger as worker_logger

    # Set up logging capture
    with patch("src.backup.worker.logger.warning") as mock_warning:
        worker = BackupWorker()

        # Mock Redis with sensitive keys that match include patterns.
        # Only config:redis_password is used here: abuseipdb:score:* was
        # intentionally removed from include_patterns (Bug 1 fix) so it never
        # reaches the never-backup guard and no warning is expected for it.
        mock_redis = MagicMock()
        sensitive_keys = ["config:redis_password"]
        normal_keys = ["config:dial", "ban:192.168.1.1"]
        all_keys = sensitive_keys + normal_keys

        mock_redis.scan = MagicMock(
            side_effect=[
                (0, all_keys),
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
        ):

            # Create backup
            worker.create_backup("/tmp/test_backups")

        # Verify that warnings were logged for sensitive keys
        assert mock_warning.called

        # Check the actual call arguments
        for call in mock_warning.call_args_list:
            log_message = call[0][0]  # First argument is the log message
            log_data = json.loads(log_message)
            assert log_data["event"] == "sensitive_key_detected"
            assert log_data["key"] in sensitive_keys

        # Verify that warnings were logged for each sensitive key
        sensitive_keys_found = []
        for call in mock_warning.call_args_list:
            log_message = call[0][0]
            log_data = json.loads(log_message)
            sensitive_keys_found.append(log_data["key"])

        for sensitive_key in sensitive_keys:
            assert (
                sensitive_key in sensitive_keys_found
            ), f"No warning logged for sensitive key {sensitive_key}"


def test_never_backup_patterns_configurable():
    """Test that never-backup patterns can be extended via configuration."""
    # This test verifies that the patterns are defined in a way that allows
    # future extension without breaking existing functionality
    from src.backup.worker import _KEY_PATTERNS_NEVER_BACKUP

    # Verify it's a list that can be extended
    assert isinstance(_KEY_PATTERNS_NEVER_BACKUP, list)

    # Verify we can add patterns (for future extensibility)
    original_length = len(_KEY_PATTERNS_NEVER_BACKUP)
    _KEY_PATTERNS_NEVER_BACKUP.append("test:new_pattern")
    assert len(_KEY_PATTERNS_NEVER_BACKUP) == original_length + 1

    # Clean up
    _KEY_PATTERNS_NEVER_BACKUP.pop()


def test_never_backup_with_custom_policy():
    """Test that never-backup guard works independently of key policies."""
    from src.backup.worker import BackupWorker

    worker = BackupWorker()

    # Mock Redis with sensitive keys that would normally match include patterns
    mock_redis = MagicMock()
    sensitive_keys = [
        "config:redis_password"
    ]  # Matches default include pattern but should be excluded
    normal_keys = ["config:dial", "ban:192.168.1.1"]
    all_keys = sensitive_keys + normal_keys

    mock_redis.scan = MagicMock(
        side_effect=[
            (0, all_keys),
            (0, []),  # No more keys
        ]
    )
    # Configure pipeline mock so _dump_keys_batched returns test_data per key
    pipe_mock = mock_redis.pipeline.return_value
    pipe_mock.execute.side_effect = lambda raise_on_error=True: [
        b"test_data" for _ in pipe_mock.dump.call_args_list
    ]

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
    ):

        # Create backup
        worker.create_backup("/tmp/test_backups")

        # Verify that sensitive keys were not dumped even though they match include patterns
        # Dump calls go through the pipeline mock, not mock_redis directly
        dumped_keys = [call[0][0] for call in pipe_mock.dump.call_args_list]
        assert "config:redis_password" not in dumped_keys
        assert "config:dial" in dumped_keys  # Normal key should be backed up
