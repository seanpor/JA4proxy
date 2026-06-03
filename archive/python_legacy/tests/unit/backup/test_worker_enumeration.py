"""
Test suite for deterministic key enumeration.
Tests ordering, dedup, exclude filters, and max key cap.
"""

from unittest.mock import MagicMock, patch

import pytest
from src.backup.worker import BackupWorker


def test_key_enumeration_ordering():
    """Test that keys are enumerated in stable order."""
    worker = BackupWorker()

    # Mock Redis SCAN to return keys in random order
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(
        side_effect=[
            (0, ["ban:192.168.1.3", "config:dial", "ban:192.168.1.1"]),
            (0, []),  # No more keys
        ]
    )

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis):
        keys = worker.enumerate_keys()
        # Should be sorted
        assert keys == sorted(keys)


def test_key_enumeration_dedup():
    """Test that duplicate keys are removed."""
    worker = BackupWorker()

    # Mock Redis SCAN to return duplicate keys
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(
        side_effect=[
            (0, ["ban:192.168.1.1", "ban:192.168.1.1", "config:dial"]),
            (0, []),  # No more keys
        ]
    )

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis):
        keys = worker.enumerate_keys()
        # Should have no duplicates
        assert len(keys) == len(set(keys))
        assert "ban:192.168.1.1" in keys
        assert "config:dial" in keys


def test_key_enumeration_exclude_filters():
    """Test that excluded keys are filtered out."""
    worker = BackupWorker()

    # Mock Redis SCAN to return mix of included and excluded keys
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(
        side_effect=[
            (0, ["config:dial", "session:ip:192.168.1.1:ja4:abc", "ban:192.168.1.1"]),
            (0, []),  # No more keys
        ]
    )

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis):
        keys = worker.enumerate_keys()
        # Should exclude session keys
        assert "config:dial" in keys
        assert "ban:192.168.1.1" in keys
        assert "session:ip:192.168.1.1:ja4:abc" not in keys


def test_key_enumeration_max_key_cap():
    """Test that max_keys_per_run is respected."""
    worker = BackupWorker(max_keys_per_run=2)

    # Mock Redis SCAN to return more keys than cap
    mock_redis = MagicMock()
    mock_redis.scan = MagicMock(
        side_effect=[
            (
                0,
                [
                    "ban:192.168.1.1",
                    "ban:192.168.1.2",
                    "ban:192.168.1.3",
                    "config:dial",
                ],
            ),
            (0, []),  # No more keys
        ]
    )

    with patch("src.backup.worker.redis.Redis", return_value=mock_redis):
        keys = worker.enumerate_keys()
        # Should be limited to max_keys_per_run
        assert len(keys) <= 2
