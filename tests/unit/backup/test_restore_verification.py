"""
Phase 57f — Post-restore verification tests.

Tests for:
- `backup:restored_from` key written after successful restore (JSON format)
- Key count divergence warning (>5% → WARNING logged; advisory only)
- `backup:restored_from` NOT written on restore failure
"""
import hashlib
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import redis as redis_lib

from src.backup.format import encode_entry
from src.backup.restorer import BackupRestorer, RestoreError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_backup(tmp_path: Path, n_keys: int = 5) -> tuple[Path, Path]:
    """Write a minimal valid backup artifact + manifest.

    Returns (backup_path, manifest_path).
    """
    entries = [(f"ban:{i}", b"data") for i in range(n_keys)]
    data = b"".join(encode_entry(k, v) for k, v in entries)
    checksum = hashlib.sha256(data).hexdigest()
    filename = "backup_20260101T000000Z.bin"
    bp = tmp_path / filename
    mp = tmp_path / f"{filename}.manifest.json"
    bp.write_bytes(data)
    mp.write_text(json.dumps({
        "filename": filename,
        "created_at": "2026-01-01T00:00:00Z",
        "backup_type": "full",
        "keys_count": n_keys,
        "checksum_sha256": checksum,
        "size_bytes": len(data),
        "included_patterns": ["*"],
        "excluded_patterns": [],
    }))
    return bp, mp


def _make_mock_redis(scan_key_count: int = 0) -> MagicMock:
    """Return a Redis MagicMock.

    - ping() returns True
    - restore() succeeds (no-op)
    - set/get/lpush/ltrim/delete/scan all succeed
    - scan() returns `scan_key_count` dummy keys in one page (cursor=0 at end)
    """
    mock = MagicMock()
    mock.ping.return_value = True
    mock.restore.return_value = None
    mock.set.return_value = True
    mock.get.return_value = None
    mock.lpush.return_value = 1
    mock.ltrim.return_value = True
    mock.delete.return_value = 1

    # Simulate SCAN returning `scan_key_count` keys in one page
    scan_keys = [f"k:{i}".encode() for i in range(scan_key_count)]
    mock.scan.return_value = (0, scan_keys)  # (cursor, keys)

    # Track what was stored via set()
    _stored: dict[str, bytes] = {}

    def _set(key, value, *args, **kwargs):
        _stored[key] = value if isinstance(value, bytes) else value.encode() if isinstance(value, str) else value
        return True

    def _get(key):
        return _stored.get(key)

    mock.set.side_effect = _set
    mock.get.side_effect = _get

    return mock


def _make_restorer() -> BackupRestorer:
    return BackupRestorer()


# ---------------------------------------------------------------------------
# Test: backup:restored_from key written after successful restore
# ---------------------------------------------------------------------------

class TestRestoredFromKeyWritten:
    """backup:restored_from is set on success."""

    def test_restored_from_key_written_after_restore(self, tmp_path):
        """After successful restore, redis_client.get('backup:restored_from') is set."""
        bp, mp = _make_backup(tmp_path)
        mock_redis = _make_mock_redis()

        restorer = _make_restorer()
        with patch("redis.Redis", return_value=mock_redis):
            restorer.restore_backup(str(bp), str(mp))

        raw = mock_redis.get("backup:restored_from")
        assert raw is not None, "backup:restored_from was not written"

    def test_restored_from_key_includes_timestamp(self, tmp_path):
        """backup:restored_from value is JSON with filename, restored_at, keys_count."""
        bp, mp = _make_backup(tmp_path, n_keys=7)
        mock_redis = _make_mock_redis()

        restorer = _make_restorer()
        with patch("redis.Redis", return_value=mock_redis):
            restorer.restore_backup(str(bp), str(mp))

        raw = mock_redis.get("backup:restored_from")
        assert raw is not None

        # raw may be bytes or str
        raw_str = raw.decode() if isinstance(raw, bytes) else raw
        record = json.loads(raw_str)

        assert "filename" in record, "JSON missing 'filename'"
        assert "restored_at" in record, "JSON missing 'restored_at'"
        assert "keys_count" in record, "JSON missing 'keys_count'"

        # filename should be the artifact filename
        assert record["filename"] == bp.name

        # restored_at should parse as ISO-8601
        from datetime import datetime
        ts = record["restored_at"].rstrip("Z").split("+")[0]
        datetime.fromisoformat(ts)  # raises ValueError if not valid ISO

        # keys_count should be a non-negative integer
        assert isinstance(record["keys_count"], int)
        assert record["keys_count"] >= 0


# ---------------------------------------------------------------------------
# Test: key count divergence warning
# ---------------------------------------------------------------------------

class TestKeyCountDivergence:
    """_verify_key_count emits WARNING on >5% divergence; never blocks restore."""

    def test_key_count_within_5pct_no_warning(self, tmp_path, caplog):
        """100 keys in manifest, 98 returned by SCAN → within 5% → no divergence WARNING."""
        bp, mp = _make_backup(tmp_path, n_keys=100)
        # 98 keys returned by scan (2% divergence — within tolerance)
        mock_redis = _make_mock_redis(scan_key_count=98)

        restorer = _make_restorer()
        with patch("redis.Redis", return_value=mock_redis):
            with caplog.at_level(logging.WARNING, logger="src.backup.restorer"):
                restorer.restore_backup(str(bp), str(mp))

        divergence_warnings = [
            r for r in caplog.records
            if "divergence" in r.getMessage().lower()
            and r.levelno >= logging.WARNING
        ]
        assert divergence_warnings == [], (
            f"Unexpected divergence warning(s): {[r.getMessage() for r in divergence_warnings]}"
        )

    def test_key_count_diverges_warning_logged(self, tmp_path, caplog):
        """100 keys in manifest, 80 returned by SCAN → 20% divergence → WARNING logged."""
        bp, mp = _make_backup(tmp_path, n_keys=100)
        mock_redis = _make_mock_redis(scan_key_count=80)

        restorer = _make_restorer()
        with patch("redis.Redis", return_value=mock_redis):
            with caplog.at_level(logging.WARNING, logger="src.backup.restorer"):
                restorer.restore_backup(str(bp), str(mp))

        divergence_warnings = [
            r for r in caplog.records
            if "divergence" in r.getMessage().lower()
            and r.levelno >= logging.WARNING
        ]
        assert len(divergence_warnings) >= 1, (
            "Expected at least one key-count-divergence WARNING but found none. "
            f"All warnings: {[r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]}"
        )

    def test_key_count_diverges_restore_still_succeeds(self, tmp_path):
        """Divergence is advisory — restore does NOT raise even with 80% of expected keys."""
        bp, mp = _make_backup(tmp_path, n_keys=100)
        mock_redis = _make_mock_redis(scan_key_count=80)

        restorer = _make_restorer()
        with patch("redis.Redis", return_value=mock_redis):
            # Must not raise
            restorer.restore_backup(str(bp), str(mp))


# ---------------------------------------------------------------------------
# Test: backup:restored_from NOT written on failure
# ---------------------------------------------------------------------------

class TestRestoredFromKeyNotWrittenOnFailure:
    """backup:restored_from must not be written when restore fails."""

    def test_restored_from_key_not_written_on_checksum_failure(self, tmp_path):
        """Checksum mismatch → RestoreError → backup:restored_from not written."""
        # Write valid entries, record correct checksum in manifest, then corrupt binary
        entries = [("ban:1", b"data")]
        data = b"".join(encode_entry(k, v) for k, v in entries)
        checksum = hashlib.sha256(data).hexdigest()
        filename = "backup_20260101T120000Z.bin"
        bp = tmp_path / filename
        mp = tmp_path / f"{filename}.manifest.json"
        bp.write_bytes(data)
        mp.write_text(json.dumps({
            "filename": filename,
            "created_at": "2026-01-01T12:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(data),
            "included_patterns": ["*"],
            "excluded_patterns": [],
        }))

        # Corrupt the binary so checksum fails
        bp.write_bytes(b"corrupted content that does not match")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError):
                restorer.restore_backup(str(bp), str(mp))

        # Checksum failure happens BEFORE Redis is touched, so `set` was never called
        # for restored_from. get() should return None.
        raw = mock_redis.get("backup:restored_from")
        assert raw is None, (
            "backup:restored_from must not be written when restore fails (checksum mismatch)"
        )
