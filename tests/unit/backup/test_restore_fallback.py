"""
Phase 57f — Fallback restore path tests.

Tests for BackupRestorer.restore_with_fallback():
- Primary succeeds → fallback never opened
- Primary checksum fails, fallback valid → restore succeeds via fallback
- Fallback used → WARNING logged
- All artifacts fail → RestoreError raised
- Empty fallback list + primary fails → RestoreError raised
- audit key records the actually-used artifact filename
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


def _write_valid_artifact(tmp_path: Path, suffix: str = "") -> tuple[Path, Path]:
    """Write a valid backup artifact + manifest. Returns (backup_path, manifest_path)."""
    entries = [("ban:0", b"v"), ("ban:1", b"v")]
    data = b"".join(encode_entry(k, v) for k, v in entries)
    checksum = hashlib.sha256(data).hexdigest()
    filename = f"backup_20260101T000000Z{suffix}.bin"
    bp = tmp_path / filename
    mp = tmp_path / f"{filename}.manifest.json"
    bp.write_bytes(data)
    mp.write_text(
        json.dumps(
            {
                "filename": filename,
                "created_at": "2026-01-01T00:00:00Z",
                "backup_type": "full",
                "keys_count": 2,
                "checksum_sha256": checksum,
                "size_bytes": len(data),
                "included_patterns": ["*"],
                "excluded_patterns": [],
            }
        )
    )
    return bp, mp


def _write_bad_artifact(tmp_path: Path, suffix: str = "_bad") -> tuple[Path, Path]:
    """Write an artifact whose checksum will not match the manifest."""
    filename = f"backup_20260101T000001Z{suffix}.bin"
    bp = tmp_path / filename
    mp = tmp_path / f"{filename}.manifest.json"
    bp.write_bytes(b"garbage data for a bad artifact")
    mp.write_text(
        json.dumps(
            {
                "filename": filename,
                "created_at": "2026-01-01T00:00:01Z",
                "backup_type": "full",
                "keys_count": 1,
                "checksum_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "size_bytes": 31,
                "included_patterns": ["*"],
                "excluded_patterns": [],
            }
        )
    )
    return bp, mp


def _make_mock_redis() -> MagicMock:
    """Return a Redis MagicMock that tracks set()/get() calls."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.restore.return_value = None

    _stored: dict[str, object] = {}

    def _set(key, value, *args, **kwargs):
        _stored[key] = value
        return True

    def _get(key):
        return _stored.get(key)

    mock.set.side_effect = _set
    mock.get.side_effect = _get
    mock.scan.return_value = (0, [])
    mock.lpush.return_value = 1
    mock.ltrim.return_value = True
    mock.delete.return_value = 1

    return mock


def _make_restorer() -> BackupRestorer:
    return BackupRestorer()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRestoreWithFallback:

    def test_fallback_not_tried_when_primary_succeeds(self, tmp_path):
        """Primary artifact valid → restore_with_fallback() succeeds; fallback never opened."""
        primary_bp, _ = _write_valid_artifact(tmp_path, suffix="_primary")
        fallback_bp, _ = _write_valid_artifact(tmp_path, suffix="_fallback")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        opened_paths: list[str] = []
        real_open = open

        def _tracking_open(path, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, *args, **kwargs)

        with patch("redis.Redis", return_value=mock_redis):
            with patch("builtins.open", side_effect=_tracking_open):
                result = restorer.restore_with_fallback(primary_bp, [fallback_bp])

        assert result == primary_bp
        # Fallback binary must never be read
        assert (
            str(fallback_bp) not in opened_paths
        ), "Fallback artifact file was opened when primary succeeded"

    def test_fallback_used_when_primary_checksum_fails(self, tmp_path):
        """Primary has bad checksum; fallback is valid → restore succeeds via fallback."""
        primary_bp, _ = _write_bad_artifact(tmp_path, suffix="_primary")
        fallback_bp, _ = _write_valid_artifact(tmp_path, suffix="_fallback")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            result = restorer.restore_with_fallback(primary_bp, [fallback_bp])

        assert result == fallback_bp

    def test_fallback_logged_when_used(self, tmp_path, caplog):
        """When fallback is used, a WARNING is logged naming the artifact used."""
        primary_bp, _ = _write_bad_artifact(tmp_path, suffix="_primary")
        fallback_bp, _ = _write_valid_artifact(tmp_path, suffix="_fallback")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            with caplog.at_level(logging.WARNING, logger="src.backup.restorer"):
                restorer.restore_with_fallback(primary_bp, [fallback_bp])

        fallback_warnings = [
            r
            for r in caplog.records
            if "fallback" in r.getMessage().lower() and r.levelno >= logging.WARNING
        ]
        assert len(fallback_warnings) >= 1, (
            "Expected WARNING about fallback being used, found none. "
            f"All log records: {[r.getMessage() for r in caplog.records]}"
        )
        # At least one warning should mention the fallback filename
        msgs = " ".join(r.getMessage() for r in fallback_warnings)
        assert (
            fallback_bp.name in msgs
        ), f"Fallback filename '{fallback_bp.name}' not mentioned in warnings: {msgs}"

    def test_all_fallbacks_fail_raises_restore_error(self, tmp_path):
        """Primary fails + all fallbacks fail → RestoreError raised."""
        primary_bp, _ = _write_bad_artifact(tmp_path, suffix="_primary")
        fallback1_bp, _ = _write_bad_artifact(tmp_path, suffix="_fallback1")
        fallback2_bp, _ = _write_bad_artifact(tmp_path, suffix="_fallback2")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError):
                restorer.restore_with_fallback(primary_bp, [fallback1_bp, fallback2_bp])

    def test_fallback_list_empty_primary_fails_raises(self, tmp_path):
        """restore_with_fallback(primary, fallbacks=[]) with bad primary → RestoreError."""
        primary_bp, _ = _write_bad_artifact(tmp_path, suffix="_primary")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError):
                restorer.restore_with_fallback(primary_bp, [])

    def test_audit_log_records_which_artifact_used(self, tmp_path):
        """backup:restored_from JSON contains the fallback filename when fallback was used."""
        primary_bp, _ = _write_bad_artifact(tmp_path, suffix="_primary")
        fallback_bp, _ = _write_valid_artifact(tmp_path, suffix="_fallback")

        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            result = restorer.restore_with_fallback(primary_bp, [fallback_bp])

        assert result == fallback_bp

        raw = mock_redis.get("backup:restored_from")
        assert raw is not None, "backup:restored_from was not written"

        raw_str = raw.decode() if isinstance(raw, bytes) else raw
        record = json.loads(raw_str)
        assert (
            record["filename"] == fallback_bp.name
        ), f"Expected filename '{fallback_bp.name}', got '{record.get('filename')}'"

    def test_restore_with_fallback_no_fallback_arg(self, tmp_path):
        """restore_with_fallback(primary) with no fallbacks → behaves as if fallbacks=[]."""
        primary_bp, _ = _write_valid_artifact(tmp_path, suffix="_primary")
        mock_redis = _make_mock_redis()
        restorer = _make_restorer()

        with patch("redis.Redis", return_value=mock_redis):
            result = restorer.restore_with_fallback(primary_bp)

        assert result == primary_bp
