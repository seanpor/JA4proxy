"""
Test suite for retention policies.
Tests count-based, age-based, and combined retention.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.backup.worker import BackupWorker


def test_count_based_retention():
    """Test that only most recent N artifacts are kept."""
    # Create a temporary backup directory
    backup_dir = "/tmp/test_backups_retention"
    os.makedirs(backup_dir, exist_ok=True)

    worker = BackupWorker()

    # Create some test backup files
    now = datetime.utcnow()
    for i in range(5):
        timestamp = (now - timedelta(hours=i)).strftime("%Y%m%dT%H%M%SZ")
        backup_file = Path(backup_dir) / f"backup_{timestamp}.bin"
        manifest_file = Path(backup_dir) / f"backup_{timestamp}.bin.manifest.json"

        # Create backup file
        backup_file.write_bytes(b"test_data")

        # Create manifest
        manifest = {
            "filename": f"backup_{timestamp}.bin",
            "created_at": (now - timedelta(hours=i)).isoformat() + "Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": "test_checksum",
            "size_bytes": 10,
            "included_patterns": [],
            "excluded_patterns": [],
        }
        manifest_file.write_text(json.dumps(manifest, indent=2))

    # Apply count-based retention (keep only 3)
    worker.apply_retention(backup_dir, retain_count=3, retention_days=None)

    # Check that only 3 backup files remain
    remaining_backups = list(Path(backup_dir).glob("backup_*.bin"))
    assert len(remaining_backups) == 3

    # Check that manifests were also cleaned up
    remaining_manifests = list(Path(backup_dir).glob("backup_*.bin.manifest.json"))
    assert len(remaining_manifests) == 3

    # Clean up
    for f in Path(backup_dir).glob("*"):
        f.unlink()
    os.rmdir(backup_dir)


def test_age_based_retention():
    """Test that artifacts older than retention_days are deleted."""
    # Create a temporary backup directory
    backup_dir = "/tmp/test_backups_age"
    # Clean up any existing files
    if os.path.exists(backup_dir):
        for f in Path(backup_dir).glob("*"):
            f.unlink()
    else:
        os.makedirs(backup_dir, exist_ok=True)

    worker = BackupWorker()

    # Create some test backup files with different ages
    now = datetime.utcnow()
    for i in range(5):
        # Create unique timestamps by adding seconds to avoid collisions
        timestamp = (now - timedelta(days=i, seconds=i * 10)).strftime("%Y%m%dT%H%M%SZ")
        backup_file = Path(backup_dir) / f"backup_{timestamp}.bin"
        manifest_file = Path(backup_dir) / f"backup_{timestamp}.bin.manifest.json"

        # Create backup file
        backup_file.write_bytes(b"test_data")

        # Create manifest with the correct timestamp
        created_at = (now - timedelta(days=i, seconds=i * 10)).isoformat() + "Z"
        manifest = {
            "filename": f"backup_{timestamp}.bin",
            "created_at": created_at,
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": "test_checksum",
            "size_bytes": 10,
            "included_patterns": [],
            "excluded_patterns": [],
        }
        manifest_file.write_text(json.dumps(manifest, indent=2))

    # Apply age-based retention (keep only 2 days)
    worker.apply_retention(backup_dir, retain_count=None, retention_days=2)

    # Check that only recent backups remain
    remaining_backups = list(Path(backup_dir).glob("backup_*.bin"))

    # Should keep backups from today and yesterday (2 days total)
    # The test creates 5 backups with dates from today back 4 days
    # So we should have 2 remaining (today and yesterday)
    assert len(remaining_backups) == 2  # Today and yesterday

    # Check that manifests were also cleaned up
    remaining_manifests = list(Path(backup_dir).glob("backup_*.bin.manifest.json"))
    assert len(remaining_manifests) == 2

    # Clean up
    for f in Path(backup_dir).glob("*"):
        f.unlink()
    os.rmdir(backup_dir)


def test_combined_retention_policy():
    """Test that both count and age rules apply deterministically."""
    # Create a temporary backup directory
    backup_dir = "/tmp/test_backups_combined"
    os.makedirs(backup_dir, exist_ok=True)

    worker = BackupWorker()

    # Create some test backup files
    now = datetime.utcnow()
    for i in range(10):
        timestamp = (now - timedelta(days=i)).strftime("%Y%m%dT%H%M%SZ")
        backup_file = Path(backup_dir) / f"backup_{timestamp}.bin"
        manifest_file = Path(backup_dir) / f"backup_{timestamp}.bin.manifest.json"

        # Create backup file
        backup_file.write_bytes(b"test_data")

        # Create manifest
        manifest = {
            "filename": f"backup_{timestamp}.bin",
            "created_at": (now - timedelta(days=i)).isoformat() + "Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": "test_checksum",
            "size_bytes": 10,
            "included_patterns": [],
            "excluded_patterns": [],
        }
        manifest_file.write_text(json.dumps(manifest, indent=2))

    # Apply combined retention (keep max 5, but only if younger than 7 days)
    worker.apply_retention(backup_dir, retain_count=5, retention_days=7)

    # Check that the right number of backups remain
    remaining_backups = list(Path(backup_dir).glob("backup_*.bin"))
    # Should have min(5, 7) = 5 most recent backups that are < 7 days old
    assert len(remaining_backups) == 5

    # Check that manifests were also cleaned up
    remaining_manifests = list(Path(backup_dir).glob("backup_*.bin.manifest.json"))
    assert len(remaining_manifests) == 5

    # Clean up
    for f in Path(backup_dir).glob("*"):
        f.unlink()
    os.rmdir(backup_dir)


# ---------------------------------------------------------------------------
# Coverage gap additions — lines 483, 489, 515-517, 520, 548-549, 555-556
# ---------------------------------------------------------------------------

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch


class TestRetentionCoverageGaps:
    """Missing branches in apply_retention: nonexistent dir, empty dir,
    invalid manifests, and OSError on unlink."""

    def test_apply_retention_nonexistent_dir_returns_early(self):
        """Line 483: backup_dir does not exist → returns immediately without error.
        So what: without this guard, Path.glob() would raise FileNotFoundError,
        crashing the backup scheduler cron and leaving retention unenforced."""
        worker = BackupWorker()
        worker.apply_retention("/nonexistent/backup/dir/xyz", retain_count=3)

    def test_apply_retention_empty_dir_returns_early(self):
        """Line 489: dir exists but contains no backup_*.bin files → returns early.
        So what: without this guard, the code proceeds through an empty loop cleanly,
        but this short-circuit avoids unnecessary manifest-parsing I/O."""
        tmpdir = tempfile.mkdtemp()
        try:
            (Path(tmpdir) / "not_a_backup.txt").write_text("nope")
            BackupWorker().apply_retention(tmpdir, retain_count=3)
            assert Path(tmpdir).exists()
        finally:
            shutil.rmtree(tmpdir)

    def test_apply_retention_invalid_manifest_json_skipped(self):
        """Lines 515-517: manifest with invalid JSON → KeyError/JSONDecodeError → skipped.
        So what: without this except, a single corrupted manifest file would crash
        apply_retention for the entire backup directory, leaving stale backups forever.
        """
        tmpdir = tempfile.mkdtemp()
        try:
            bp = Path(tmpdir) / "backup_20260101T000000Z.bin"
            mp = Path(tmpdir) / "backup_20260101T000000Z.bin.manifest.json"
            bp.write_bytes(b"data")
            mp.write_text("{ invalid json !!!")
            BackupWorker().apply_retention(tmpdir, retain_count=3)
        finally:
            shutil.rmtree(tmpdir)

    def test_apply_retention_all_manifests_invalid_returns_early(self):
        """Line 520: all manifests were invalid → backups=[] → early return before deletion.
        So what: without this guard, the code would proceed to compute set differences
        on empty sets — harmless but this short-circuits cleanly."""
        tmpdir = tempfile.mkdtemp()
        try:
            bp = Path(tmpdir) / "backup_20260101T000000Z.bin"
            mp = Path(tmpdir) / "backup_20260101T000000Z.bin.manifest.json"
            bp.write_bytes(b"data")
            mp.write_text('{"missing": "required_fields"}')  # no created_at → KeyError
            BackupWorker().apply_retention(tmpdir, retain_count=1)
            assert bp.exists()  # file untouched (returned early)
        finally:
            shutil.rmtree(tmpdir)

    def test_apply_retention_oserror_on_unlink_is_suppressed(self):
        """Lines 548-549, 555-556: unlink() raises OSError → suppressed, loop continues.
        So what: without these excepts, a single locked file would abort cleanup of all
        remaining expired backups, leaving disk space unreleased."""
        tmpdir = tempfile.mkdtemp()
        try:
            now = datetime.utcnow()
            for i, age_days in enumerate([10, 0]):
                ts = (now - timedelta(days=age_days, seconds=i)).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                bp = Path(tmpdir) / f"backup_{ts}.bin"
                mp = Path(tmpdir) / f"backup_{ts}.bin.manifest.json"
                bp.write_bytes(b"data")
                mp.write_text(
                    json.dumps(
                        {
                            "filename": f"backup_{ts}.bin",
                            "created_at": (
                                now - timedelta(days=age_days, seconds=i)
                            ).isoformat()
                            + "Z",
                            "backup_type": "full",
                            "keys_count": 1,
                            "checksum_sha256": "abc",
                            "size_bytes": 4,
                            "included_patterns": [],
                            "excluded_patterns": [],
                        }
                    )
                )

            def _failing_unlink(self, missing_ok=False):
                raise OSError("permission denied")

            with patch.object(Path, "unlink", _failing_unlink):
                BackupWorker().apply_retention(tmpdir, retain_count=1)
        finally:
            shutil.rmtree(tmpdir)
