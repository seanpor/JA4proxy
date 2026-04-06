"""
Full round-trip integration test: S3 cloud backup + restore (Phase 57b).

Uses moto (S3 mock) and fakeredis — no real AWS or Redis required.

Round-trip: populate fakeredis → BackupWorker.create_backup() →
S3StorageAdapter.upload() → S3StorageAdapter.download() →
BackupRestorer.restore_backup() → assert all keys restored.
"""

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import boto3
import fakeredis
import pytest
from moto import mock_aws

from src.backup.restorer import BackupRestorer
from src.backup.worker import BackupWorker


# ---------------------------------------------------------------------------
# Helpers shared with test_backup_roundtrip.py
# ---------------------------------------------------------------------------


def _patch_redis(fake: fakeredis.FakeRedis):
    """Context manager: any redis.Redis() call returns *fake*."""
    return patch("redis.Redis", return_value=fake)


def _patch_os_stat_for_dir(tmpdir: Path):
    """Make _validate_backup_directory pass for tmpdir."""
    real_stat = os.stat

    def mock_stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        import stat as stat_module

        class FakeStat:
            st_uid = os.getuid()
            st_mode = st.st_mode & ~(stat_module.S_IWGRP | stat_module.S_IWOTH)
            st_gid = st.st_gid

        return FakeStat()

    def mock_access(path, mode):
        return True

    return (
        patch("os.stat", side_effect=mock_stat),
        patch("os.access", side_effect=mock_access),
    )


def _do_backup(fake: fakeredis.FakeRedis, dest: Path) -> tuple[Path, Path]:
    """Run create_backup against *fake*; return (backup_path, manifest_path)."""
    worker = BackupWorker()
    stat_patch, access_patch = _patch_os_stat_for_dir(dest)
    with _patch_redis(fake), stat_patch, access_patch:
        backup_path = worker.create_backup(str(dest))
    manifest_path = Path(str(backup_path) + ".manifest.json")
    return backup_path, manifest_path


def _do_restore(
    fake: fakeredis.FakeRedis, backup_path: Path, threshold: float = 0.05
) -> None:
    manifest_path = Path(str(backup_path) + ".manifest.json")
    restorer = BackupRestorer(restore_error_threshold=threshold)
    with _patch_redis(fake):
        restorer.restore_backup(str(backup_path), str(manifest_path))


# ---------------------------------------------------------------------------
# Main round-trip test
# ---------------------------------------------------------------------------


class TestFullRoundTripS3:
    """Full backup → S3 upload → S3 download → restore round-trip."""

    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir)

    def test_full_roundtrip_s3(self, monkeypatch):
        """
        Populate fakeredis with 10 keys → backup → upload to mocked S3
        → download from S3 → restore → assert all 10 keys present.
        """
        # Set fake AWS credentials
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        import asyncio

        with mock_aws():
            # Create S3 bucket
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="ja4proxy-backups")

            # Populate fakeredis with 10 representative keys
            fake = fakeredis.FakeRedis()
            fake.set("ban:1.1.1.1", "1")
            fake.set("ban:2.2.2.2", "1")
            fake.set("ban:3.3.3.3", "1")
            fake.set("config:dial", "50")
            fake.set("config:mode", "monitor")
            fake.sadd("ja4:whitelist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
            fake.sadd("ja4:blacklist", "t12d1011h1_112233445566_aabbccddeeff")
            fake.hset(
                "rdap:ip:10.0.0.1",
                mapping={"org": "TestISP", "cidr": "10.0.0.0/24", "risk": "7"},
            )
            fake.zadd("analytics:top_risk", {"10.0.0.2": 95.0})
            fake.set("config:block_threshold", "70")

            assert fake.dbsize() == 10

            # Step 1 — create local backup
            backup_path, manifest_path = _do_backup(fake, self.tmpdir)
            assert backup_path.exists()

            # Step 2 — upload to mocked S3
            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="ja4proxy-backups", prefix="backups/", region="us-east-1"
            )
            import json

            manifest = json.loads(manifest_path.read_text())
            meta = asyncio.run(adapter.upload(backup_path, manifest))
            assert meta is not None
            assert meta.uri.startswith("s3://ja4proxy-backups/")

            # Step 3 — download from S3 to a fresh local path
            download_dest = self.tmpdir / "downloaded_backup.bin"
            asyncio.run(adapter.download(meta.uri, download_dest))
            assert download_dest.exists()

            # Step 4 — copy manifest next to download (restorer expects sidecar)
            import shutil as _shutil

            _shutil.copy(manifest_path, str(download_dest) + ".manifest.json")

            # Step 5 — flush and restore
            fake.flushdb()
            assert fake.dbsize() == 0

            _do_restore(fake, download_dest)

            # Step 6 — assert all 10 keys restored
            assert fake.get("ban:1.1.1.1") == b"1"
            assert fake.get("ban:2.2.2.2") == b"1"
            assert fake.get("ban:3.3.3.3") == b"1"
            assert fake.get("config:dial") == b"50"
            assert fake.get("config:mode") == b"monitor"
            assert fake.sismember(
                "ja4:whitelist", "t13d1516h2_aabbccddeeff_aabbccddeeff"
            )
            assert fake.sismember(
                "ja4:blacklist", "t12d1011h1_112233445566_aabbccddeeff"
            )
            assert fake.hget("rdap:ip:10.0.0.1", "org") == b"TestISP"
            scores = fake.zrange("analytics:top_risk", 0, -1)
            assert len(scores) == 1
            assert fake.get("config:block_threshold") == b"70"

    def test_downloaded_bytes_match_uploaded_bytes(self, monkeypatch):
        """Bytes downloaded from S3 must be byte-for-byte identical to uploaded."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        import asyncio

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="test-integrity")

            fake = fakeredis.FakeRedis()
            fake.set("config:dial", "100")

            backup_path, manifest_path = _do_backup(fake, self.tmpdir)

            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="test-integrity", prefix="backups/", region="us-east-1"
            )
            import json

            manifest = json.loads(manifest_path.read_text())
            meta = asyncio.run(adapter.upload(backup_path, manifest))

            download_dest = self.tmpdir / "integrity_check.bin"
            asyncio.run(adapter.download(meta.uri, download_dest))

            assert download_dest.read_bytes() == backup_path.read_bytes()

    def test_checksum_verified_after_roundtrip(self, monkeypatch):
        """verify_checksum() returns True for the downloaded artifact."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        import asyncio

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="test-checksum")

            fake = fakeredis.FakeRedis()
            fake.set("ban:5.5.5.5", "1")

            backup_path, manifest_path = _do_backup(fake, self.tmpdir)

            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="test-checksum", prefix="backups/", region="us-east-1"
            )
            import json

            manifest = json.loads(manifest_path.read_text())
            meta = asyncio.run(adapter.upload(backup_path, manifest))

            verified = asyncio.run(
                adapter.verify_checksum(meta.uri, meta.checksum_sha256)
            )
            assert verified is True
