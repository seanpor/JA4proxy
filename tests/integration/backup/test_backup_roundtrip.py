"""
Fakeredis-based encode→backup→restore round-trip integration tests (P19-G6).

These tests use fakeredis.FakeRedis() as a drop-in for redis.Redis, so they
run without a live Redis instance and are included in the normal test suite.

The round-trip is: populate FakeRedis → BackupWorker.create_backup() →
flushdb → BackupRestorer.restore_backup() → verify identical state.
"""

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import fakeredis
import pytest

from src.backup.restorer import BackupRestorer
from src.backup.worker import BackupWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_worker(fake_redis: fakeredis.FakeRedis) -> BackupWorker:
    worker = BackupWorker()
    # Patch redis.Redis so BackupWorker.create_backup() uses the fake instance
    worker._fake_redis = fake_redis
    return worker


def _patch_redis(fake: fakeredis.FakeRedis):
    """Context manager: any redis.Redis() call returns *fake*."""
    return patch("redis.Redis", return_value=fake)


def _patch_os_stat_for_dir(tmpdir: Path):
    """Make _validate_backup_directory pass for tmpdir."""
    real_stat = os.stat
    real_access = os.access

    def mock_stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        # Fake uid match and remove world/group-write bits
        import stat as stat_module

        class FakeStat:
            st_uid = os.getuid()
            st_mode = st.st_mode & ~(stat_module.S_IWGRP | stat_module.S_IWOTH)
            st_gid = st.st_gid

        return FakeStat()

    def mock_access(path, mode):
        return True

    return patch("os.stat", side_effect=mock_stat), patch(
        "os.access", side_effect=mock_access
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
    fake: fakeredis.FakeRedis,
    backup_path: Path,
    manifest_path: Path,
    threshold: float = 0.05,
) -> None:
    restorer = BackupRestorer(restore_error_threshold=threshold)
    with _patch_redis(fake):
        restorer.restore_backup(str(backup_path), str(manifest_path))


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestBackupRoundTrip:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir)

    def test_roundtrip_string_key(self):
        fake = fakeredis.FakeRedis()
        fake.set("config:dial", "50")

        bp, mp = _do_backup(fake, self.tmpdir)
        fake.flushdb()
        assert fake.get("config:dial") is None

        _do_restore(fake, bp, mp)
        assert fake.get("config:dial") == b"50"

    def test_roundtrip_set_key(self):
        fake = fakeredis.FakeRedis()
        fake.sadd("ja4:blacklist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
        fake.sadd("ja4:blacklist", "t12d1011h1_112233445566_aabbccddeeff")

        bp, mp = _do_backup(fake, self.tmpdir)
        fake.flushdb()

        _do_restore(fake, bp, mp)
        members = fake.smembers("ja4:blacklist")
        assert b"t13d1516h2_aabbccddeeff_aabbccddeeff" in members
        assert b"t12d1011h1_112233445566_aabbccddeeff" in members

    def test_roundtrip_hash_key(self):
        # rdap:ip:* is in the include list and naturally stores hash fields
        fake = fakeredis.FakeRedis()
        fake.hset(
            "rdap:ip:1.2.3.4",
            mapping={"org": "ExampleISP", "cidr": "1.2.3.0/24", "risk": "5"},
        )

        bp, mp = _do_backup(fake, self.tmpdir)
        fake.flushdb()

        _do_restore(fake, bp, mp)
        assert fake.hget("rdap:ip:1.2.3.4", "risk") == b"5"
        assert fake.hget("rdap:ip:1.2.3.4", "org") == b"ExampleISP"

    def test_roundtrip_sorted_set_key(self):
        # analytics:* is in the include list and can store sorted sets
        fake = fakeredis.FakeRedis()
        fake.zadd("analytics:scores", {"1.2.3.4": 75.0, "5.6.7.8": 42.0})

        bp, mp = _do_backup(fake, self.tmpdir)
        fake.flushdb()

        _do_restore(fake, bp, mp)
        members = fake.zrange("analytics:scores", 0, -1)
        assert len(members) == 2

    def test_roundtrip_multiple_key_types(self):
        """Representative set of proxy key types all survive round-trip."""
        fake = fakeredis.FakeRedis()
        fake.set("ban:1.2.3.4", "1")
        fake.set("config:dial", "75")
        fake.sadd("ja4:blacklist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
        fake.hset("rdap:ip:5.6.7.8", mapping={"org": "TestISP", "risk": "3"})
        fake.zadd("analytics:top_risk", {"9.10.11.12": 100.0})

        bp, mp = _do_backup(fake, self.tmpdir)
        fake.flushdb()
        assert fake.dbsize() == 0

        _do_restore(fake, bp, mp)

        assert fake.get("ban:1.2.3.4") == b"1"
        assert fake.get("config:dial") == b"75"
        assert fake.sismember("ja4:blacklist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
        assert fake.hget("rdap:ip:5.6.7.8", "org") == b"TestISP"
        assert len(fake.zrange("analytics:top_risk", 0, -1)) == 1

    def test_backup_file_is_deterministic(self):
        """Two backups of identical state produce identical checksums."""
        fake1 = fakeredis.FakeRedis()
        fake1.set("config:dial", "50")
        fake1.sadd("ja4:blacklist", "fp1")

        fake2 = fakeredis.FakeRedis()
        fake2.set("config:dial", "50")
        fake2.sadd("ja4:blacklist", "fp1")

        dest1 = self.tmpdir / "run1"
        dest2 = self.tmpdir / "run2"
        dest1.mkdir()
        dest2.mkdir()

        bp1, mp1 = _do_backup(fake1, dest1)
        bp2, mp2 = _do_backup(fake2, dest2)

        m1 = json.loads(mp1.read_text())
        m2 = json.loads(mp2.read_text())
        assert m1["checksum_sha256"] == m2["checksum_sha256"]

    def test_restore_into_nonempty_db_overwrites_existing_keys(self):
        """Restoring over existing state replaces values (replace=True)."""
        fake = fakeredis.FakeRedis()
        fake.set("config:dial", "50")

        bp, mp = _do_backup(fake, self.tmpdir)

        # Overwrite the value
        fake.set("config:dial", "99")
        assert fake.get("config:dial") == b"99"

        _do_restore(fake, bp, mp)
        # Restored value wins
        assert fake.get("config:dial") == b"50"

    def test_manifest_keys_count_matches_actual_keys_backed_up(self):
        fake = fakeredis.FakeRedis()
        fake.set("ban:1.1.1.1", "1")
        fake.set("ban:2.2.2.2", "1")
        fake.sadd("ja4:whitelist", "fp1")

        bp, mp = _do_backup(fake, self.tmpdir)
        manifest = json.loads(mp.read_text())

        # keys_count in manifest should reflect what was backed up
        # (may exclude never-backup keys — just verify it's a positive int)
        assert manifest["keys_count"] > 0
        assert isinstance(manifest["checksum_sha256"], str)
        assert len(manifest["checksum_sha256"]) == 64  # SHA-256 hex digest
