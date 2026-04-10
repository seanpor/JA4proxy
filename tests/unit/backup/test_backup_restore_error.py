"""
Tests for RestoreError key-failure threshold in BackupRestorer (P19-G4).
"""
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import redis as redis_lib

from src.backup.format import encode_entry
from src.backup.restorer import BackupRestorer, RestoreError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_backup(dest: Path, entries: list[tuple[str, bytes]]) -> tuple[Path, Path]:
    """Write a minimal backup artifact + manifest; return (backup_path, manifest_path)."""
    data = b"".join(encode_entry(k, v) for k, v in entries)
    checksum = hashlib.sha256(data).hexdigest()
    ts = "20260101T000000Z"
    filename = f"backup_{ts}.bin"
    bp = dest / filename
    mp = dest / f"{filename}.manifest.json"
    bp.write_bytes(data)
    mp.write_text(json.dumps({
        "filename": filename,
        "created_at": "2026-01-01T00:00:00Z",
        "backup_type": "full",
        "keys_count": len(entries),
        "checksum_sha256": checksum,
        "size_bytes": len(data),
        "included_patterns": ["*"],
        "excluded_patterns": [],
    }))
    return bp, mp


def _make_restorer(threshold: float = 0.05) -> BackupRestorer:
    return BackupRestorer(restore_error_threshold=threshold)


def _make_mock_redis(fail_keys: set[str] | None = None):
    """Redis mock that raises RedisError for keys in fail_keys."""
    fail_keys = fail_keys or set()
    mock = MagicMock()
    mock.ping.return_value = True

    def _restore(key, ttl, data, replace=True):
        if key in fail_keys:
            raise redis_lib.RedisError(f"mock failure for {key}")

    mock.restore.side_effect = _restore
    return mock


# ---------------------------------------------------------------------------
# RestoreError constructor tests
# ---------------------------------------------------------------------------

class TestRestoreErrorConstructor:
    def test_default_attributes(self):
        err = RestoreError("msg")
        assert err.failed == 0
        assert err.total == 0
        assert err.threshold == 0.0

    def test_custom_attributes(self):
        err = RestoreError("msg", failed=5, total=100, threshold=0.05)
        assert err.failed == 5
        assert err.total == 100
        assert err.threshold == 0.05

    def test_str_contains_message(self):
        err = RestoreError("something went wrong")
        assert "something went wrong" in str(err)


# ---------------------------------------------------------------------------
# Threshold enforcement tests
# ---------------------------------------------------------------------------

class TestRestoreErrorThreshold:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir)

    def _restore(self, restorer, entries, fail_keys=None):
        bp, mp = _write_backup(self.tmpdir, entries)
        mock_redis = _make_mock_redis(fail_keys)
        with patch("redis.Redis", return_value=mock_redis):
            restorer.restore_backup(str(bp), str(mp))

    def test_restore_raises_when_failures_exceed_threshold(self):
        """6 of 10 keys fail → 60% > 5% threshold → RestoreError."""
        restorer = _make_restorer(threshold=0.05)
        entries = [(f"key:{i}", b"data") for i in range(10)]
        fail_keys = {f"key:{i}" for i in range(6)}

        with pytest.raises(RestoreError) as exc_info:
            self._restore(restorer, entries, fail_keys)

        err = exc_info.value
        assert err.failed == 6
        assert err.total == 10
        assert err.threshold == 0.05

    def test_restore_succeeds_when_failures_below_threshold(self):
        """1 of 10 keys fails → 10% < default 5%... wait that's above. Use threshold=0.15."""
        restorer = _make_restorer(threshold=0.15)
        entries = [(f"key:{i}", b"data") for i in range(10)]
        fail_keys = {"key:0"}  # 10% failure rate < 15% threshold

        # Should not raise
        self._restore(restorer, entries, fail_keys)

    def test_restore_succeeds_when_failures_at_threshold_boundary(self):
        """Exactly at threshold is not exceeded (strict >)."""
        # 5 of 100 = 5.0% which is NOT > 5% threshold
        restorer = _make_restorer(threshold=0.05)
        entries = [(f"key:{i}", b"data") for i in range(100)]
        fail_keys = {f"key:{i}" for i in range(5)}  # exactly 5%

        # Should not raise
        self._restore(restorer, entries, fail_keys)

    def test_restore_succeeds_with_no_failures(self):
        restorer = _make_restorer(threshold=0.05)
        entries = [("ban:1.2.3.4", b"data"), ("config:dial", b"50")]

        # Should not raise
        self._restore(restorer, entries, fail_keys=set())

    def test_restore_error_message_contains_counts(self):
        restorer = _make_restorer(threshold=0.05)
        entries = [(f"k:{i}", b"v") for i in range(4)]
        fail_keys = {f"k:{i}" for i in range(3)}  # 75% failure

        with pytest.raises(RestoreError) as exc_info:
            self._restore(restorer, entries, fail_keys)

        msg = str(exc_info.value)
        assert "3" in msg   # failed count
        assert "4" in msg   # total count

    def test_restore_threshold_zero_means_any_failure_raises(self):
        restorer = _make_restorer(threshold=0.0)
        entries = [("good", b"v"), ("bad", b"v")]
        fail_keys = {"bad"}

        with pytest.raises(RestoreError) as exc_info:
            self._restore(restorer, entries, fail_keys)

        assert exc_info.value.failed == 1

    def test_restore_threshold_1_never_raises_on_failures(self):
        """threshold=1.0 means 100% failure required to raise — effectively disabled."""
        restorer = _make_restorer(threshold=1.0)
        entries = [("k1", b"v"), ("k2", b"v")]
        fail_keys = {"k1", "k2"}  # 100% failure but threshold=1.0 means not strictly >

        # Should not raise
        self._restore(restorer, entries, fail_keys)

    def test_restore_threshold_attribute_on_restorer(self):
        r = BackupRestorer(restore_error_threshold=0.10)
        assert r.restore_error_threshold == 0.10

    def test_restore_threshold_default_is_0_05(self):
        r = BackupRestorer()
        assert r.restore_error_threshold == 0.05


# ---------------------------------------------------------------------------
# Coverage gap additions — lines 227, 258-272, 391-393, 437-438, 460-470
# ---------------------------------------------------------------------------

class TestRestorerCoverageGaps:
    """Missing coverage for restorer.py lines 227, 258-272, 391-393, 437-438, 460-470."""

    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir)

    def _write_backup(self, entries=None):
        entries = entries or [("key:1", b"val")]
        return _write_backup(self.tmpdir, entries)

    def test_lock_held_raises_restore_error(self):
        """Line 227: distributed lock already held → RestoreError before restore begins.
        So what: without this guard, two concurrent restores could interleave writes
        into Redis, producing a partially-overwritten, inconsistent keyspace."""
        bp, mp = self._write_backup()
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        # nx=True set returns None/False → lock already held
        mock_redis.set.return_value = None

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError, match="lock held"):
                BackupRestorer().restore_backup(str(bp), str(mp))

    def test_audit_log_redis_error_is_suppressed(self):
        """Lines 391-393: audit log lpush raises RedisError → suppressed, main error re-raised.
        So what: without this except, a Redis outage during the audit-log write would
        mask the real restore error, making root-cause analysis impossible."""
        bp, mp = self._write_backup()
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True  # lock acquired
        mock_redis.restore.side_effect = Exception("deliberate restore failure")
        mock_redis.lpush.side_effect = redis_lib.RedisError("audit log write failed")

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError):
                BackupRestorer().restore_backup(str(bp), str(mp))
        # test passes if no secondary exception escapes

    def test_restore_backup_data_oserror_raises_restore_error(self):
        """Lines 437-438: backup file unreadable → RestoreError('Failed to read backup data').
        So what: without this handler, an OSError propagates untyped through restore_backup,
        losing the descriptive context and making operator diagnosis harder."""
        bp, mp = self._write_backup()
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True  # lock acquired

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            # Pass a nonexistent backup path; manifest validation passes first,
            # so we patch verify_checksum to return True
            with patch.object(BackupRestorer, "verify_checksum", return_value=True):
                with pytest.raises(RestoreError, match="Failed to read backup data"):
                    BackupRestorer().restore_backup("/nonexistent/path.bin", str(mp))

    def test_restore_from_bytes_restores_keys(self):
        """Lines 460-470: _restore_from_bytes() iterates decoded entries and restores them.
        So what: this is the only code path executed for encrypted backups — if broken,
        all encrypted backup restores silently restore 0 keys, losing the Redis state."""
        from src.backup.format import encode_entry
        data = encode_entry("key:foo", b"dump-data") + encode_entry("key:bar", b"dump-data-2")

        mock_redis = MagicMock()
        mock_redis.restore.return_value = None

        restorer = BackupRestorer()
        keys_restored, keys_failed = restorer._restore_from_bytes(mock_redis, data)

        assert keys_restored == 2
        assert keys_failed == 0
        assert mock_redis.restore.call_count == 2

    def test_restore_from_bytes_redis_error_counts_failure(self):
        """Lines 466-468: RedisError on individual key in _restore_from_bytes is logged and counted.
        So what: without this handler, one bad key in an encrypted backup aborts the entire
        restore, losing all subsequent keys even though they were valid."""
        from src.backup.format import encode_entry
        data = encode_entry("bad:key", b"corrupt") + encode_entry("good:key", b"valid")

        mock_redis = MagicMock()
        call_count = [0]

        def _restore(key, ttl, data, replace=True):
            call_count[0] += 1
            if call_count[0] == 1:
                raise redis_lib.RedisError("corrupted dump")

        mock_redis.restore.side_effect = _restore

        restorer = BackupRestorer()
        keys_restored, keys_failed = restorer._restore_from_bytes(mock_redis, data)

        assert keys_restored == 1
        assert keys_failed == 1

    def test_encrypted_backup_restore_path(self):
        """Lines 258-272: encrypted manifest → reads file, decrypts, calls _restore_from_bytes.
        So what: if this branch is broken, encrypted backups always fail with 'Backup is
        encrypted but no decryption key provided' or silently fall through to unencrypted
        path, producing garbage data in Redis."""
        from src.backup.format import encode_entry
        raw_data = encode_entry("secret:key", b"secret-dump")

        # Write a backup with encryption flag in manifest
        ts = "20260101T000000Z"
        filename = f"backup_{ts}.bin"
        bp = self.tmpdir / filename
        mp = self.tmpdir / f"{filename}.manifest.json"

        import hashlib
        checksum = hashlib.sha256(raw_data).hexdigest()
        bp.write_bytes(raw_data)  # unencrypted bytes (encryption.decrypt is mocked)
        mp.write_text(json.dumps({
            "filename": filename,
            "created_at": "2026-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(raw_data),
            "included_patterns": ["*"],
            "excluded_patterns": [],
            "encryption": {"enabled": True},
        }))

        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True  # lock acquired
        mock_redis.restore.return_value = None

        mock_encryption = MagicMock()
        mock_encryption.decrypt.return_value = raw_data  # "decrypt" returns raw_data unchanged

        restorer = BackupRestorer(encryption_key="dummy-key")
        restorer.encryption = mock_encryption  # inject mock

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            restorer.restore_backup(str(bp), str(mp))

        mock_encryption.decrypt.assert_called_once()
        # Verify keys were restored via _restore_from_bytes path
        assert mock_redis.restore.called

    def _write_encrypted_manifest(self):
        """Write a minimal backup with encryption=enabled in the manifest."""
        import hashlib

        from src.backup.format import encode_entry
        raw_data = encode_entry("k", b"v")
        ts = "20260102T000000Z"
        filename = f"backup_{ts}.bin"
        bp = self.tmpdir / filename
        mp = self.tmpdir / f"{filename}.manifest.json"
        checksum = hashlib.sha256(raw_data).hexdigest()
        bp.write_bytes(raw_data)
        mp.write_text(json.dumps({
            "filename": filename,
            "created_at": "2026-01-02T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(raw_data),
            "included_patterns": ["*"],
            "excluded_patterns": [],
            "encryption": {"enabled": True},
        }))
        return bp, mp

    def test_encrypted_backup_no_key_raises_restore_error(self):
        """Line 259: encrypted manifest + no encryption_key → RestoreError.
        So what: without this guard, the restorer would attempt to pass ciphertext
        bytes directly to _restore_from_bytes, producing corrupt or empty key restores
        with no error surfaced to the operator."""
        bp, mp = self._write_encrypted_manifest()
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True  # lock acquired

        restorer = BackupRestorer()  # no encryption_key → self.encryption is None
        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError, match="no decryption key"):
                restorer.restore_backup(str(bp), str(mp))

    def test_encrypted_backup_decryption_failure_raises_restore_error(self):
        """Lines 269-270: encryption.decrypt() raises → RestoreError('Decryption failed').
        So what: without this re-raise, a corrupt ciphertext silently propagates a
        low-level cryptography exception instead of a structured RestoreError, breaking
        operator tooling that catches only RestoreError."""
        bp, mp = self._write_encrypted_manifest()
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True  # lock acquired

        mock_encryption = MagicMock()
        mock_encryption.decrypt.side_effect = ValueError("invalid tag")

        restorer = BackupRestorer(encryption_key="dummy-key")
        restorer.encryption = mock_encryption

        with patch("src.backup.restorer.redis.Redis", return_value=mock_redis):
            with pytest.raises(RestoreError, match="Decryption failed"):
                restorer.restore_backup(str(bp), str(mp))
