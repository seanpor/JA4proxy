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
