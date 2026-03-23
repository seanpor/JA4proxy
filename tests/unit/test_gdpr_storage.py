#!/usr/bin/env python3
"""
Tests for src/security/gdpr_storage.py.

Covers uncovered paths: cleanup_expired, get_audit_logs, exception handlers
in get_retention_report and _audit_log.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import redis

from src.security.gdpr_storage import DataCategory, GDPRStorage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_storage(ping_ok=True, audit_enabled=True):
    """Build a GDPRStorage with a mocked Redis client."""
    redis_mock = MagicMock()
    if ping_ok:
        redis_mock.ping.return_value = True
    else:
        redis_mock.ping.side_effect = redis.ConnectionError("down")
    config = {"gdpr": {"audit_logging": audit_enabled}}
    return GDPRStorage(redis_client=redis_mock, config=config), redis_mock


# ---------------------------------------------------------------------------
# cleanup_expired (lines 272-290)
# ---------------------------------------------------------------------------

class TestCleanupExpired:
    def test_no_keys_returns_zero(self):
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = []
        assert storage.cleanup_expired() == 0

    def test_keys_with_positive_ttl_not_counted(self):
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"key1", b"key2"]
        redis_mock.ttl.return_value = 300  # healthy TTL
        assert storage.cleanup_expired() == 0

    def test_key_with_ttl_zero_is_counted(self):
        """TTL=0 means the key is about to expire."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"key1"]
        redis_mock.ttl.return_value = 0
        assert storage.cleanup_expired() == 1

    def test_key_with_ttl_negative_two_is_counted(self):
        """TTL=-2 means the key has already expired (Redis returns -2)."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"key1", b"key2"]
        redis_mock.ttl.return_value = -2
        assert storage.cleanup_expired() == 2

    def test_mixed_ttls_counts_only_zero_and_minus_two(self):
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"k1", b"k2", b"k3"]
        redis_mock.ttl.side_effect = [300, 0, -2]
        assert storage.cleanup_expired() == 2

    def test_exception_returns_zero(self):
        """Line 288-290: exception in cleanup → return 0."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.side_effect = redis.ConnectionError("Redis unavailable")
        assert storage.cleanup_expired() == 0


# ---------------------------------------------------------------------------
# get_retention_report — exception path (lines 327-328)
# ---------------------------------------------------------------------------

class TestGetRetentionReport:
    def test_returns_report_with_categories(self):
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = []
        report = storage.get_retention_report()
        assert "retention_periods" in report
        assert "key_counts" in report

    def test_key_count_exception_silenced(self):
        """Lines 327-328: redis.keys() raises during key count → exception caught."""
        storage, redis_mock = _make_storage()
        # First call succeeds (for any earlier checks), keys() call in loop raises
        redis_mock.keys.side_effect = redis.TimeoutError("Redis timeout")
        # Must not raise; report is still returned
        report = storage.get_retention_report()
        assert "retention_periods" in report
        # key_counts will be empty because the exception was caught
        assert report.get("key_counts", {}) == {}


# ---------------------------------------------------------------------------
# _audit_log — exception path (lines 346-347)
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_audit_log_writes_to_redis(self):
        """Normal audit log write succeeds."""
        storage, redis_mock = _make_storage(audit_enabled=True)
        entry = {"action": "store", "category": "fingerprints"}
        storage._audit_log(entry)
        redis_mock.setex.assert_called_once()

    def test_audit_log_exception_is_silenced(self):
        """Lines 346-347: setex raises → exception caught, no propagation."""
        storage, redis_mock = _make_storage(audit_enabled=True)
        redis_mock.setex.side_effect = redis.ResponseError("write failed")
        # Must not raise
        storage._audit_log({"action": "test"})

    def test_audit_log_disabled_skips_write(self):
        """When audit_logging=False, store() skips the audit log."""
        storage, redis_mock = _make_storage(audit_enabled=False)
        redis_mock.setex.return_value = True
        storage.store("mykey", "value", DataCategory.FINGERPRINTS)
        # setex called once for the data store, but not for audit log
        # (audit log disabled)
        called_keys = [str(c) for c in redis_mock.setex.call_args_list]
        audit_calls = [c for c in called_keys if "audit:" in c]
        assert len(audit_calls) == 0


# ---------------------------------------------------------------------------
# get_audit_logs (lines 359-378)
# ---------------------------------------------------------------------------

class TestGetAuditLogs:
    def test_returns_empty_when_no_audit_keys(self):
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = []
        logs = storage.get_audit_logs()
        assert logs == []

    def test_returns_parsed_json_logs(self):
        """Lines 359-375: normal path — keys retrieved, data parsed."""
        storage, redis_mock = _make_storage()
        entry = {"action": "store", "category": "fingerprints"}
        redis_mock.keys.return_value = [b"audit:1000", b"audit:999"]
        redis_mock.get.return_value = json.dumps(entry).encode()
        logs = storage.get_audit_logs()
        assert len(logs) == 2
        assert logs[0]["action"] == "store"

    def test_none_data_skipped(self):
        """data=None is falsy → not appended."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"audit:1000"]
        redis_mock.get.return_value = None
        logs = storage.get_audit_logs()
        assert logs == []

    def test_invalid_json_inner_exception_caught(self):
        """Inner except (lines 372-373): json.loads fails → error logged, skipped."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"audit:1000"]
        redis_mock.get.return_value = b"not-valid-json{"
        # Must not raise; bad entry is silently dropped
        logs = storage.get_audit_logs()
        assert logs == []

    def test_outer_exception_returns_empty_list(self):
        """Lines 376-378: redis.keys raises → outer except returns []."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.side_effect = redis.ConnectionError("Redis down")
        logs = storage.get_audit_logs()
        assert logs == []

    def test_limit_respected(self):
        """Limit parameter slices the sorted key list."""
        storage, redis_mock = _make_storage()
        # 5 audit keys, limit=2 → only 2 logs
        keys = [f"audit:{i}".encode() for i in range(5)]
        redis_mock.keys.return_value = keys
        redis_mock.get.return_value = json.dumps({"n": 1}).encode()
        logs = storage.get_audit_logs(limit=2)
        assert len(logs) == 2


# ---------------------------------------------------------------------------
# verify_compliance — exception path (already in existing tests but double-check)
# ---------------------------------------------------------------------------

class TestVerifyCompliance:
    def test_no_ttl_key_is_violation(self):
        """TTL=-1 means key has no expiry → GDPR violation."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"key1"]
        redis_mock.ttl.return_value = -1
        result = storage.verify_compliance()
        assert result["non_compliant_keys"] == 1
        assert len(result["violations"]) == 1

    def test_key_bytes_decoded_for_hash(self):
        """bytes key is decoded before hashing (line 232 isinstance branch)."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"mykey"]
        redis_mock.ttl.return_value = -1
        result = storage.verify_compliance()
        assert result["non_compliant_keys"] == 1


# ---------------------------------------------------------------------------
# store — custom TTL edge cases
# ---------------------------------------------------------------------------

class TestStoreCustomTtl:
    def test_custom_ttl_exceeding_max_is_clamped(self):
        """custom_ttl > max_ttl → clamped to max_ttl."""
        storage, redis_mock = _make_storage(audit_enabled=False)
        redis_mock.setex.return_value = True
        # RATE_TRACKING max is 300s; pass 9999 → clamped to 300
        storage.store("key", "value", DataCategory.RATE_TRACKING, custom_ttl=9999)
        # First (and only with audit disabled) setex call is for the data
        first_call = redis_mock.setex.call_args_list[0]
        assert first_call[0][1] == DataCategory.RATE_TRACKING.get_max_ttl()

    def test_custom_ttl_zero_or_negative_uses_default(self):
        """custom_ttl <= 0 → fallback to configured retention period."""
        storage, redis_mock = _make_storage(audit_enabled=False)
        redis_mock.setex.return_value = True
        default_ttl = storage.retention_periods[DataCategory.FINGERPRINTS]
        storage.store("key", "value", DataCategory.FINGERPRINTS, custom_ttl=0)
        first_call = redis_mock.setex.call_args_list[0]
        assert first_call[0][1] == default_ttl

    def test_empty_key_returns_false(self):
        storage, redis_mock = _make_storage()
        result = storage.store("", "value", DataCategory.FINGERPRINTS)
        assert result is False
        redis_mock.setex.assert_not_called()

    def test_redis_setex_failure_returns_false(self):
        """Exception in setex → return False."""
        storage, redis_mock = _make_storage()
        redis_mock.setex.side_effect = redis.ResponseError("write error")
        result = storage.store("key", "value", DataCategory.FINGERPRINTS)
        assert result is False
