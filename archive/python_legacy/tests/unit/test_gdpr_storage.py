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


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestGDPRStorageCoverageGaps:
    """Cover lines 96, 109-111, 124-136, 188, 199, 241-242, 259-261, 402.

    So what: these paths protect against broken Redis connections corrupting the
    GDPR data store silently, ensure TTL clamping actually enforces GDPR limits,
    and verify that the audit trail is written on successful stores.
    """

    def test_none_redis_client_raises_value_error(self):
        """Line 96: GDPRStorage(None) raises ValueError immediately.
        So what: a None client would cause AttributeError deep in setex/ping later —
        an explicit ValueError at construction time is clearer and prevents silent
        GDPR non-compliance from an unconfigured storage instance."""
        with pytest.raises(ValueError, match="Redis client is required"):
            GDPRStorage(redis_client=None, config={})

    def test_ping_redis_error_propagates(self):
        """Lines 109-111: redis.RedisError during ping → logged and re-raised.
        So what: if this re-raise is missing, a proxy started with a dead Redis
        silently accepts and stores all data without TTLs — violating GDPR retention
        requirements from the first connection."""
        redis_mock = MagicMock()
        redis_mock.ping.side_effect = redis.ConnectionError("connection refused")
        config = {"gdpr": {"audit_logging": True}}
        with pytest.raises(redis.RedisError):
            GDPRStorage(redis_client=redis_mock, config=config)

    def test_load_retention_clamps_ttl_exceeding_max(self):
        """Lines 124-136: configured TTL > GDPR maximum → clamped to max.
        So what: if clamping is skipped, an operator error in proxy.yml can set a
        90-day retention on rate-tracking data — a direct GDPR violation for
        ephemeral traffic metadata."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True
        # rate_tracking max = 300s; set to 99999 → must be clamped to 300
        config = {
            "gdpr": {
                "audit_logging": False,
                "retention_periods": {"rate_tracking": 99999},
            }
        }
        storage = GDPRStorage(redis_client=redis_mock, config=config)
        assert (
            storage.retention_periods[DataCategory.RATE_TRACKING]
            == DataCategory.RATE_TRACKING.get_max_ttl()
        )

    def test_store_valid_custom_ttl_uses_custom_value(self):
        """Line 188: valid custom_ttl (positive, within max) → stored with that exact TTL.
        So what: if the else-branch is missing, all valid custom TTLs silently fall
        through to the default, which could be much shorter or longer than intended —
        breaking downstream retention SLAs."""
        storage, redis_mock = _make_storage(audit_enabled=False)
        redis_mock.setex.return_value = True
        # FINGERPRINTS max is 86400; use 7200 — valid
        storage.store("mykey", "val", DataCategory.FINGERPRINTS, custom_ttl=7200)
        call = redis_mock.setex.call_args_list[0]
        assert call[0][1] == 7200

    def test_store_audit_log_called_when_enabled(self):
        """Line 199: when audit_enabled=True and setex succeeds, _audit_log is called.
        So what: if this branch is never exercised, the audit trail is silently empty
        — compliance officers would see zero evidence of data stored, making GDPR
        audit reports unverifiable."""
        storage, redis_mock = _make_storage(audit_enabled=True)
        redis_mock.setex.return_value = True
        result = storage.store("tracked_key", "value", DataCategory.FINGERPRINTS)
        assert result is True
        # setex called at least twice: once for data, once for audit log
        assert redis_mock.setex.call_count >= 2

    def test_verify_compliance_counts_compliant_keys(self):
        """Lines 241-242: keys with TTL >= 0 are counted as compliant.
        So what: if this branch is missing, all keys appear non-compliant in audit
        reports — operators would see false GDPR violations and might unnecessarily
        purge live keys or escalate to a DPO."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.return_value = [b"rate:1.2.3.4", b"blocked:t:abc"]
        redis_mock.ttl.return_value = 300  # positive TTL → compliant
        result = storage.verify_compliance()
        assert result["compliant_keys"] == 2
        assert result["non_compliant_keys"] == 0

    def test_verify_compliance_redis_error_returns_error_dict(self):
        """Lines 259-261: redis.RedisError in verify_compliance → error dict returned.
        So what: if this exception propagates, the health endpoint that calls
        verify_compliance() would crash — the proxy operator loses visibility into
        GDPR compliance status exactly when Redis is under pressure."""
        storage, redis_mock = _make_storage()
        redis_mock.keys.side_effect = redis.TimeoutError("Redis timeout")
        result = storage.verify_compliance()
        assert "error" in result
        assert result["compliant_keys"] == 0

    def test_from_config_classmethod(self):
        """Line 402: from_config() constructs a GDPRStorage instance.
        So what: operators use from_config() to wire up GDPRStorage from proxy.yml;
        if the classmethod is broken, the storage object is never created and all
        GDPR retention enforcement is silently absent."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True
        config = {"gdpr": {"audit_logging": False}}
        storage = GDPRStorage.from_config(redis_mock, config)
        assert isinstance(storage, GDPRStorage)
