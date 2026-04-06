#!/usr/bin/env python3
"""
Unit tests for scripts/gdpr_delete.py — Phase 91 (GDPR Live Redis Erasure)

Uses fakeredis for full Redis fidelity without a running Redis instance.

These tests are written TDD-style and are expected to FAIL until the code
agent implements:
  - The ``r`` parameter on ``purge_ip`` (for dependency injection)
  - Audit log writes to ``management:gdpr_erasure_log``
"""
import json
import sys
import os

import pytest
import fakeredis

# Allow import of scripts/ directory from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from scripts.gdpr_delete import purge_ip, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redis() -> fakeredis.FakeRedis:
    """Return a fresh, isolated fakeredis client with decode_responses=True."""
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------------------------------------------------------------------
# 1. Exact-key deletion
# ---------------------------------------------------------------------------

def test_exact_key_deletion():
    """Exact per-IP keys (ban, visitor, lifespan, concurrent) are all deleted."""
    r = _make_redis()
    ip = "1.2.3.4"
    keys = [
        f"ban:{ip}",
        f"visitor:{ip}",
        f"lifespan:{ip}",
        f"concurrent:{ip}",
    ]
    for key in keys:
        r.set(key, "value")

    result = purge_ip(ip, dry_run=False, r=r)

    for key in keys:
        assert not r.exists(key), f"Expected key '{key}' to be deleted"

    assert result["keys_deleted"] == len(keys)


# ---------------------------------------------------------------------------
# 2. Wildcard-key deletion
# ---------------------------------------------------------------------------

def test_wildcard_key_deletion():
    """Keys matching wildcard patterns (session:ip:* and beacon:*) are deleted."""
    r = _make_redis()
    ip = "1.2.3.4"
    wildcard_keys = [
        f"session:ip:{ip}:ja4:abc123",
        f"beacon:{ip}:some_ja4",
    ]
    for key in wildcard_keys:
        r.set(key, "value")

    result = purge_ip(ip, dry_run=False, r=r)

    for key in wildcard_keys:
        assert not r.exists(key), f"Expected wildcard key '{key}' to be deleted"

    assert result["keys_deleted"] >= len(wildcard_keys)


# ---------------------------------------------------------------------------
# 3. Sorted-set member removal
# ---------------------------------------------------------------------------

def test_zset_member_removal():
    """Members belonging to the target IP are removed; other members remain."""
    r = _make_redis()
    ip = "1.2.3.4"
    other_ip = "5.5.5.5"
    zset_key = "behavioral:burst:example.com"

    r.zadd(zset_key, {f"{ip}:1000": 1000, f"{other_ip}:2000": 2000})

    result = purge_ip(ip, dry_run=False, r=r)

    # The target IP's member must be gone
    members = r.zrange(zset_key, 0, -1)
    assert f"{ip}:1000" not in members, "Target IP member should have been removed"
    # The other IP's member must still be present
    assert f"{other_ip}:2000" in members, "Other IP member should not have been removed"

    assert result["zset_members_removed"] >= 1


# ---------------------------------------------------------------------------
# 4. HLL keys are not deleted
# ---------------------------------------------------------------------------

def test_hll_keys_not_deleted():
    """HyperLogLog keys are skipped (cannot remove individual contributors)."""
    r = _make_redis()
    ip = "1.2.3.4"
    hll_key = "hll:cidr48:1.2.3.0/24"

    r.pfadd(hll_key, ip)

    result = purge_ip(ip, dry_run=False, r=r)

    assert r.exists(hll_key), "HLL key should NOT be deleted"
    assert result["hll_skipped"] == 1, (
        f"Expected hll_skipped == 1, got {result['hll_skipped']}"
    )


# ---------------------------------------------------------------------------
# 5. Dry-run deletes nothing
# ---------------------------------------------------------------------------

def test_dry_run_deletes_nothing():
    """With dry_run=True no keys are actually deleted, but count reflects would-be deletions."""
    r = _make_redis()
    ip = "1.2.3.4"
    key = f"ban:{ip}"
    r.set(key, "value")

    result = purge_ip(ip, dry_run=True, r=r)

    assert r.exists(key), "Key should still exist after dry run"
    assert result["keys_deleted"] >= 1, (
        "dry_run result should report how many keys WOULD be deleted"
    )


# ---------------------------------------------------------------------------
# 6. Audit log written on normal run
# ---------------------------------------------------------------------------

def test_audit_log_written():
    """A JSON entry is appended to management:gdpr_erasure_log after purge."""
    r = _make_redis()
    ip = "1.2.3.4"
    r.set(f"ban:{ip}", "value")

    result = purge_ip(ip, dry_run=False, r=r)

    log_len = r.llen("management:gdpr_erasure_log")
    assert log_len >= 1, "Audit log should have at least one entry"

    raw = r.lindex("management:gdpr_erasure_log", 0)
    assert raw is not None, "Audit log entry should not be None"

    entry = json.loads(raw)

    assert "timestamp" in entry, "Audit entry must include 'timestamp'"
    assert entry["ip"] == ip, f"Audit entry ip mismatch: {entry['ip']!r}"
    assert "keys_deleted" in entry, "Audit entry must include 'keys_deleted'"
    assert "keys_skipped_hll" in entry, "Audit entry must include 'keys_skipped_hll'"
    assert "zset_members_removed" in entry, "Audit entry must include 'zset_members_removed'"
    assert entry["keys_deleted"] == result["keys_deleted"]


# ---------------------------------------------------------------------------
# 7. Audit log flags dry-run runs
# ---------------------------------------------------------------------------

def test_audit_log_dry_run_flagged():
    """Audit log entry records dry_run=True when called with dry_run=True."""
    r = _make_redis()
    ip = "1.2.3.4"
    r.set(f"ban:{ip}", "value")

    purge_ip(ip, dry_run=True, r=r)

    log_len = r.llen("management:gdpr_erasure_log")
    assert log_len >= 1, "Audit log should have at least one entry even on dry run"

    raw = r.lindex("management:gdpr_erasure_log", 0)
    entry = json.loads(raw)

    assert entry.get("dry_run") is True, (
        f"Audit entry should have dry_run=true, got: {entry.get('dry_run')!r}"
    )


# ---------------------------------------------------------------------------
# 8. IPv6 canonical form
# ---------------------------------------------------------------------------

def test_ipv6_canonical_form():
    """Purging ::1 deletes the key keyed under the canonical compressed form."""
    r = _make_redis()
    # The canonical compressed form of the IPv6 loopback is "::1"
    canonical = "::1"
    r.set(f"ban:{canonical}", "value")

    result = purge_ip(canonical, dry_run=False, r=r)

    assert not r.exists(f"ban:{canonical}"), (
        "Canonical IPv6 key 'ban:::1' should have been deleted"
    )
    assert result["keys_deleted"] >= 1


# ---------------------------------------------------------------------------
# 9. Empty Redis — no error
# ---------------------------------------------------------------------------

def test_empty_redis_no_error():
    """Purging an IP with no keys in Redis succeeds and returns all-zero counts."""
    r = _make_redis()
    ip = "10.0.0.1"

    # Should not raise any exception
    result = purge_ip(ip, dry_run=False, r=r)

    assert result["keys_deleted"] == 0, f"Expected 0 keys_deleted, got {result['keys_deleted']}"
    assert result["zset_members_removed"] == 0, (
        f"Expected 0 zset_members_removed, got {result['zset_members_removed']}"
    )
    assert result["hll_skipped"] == 0, f"Expected 0 hll_skipped, got {result['hll_skipped']}"


# ---------------------------------------------------------------------------
# 10. Invalid IP causes non-zero exit
# ---------------------------------------------------------------------------

def test_invalid_ip_exits_nonzero():
    """Passing a non-IP string to main() should return exit code 1.

    ``main()`` returns an int (1 = error) without calling ``sys.exit`` itself;
    only the ``__main__`` guard wraps it in ``sys.exit``.  We therefore call
    ``main()`` directly and assert the return value is 1.
    """
    original_argv = sys.argv
    try:
        sys.argv = ["gdpr_delete.py", "--ip", "not-an-ip"]
        exit_code = main()
        assert exit_code == 1, f"Expected main() to return 1 for invalid IP, got {exit_code}"
    finally:
        sys.argv = original_argv
