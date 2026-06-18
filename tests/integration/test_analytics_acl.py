"""Integration test: analytics Redis ACL enforcement.

This test requires a real Redis instance with ACL configuration loaded.
It is skipped in unit test runs (requires INTEGRATION_REDIS_URL env var).

To run:
  INTEGRATION_REDIS_URL=redis://analytics:<pwd>@localhost:6379/0 pytest tests/integration/test_analytics_acl.py -v
"""
import os
import pytest
import redis as redis_sync

INTEGRATION_REDIS_URL = os.getenv("INTEGRATION_REDIS_URL")
requires_integration_redis = pytest.mark.skipif(
    not INTEGRATION_REDIS_URL,
    reason="INTEGRATION_REDIS_URL not set — skipping ACL integration test",
)


@requires_integration_redis
def test_analytics_can_write_analytics_key():
    """Analytics ACL user can write analytics:* keys."""
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    r.hset("analytics:finding:acl-test", mapping={"confidence": "0.95"})
    assert r.hget("analytics:finding:acl-test", "confidence") == b"0.95"
    r.delete("analytics:finding:acl-test")


@requires_integration_redis
def test_analytics_cannot_write_config_key():
    """Analytics ACL user MUST NOT be able to write config:dial.

    If this test fails, the Redis ACL is not enforced and the blocklist
    poisoning attack described in PHASE_231.md (Analytics Trust Boundary) is possible.
    """
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    with pytest.raises(redis_sync.exceptions.NoPermissionError):
        r.set("config:dial", "50")


@requires_integration_redis
def test_analytics_cannot_write_blocklist():
    """Analytics ACL user MUST NOT be able to write ja4:blocklist."""
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    with pytest.raises(redis_sync.exceptions.NoPermissionError):
        r.sadd("ja4:blocklist", "t13d1516h2_test")
