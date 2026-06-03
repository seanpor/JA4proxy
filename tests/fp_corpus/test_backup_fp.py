"""
FP corpus tests for backup key-policy decisions.

Verifies that the backup inclusion/exclusion policy does not accidentally exclude
critical security keys (false negative — losing a ban or blacklist entry on restore)
or accidentally include transient state (false positive — inflating backup size with
ephemeral data that has no recovery value).

These tests use the KeyPolicy class directly, not real Redis, so they are fast
and deterministic.
"""

import pytest
from src.backup.policy import KeyPolicy


@pytest.fixture
def policy() -> KeyPolicy:
    return KeyPolicy()


# ---------------------------------------------------------------------------
# Critical security keys that must always be included
# ---------------------------------------------------------------------------


class TestCriticalKeysIncluded:
    """Verify that critical security keys are included in every backup."""

    def test_ja4_blacklist_included(self, policy: KeyPolicy) -> None:
        """ja4:blacklist SET is included in every backup."""
        assert policy.should_backup("ja4:blacklist") is True

    def test_ja4_whitelist_included(self, policy: KeyPolicy) -> None:
        """ja4:whitelist SET is included in every backup."""
        assert policy.should_backup("ja4:whitelist") is True

    def test_ban_ip_included(self, policy: KeyPolicy) -> None:
        """ban:{ip} keys are included in backup — these are active bans."""
        assert policy.should_backup("ban:1.2.3.4") is True
        assert policy.should_backup("ban:2001:db8::1") is True
        assert policy.should_backup("ban:10.0.0.0/24") is True

    def test_config_thresholds_included(self, policy: KeyPolicy) -> None:
        """config:* keys (thresholds, dial) are included in backup."""
        assert policy.should_backup("config:thresholds") is True
        assert policy.should_backup("config:dial") is True
        assert policy.should_backup("config:security_policy") is True

    def test_tor_exit_ips_included(self, policy: KeyPolicy) -> None:
        """tor:exit:ips SET is included in backup."""
        assert policy.should_backup("tor:exit:ips") is True

    def test_rdap_org_data_included(self, policy: KeyPolicy) -> None:
        """rdap:org:* enrichment data is included in backup."""
        assert policy.should_backup("rdap:org:cloudflare") is True
        assert policy.should_backup("rdap:ip:192.0.2.0/24") is True

    def test_analytics_findings_included(self, policy: KeyPolicy) -> None:
        """analytics:* findings (campaign detections) included in backup."""
        assert policy.should_backup("analytics:campaign:abc123") is True


# ---------------------------------------------------------------------------
# Transient keys that must NOT be included in backup
# ---------------------------------------------------------------------------


class TestTransientKeysExcluded:
    """Verify that transient, per-connection state is excluded from backup.

    These keys have no recovery value — they represent ephemeral state that
    will be rebuilt naturally after a restore. Including them wastes disk
    space and can cause stale state to persist across restores.
    """

    def test_session_keys_excluded(self, policy: KeyPolicy) -> None:
        """session:* per-connection tracking keys are NOT backed up."""
        assert policy.should_backup("session:ip:1.2.3.4") is False
        assert policy.should_backup("session:abc123def456") is False

    def test_lifespan_keys_excluded(self, policy: KeyPolicy) -> None:
        """lifespan:* TTL-based transient keys are NOT backed up."""
        assert policy.should_backup("lifespan:1.2.3.4") is False
        assert policy.should_backup("lifespan:2001:db8::1") is False

    def test_concurrent_connection_keys_excluded(self, policy: KeyPolicy) -> None:
        """concurrent:* counters are NOT backed up (they reset naturally)."""
        assert policy.should_backup("concurrent:1.2.3.4") is False

    def test_beacon_observation_keys_excluded(self, policy: KeyPolicy) -> None:
        """beacon:* short-term timing observations are NOT backed up."""
        assert policy.should_backup("beacon:1.2.3.4:t13d1516h2_abc") is False
        assert policy.should_backup("beacon:suspects") is False

    def test_bloom_filter_keys_excluded(self, policy: KeyPolicy) -> None:
        """bloom:* filter state is NOT backed up (rebuilt from source)."""
        assert policy.should_backup("bloom:abuseipdb_enriched") is False
        assert policy.should_backup("bloom:rdap_checked") is False

    def test_visitor_tracking_excluded(self, policy: KeyPolicy) -> None:
        """visitor:* return visitor tracking is NOT backed up."""
        assert policy.should_backup("visitor:1.2.3.4") is False

    def test_tls_alerts_excluded(self, policy: KeyPolicy) -> None:
        """tls_alerts:* transient alert counters are NOT backed up."""
        assert policy.should_backup("tls_alerts:1.2.3.4") is False


# ---------------------------------------------------------------------------
# Exclusion precedence: exclude wins over include for same key
# ---------------------------------------------------------------------------


class TestExclusionPrecedence:
    """Verify that exclusion patterns take precedence over inclusion patterns."""

    def test_unknown_key_not_backed_up(self, policy: KeyPolicy) -> None:
        """An unknown key that matches no pattern is NOT backed up (deny by default)."""
        assert policy.should_backup("rate:ip:1.2.3.4:60s") is False
        assert policy.should_backup("hll:cidr24:192.0.2.0") is False
        assert policy.should_backup("totally_unknown_key") is False
