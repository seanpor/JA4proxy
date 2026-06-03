"""
Test suite for backup key-policy contract.
Tests include/exclude precedence and forbidden key exclusion.
"""

import pytest
from src.backup.policy import KeyPolicy


def test_include_pattern_matching():
    """Test that include patterns match expected keys."""
    policy = KeyPolicy()
    assert policy.should_backup("config:dial")
    assert policy.should_backup("ban:192.168.1.1")


def test_exclude_pattern_matching():
    """Test that exclude patterns exclude expected keys."""
    policy = KeyPolicy()
    assert not policy.should_backup("session:ip:192.168.1.1:ja4:abc123")
    assert not policy.should_backup("lifespan:192.168.1.1")


def test_forbidden_key_exclusion():
    """Test that forbidden keys are always excluded."""
    policy = KeyPolicy()
    assert not policy.should_backup("backup:latest")
    assert not policy.should_backup("backup:last_success")


def test_include_exclude_precedence():
    """Test that include patterns take precedence over exclude patterns."""
    policy = KeyPolicy()
    assert policy.should_backup("config:dial")
    assert not policy.should_backup("session:ip:192.168.1.1:ja4:abc123")


def test_deterministic_ordering():
    """Test that key ordering is deterministic."""
    policy = KeyPolicy()
    keys = ["config:dial", "ban:192.168.1.1", "session:ip:192.168.1.1:ja4:abc123"]
    ordered = policy.order_keys(keys)
    assert ordered == sorted(keys)


def test_abuseipdb_score_not_in_backup():
    """AbuseIPDB score keys must not be backed up.

    These are external reputation scores re-fetchable from the API.
    worker.py _KEY_PATTERNS_NEVER_BACKUP blocks abuseipdb:* as a safety net,
    and policy.py must not list abuseipdb:score:* in include_patterns either.
    """
    policy = KeyPolicy()
    assert not policy.should_backup("abuseipdb:score:1.2.3.4")


def test_attribution_profile_is_backed_up():
    """attribution:profile:* keys must be backed up.

    These hold 90-day-TTL attacker fingerprint correlation profiles built up
    over weeks; they must survive a Redis failure.
    """
    policy = KeyPolicy()
    assert policy.should_backup("attribution:profile:abc123def")


def test_attribution_ips_is_backed_up():
    """attribution:ips:* keys must be backed up.

    These hold 30-day-TTL IP sets correlated to a JA4 fingerprint; losing
    them requires weeks of re-accumulation after a Redis failure.
    """
    policy = KeyPolicy()
    assert policy.should_backup("attribution:ips:abc123def")
