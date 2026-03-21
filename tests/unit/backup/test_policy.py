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
