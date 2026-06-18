"""Tests for CIDR expansion logic in management/api/routes/bans.py."""

import pytest

try:
    from management.api.routes.bans import _expand_cidr
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def test_valid_slash24_expands_to_254_hosts():
    """/24 produces 254 usable host addresses (excludes .0 and .255)."""
    ips = _expand_cidr("203.0.113.0/24", allow_private=False)
    assert len(ips) == 254
    assert "203.0.113.1" in ips
    assert "203.0.113.254" in ips
    assert "203.0.113.0" not in ips
    assert "203.0.113.255" not in ips


def test_private_range_rejected_by_default():
    """10.0.0.0/8 is rejected without allow_private=True."""
    with pytest.raises(ValueError, match="private"):
        _expand_cidr("10.0.0.0/8", allow_private=False)


def test_private_range_allowed_with_flag():
    """/24 in a private range is allowed when allow_private=True."""
    ips = _expand_cidr("10.0.0.0/24", allow_private=True)
    assert len(ips) == 254


def test_slash8_rejected_too_large():
    """/8 has 16M addresses — rejected regardless of allow_private."""
    with pytest.raises(ValueError, match="too large|collateral"):
        _expand_cidr("1.0.0.0/8", allow_private=False)


def test_slash16_boundary_accepted():
    """/16 is the maximum accepted (65,534 hosts)."""
    ips = _expand_cidr("203.0.0.0/16", allow_private=False)
    assert len(ips) > 0


def test_single_ip_as_slash32_works():
    """A single IP (no CIDR notation) expands to one address."""
    ips = _expand_cidr("203.0.113.42", allow_private=False)
    assert ips == ["203.0.113.42"]


def test_invalid_ip_raises_valueerror():
    with pytest.raises(ValueError, match="Invalid IP"):
        _expand_cidr("not.an.ip.address", allow_private=False)


def test_loopback_rejected():
    """Loopback range 127.0.0.0/8 rejected by default."""
    with pytest.raises(ValueError, match="private"):
        _expand_cidr("127.0.0.0/24", allow_private=False)
