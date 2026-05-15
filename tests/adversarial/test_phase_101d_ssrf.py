"""Tests for PHASE_101d: SSRF mitigation.

H6 — SSRF mitigation via is_publicly_routable_ip()
"""

import pytest

from src.analytics.ti_feeds.safe_resolver import (
    is_publicly_routable_ip,
    resolve_host_safe,
)


class TestSSRFProtection:
    """Test SSRF protection functions."""

    def test_is_publicly_routable_ip_exists(self):
        """is_publicly_routable_ip should exist."""
        assert callable(is_publicly_routable_ip)

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("8.8.8.8", True),  # Public DNS
            ("1.2.3.4", True),  # Public
            ("10.0.0.1", False),  # RFC1918
            ("172.16.0.1", False),  # RFC1918
            ("192.168.0.1", False),  # RFC1918
            ("127.0.0.1", False),  # Loopback
            ("169.254.169.254", False),  # Link-local AWS metadata
            ("::1", False),  # IPv6 loopback
            ("fc00::1", False),  # IPv6 private
        ],
    )
    def test_public_ip_check(self, ip, expected):
        """Check that public/private IP detection works."""
        assert is_publicly_routable_ip(ip) == expected

    def test_resolve_host_safe_blocks_private(self):
        """resolve_host_safe should raise on private IP."""
        with pytest.raises(ValueError, match="SSRF blocked"):
            resolve_host_safe("169.254.169.254", 80)

    def test_resolve_host_safe_allows_public(self):
        """resolve_host_safe should allow public IPs."""
        result = resolve_host_safe("google.com", 443)
        assert len(result) > 0
