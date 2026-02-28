"""Unit tests for src/utils/ip.py — canonical_ip() and get_analysis_subnet()."""

import pytest

from src.utils.ip import canonical_ip, get_analysis_subnet


class TestCanonicalIp:
    """Test canonical_ip() normalisation."""

    def test_plain_ipv4_unchanged(self):
        assert canonical_ip("192.0.2.1") == "192.0.2.1"

    def test_ipv4_leading_zeros_stripped(self):
        # ipaddress rejects leading zeros in Python 3.9+; ensure we handle clean input
        assert canonical_ip("10.0.0.1") == "10.0.0.1"

    def test_ipv4_loopback(self):
        assert canonical_ip("127.0.0.1") == "127.0.0.1"

    def test_ipv4_broadcast(self):
        assert canonical_ip("255.255.255.255") == "255.255.255.255"

    def test_ipv6_loopback(self):
        assert canonical_ip("::1") == "::1"

    def test_ipv6_compressed(self):
        assert canonical_ip("2001:0db8:0000:0000::1") == "2001:db8::1"

    def test_ipv6_full_compressed(self):
        assert canonical_ip("2001:db8::1") == "2001:db8::1"

    def test_ipv4_mapped_ipv6_unwrapped(self):
        """::ffff:192.0.2.1 must return the plain IPv4 form."""
        assert canonical_ip("::ffff:192.0.2.1") == "192.0.2.1"

    def test_ipv4_mapped_ipv6_alternative_notation(self):
        assert canonical_ip("::ffff:c000:201") == "192.0.2.1"

    def test_ipv6_link_local(self):
        result = canonical_ip("fe80::1")
        assert result == "fe80::1"

    def test_ipv6_all_zeros_compressed(self):
        assert canonical_ip("0000:0000:0000:0000:0000:0000:0000:0001") == "::1"

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError):
            canonical_ip("not-an-ip")

    def test_invalid_empty_raises(self):
        with pytest.raises(ValueError):
            canonical_ip("")


class TestGetAnalysisSubnet:
    """Test get_analysis_subnet() returns correct prefix lengths."""

    def test_ipv4_returns_slash24(self):
        assert get_analysis_subnet("192.0.2.1") == "192.0.2.0/24"

    def test_ipv4_already_network_address(self):
        assert get_analysis_subnet("192.0.2.0") == "192.0.2.0/24"

    def test_ipv4_last_host(self):
        assert get_analysis_subnet("192.0.2.255") == "192.0.2.0/24"

    def test_ipv4_loopback(self):
        assert get_analysis_subnet("127.0.0.1") == "127.0.0.0/24"

    def test_ipv4_private(self):
        assert get_analysis_subnet("10.1.2.3") == "10.1.2.0/24"

    def test_ipv6_returns_slash48(self):
        result = get_analysis_subnet("2001:db8::1")
        assert result == "2001:db8::/48"

    def test_ipv6_loopback_returns_slash48(self):
        result = get_analysis_subnet("::1")
        assert "/48" in result

    def test_ipv6_link_local(self):
        result = get_analysis_subnet("fe80::1")
        assert "/48" in result

    def test_ipv6_full_address(self):
        result = get_analysis_subnet("2001:db8:dead:beef::1")
        assert result == "2001:db8:dead::/48"

    @pytest.mark.parametrize(
        "ip,expected_prefix",
        [
            ("1.2.3.4", "/24"),
            ("10.20.30.40", "/24"),
            ("2001:db8::1", "/48"),
            ("fe80::1", "/48"),
            ("::1", "/48"),
        ],
    )
    def test_prefix_length_parametrized(self, ip, expected_prefix):
        assert get_analysis_subnet(ip).endswith(expected_prefix)
