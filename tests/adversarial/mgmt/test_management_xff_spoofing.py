"""Adversarial security test for X-Forwarded-For spoofing in Management API auth.

Tests against historical pentest finding L4-028:
Ensures that an attacker cannot spoof arbitrary client IPs to evade rate limits,
bypass account lockouts, or inject arbitrary strings into Redis audit keys by injecting
leftmost X-Forwarded-For headers through trusted upstream reverse proxies.
"""

from unittest.mock import MagicMock, patch

import pytest

from management.api.auth import _client_ip


class TestXFFSpoofingDefense:
    """Adversarial verification of XFF parsing resilience."""

    def test_leftmost_spoofed_ip_is_ignored_when_peer_is_trusted(self):
        """Attacker sending 'X-Forwarded-For: 1.2.3.4' through trusted HAProxy (10.0.0.1)

        where HAProxy appends attacker IP '198.51.100.22'. The real client IP is
        198.51.100.22, NOT 1.2.3.4.
        """
        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"X-Forwarded-For": "1.2.3.4, 198.51.100.22"}

        with patch.dict(
            "os.environ", {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        assert ip == "198.51.100.22", (
            f"Expected rightmost untrusted IP '198.51.100.22', but got '{ip}' (leftmost spoofed IP)"
        )

    def test_multi_hop_trusted_proxy_chain(self):
        """Chain of trusted proxies (10.0.0.2 -> 10.0.0.1) traversing to management API.

        Attacker spoofed 8.8.8.8, real client is 203.0.113.195, followed by trusted proxy 10.0.0.2.
        Header: '8.8.8.8, 203.0.113.195, 10.0.0.2'
        Peer: 10.0.0.1
        """
        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {
            "X-Forwarded-For": "8.8.8.8, 203.0.113.195, 10.0.0.2"
        }

        with patch.dict(
            "os.environ", {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        assert ip == "203.0.113.195"

    def test_non_ip_garbage_string_falls_back_to_socket_ip(self):
        """Attacker injecting non-IP string to pollute Redis keys."""
        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"X-Forwarded-For": "invalid_ip_garbage!@#"}

        with patch.dict(
            "os.environ", {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        # Must reject invalid_ip_garbage and fall back to trusted socket host
        assert ip == "10.0.0.1"

    def test_whitespace_and_mixed_delimiters(self):
        """Malformed whitespace in header."""
        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {
            "X-Forwarded-For": "  1.1.1.1  ,   198.51.100.77  , 10.0.0.5 "
        }

        with patch.dict(
            "os.environ", {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        assert ip == "198.51.100.77"
