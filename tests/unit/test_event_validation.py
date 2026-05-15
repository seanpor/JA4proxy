# Unit Tests for Event Validation
# Phase 12a: Foundation

import pytest

from src.analytics.stream_consumer import InvalidEventError
from src.analytics.validation import (
    is_valid_ip,
    is_valid_ja4,
    is_valid_proxy_id,
    validate_event_comprehensive,
)


class TestIPValidation:
    """Test IP address validation."""

    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("8.8.8.8") == True
        assert is_valid_ip("10.0.0.1") == True

    def test_valid_ipv6(self):
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True
        assert is_valid_ip("::1") == True
        assert is_valid_ip("fe80::1") == True

    def test_invalid_ips(self):
        assert is_valid_ip("999.999.999.999") == False
        assert is_valid_ip("not.an.ip") == False
        assert is_valid_ip("") == False
        assert is_valid_ip("192.168.1") == False


class TestProxyIDValidation:
    """Test proxy ID validation."""

    def test_valid_proxy_ids(self):
        assert is_valid_proxy_id("proxy-1") == True
        assert is_valid_proxy_id("proxy_1") == True
        assert is_valid_proxy_id("proxy123") == True
        assert is_valid_proxy_id("a" * 32) == True

    def test_invalid_proxy_ids(self):
        assert is_valid_proxy_id("") == False
        assert is_valid_proxy_id("a" * 33) == False
        assert is_valid_proxy_id("proxy@1") == False
        assert is_valid_proxy_id("proxy space") == False


class TestJA4Validation:
    """Test JA4 fingerprint validation."""

    def test_valid_ja4(self):
        assert is_valid_ja4("t13d1520h3_abc123") == True
        assert is_valid_ja4("a" * 64) == True
        assert is_valid_ja4("test_ja4-fingerprint") == True

    def test_invalid_ja4(self):
        assert is_valid_ja4("") == False
        assert is_valid_ja4("a" * 65) == False
        assert is_valid_ja4("ja4@fingerprint") == False
        assert is_valid_ja4("ja4 fingerprint") == False


class TestComprehensiveValidation:
    """Test comprehensive event validation."""

    @pytest.mark.asyncio
    async def test_valid_event(self):
        valid_event = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        # Should not raise an exception - use large tolerance for testing
        result = await validate_event_comprehensive(
            valid_event, timestamp_tolerance=999999999
        )
        assert result == True

    @pytest.mark.asyncio
    async def test_invalid_timestamp(self):
        event = {
            "timestamp": 0,  # Too old
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        with pytest.raises(ValueError, match="Timestamp too old"):
            await validate_event_comprehensive(event)

    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        event = {
            "timestamp": 1234567890.0,
            "src_ip": "not.an.ip",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        with pytest.raises(ValueError, match="Invalid source IP"):
            await validate_event_comprehensive(event, timestamp_tolerance=999999999)

    @pytest.mark.asyncio
    async def test_invalid_score(self):
        event = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 150,  # Too high
            "proxy_id": "proxy-1",
        }

        with pytest.raises(ValueError, match="Score must be between"):
            await validate_event_comprehensive(event, timestamp_tolerance=999999999)

    @pytest.mark.asyncio
    async def test_invalid_action(self):
        event = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "invalid_action",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        with pytest.raises(ValueError, match="Invalid action"):
            await validate_event_comprehensive(event, timestamp_tolerance=999999999)

    @pytest.mark.asyncio
    async def test_invalid_proxy_id(self):
        event = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "invalid@proxy",
        }

        with pytest.raises(ValueError, match="Invalid proxy ID"):
            await validate_event_comprehensive(event, timestamp_tolerance=999999999)

    @pytest.mark.asyncio
    async def test_invalid_ja4(self):
        event = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "invalid ja4",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        with pytest.raises(ValueError, match="Invalid JA4"):
            await validate_event_comprehensive(event, timestamp_tolerance=999999999)
