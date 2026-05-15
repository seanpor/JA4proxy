# Unit Tests for HMAC Authentication
# Phase 12a: Foundation

import time

import pytest

from src.analytics.authentication import HMACAuthenticator, sign_event, verify_hmac


class TestHMACFunctions:
    """Test HMAC signing and verification functions."""

    def test_sign_and_verify(self):
        secret = "test_secret"
        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        # Sign the event
        signature = sign_event(event_data, secret)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest

        # Verify the signature
        event_with_hmac = event_data.copy()
        event_with_hmac["hmac"] = signature

        assert verify_hmac(event_with_hmac, secret, signature) == True

    def test_verify_invalid_signature(self):
        secret = "test_secret"
        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            "hmac": "invalid_signature",
        }

        assert verify_hmac(event_data, secret, "invalid_signature") == False

    def test_verify_wrong_secret(self):
        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        # Sign with one secret
        signature = sign_event(event_data, "secret1")

        # Try to verify with different secret
        event_with_hmac = event_data.copy()
        event_with_hmac["hmac"] = signature

        assert verify_hmac(event_with_hmac, "secret2", signature) == False

    def test_signature_consistency(self):
        """Test that same data produces same signature."""
        secret = "test_secret"
        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        # Sign twice
        signature1 = sign_event(event_data, secret)
        signature2 = sign_event(event_data, secret)

        assert signature1 == signature2


class TestHMACAuthenticator:
    """Test HMACAuthenticator class."""

    def test_sign_method(self):
        secret = "test_secret"
        authenticator = HMACAuthenticator(secret)

        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        signed_event = authenticator.sign(event_data)

        assert "hmac" in signed_event
        assert len(signed_event["hmac"]) == 64
        assert signed_event["timestamp"] == event_data["timestamp"]
        assert signed_event["src_ip"] == event_data["src_ip"]

    def test_verify_method(self):
        secret = "test_secret"
        authenticator = HMACAuthenticator(secret)

        event_data = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        # Sign and verify
        signed_event = authenticator.sign(event_data)
        assert authenticator.verify(signed_event) == True

    def test_verify_invalid_event(self):
        secret = "test_secret"
        authenticator = HMACAuthenticator(secret)

        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            "hmac": "invalid_signature",
        }

        assert authenticator.verify(event_data) == False

    def test_verify_missing_hmac(self):
        secret = "test_secret"
        authenticator = HMACAuthenticator(secret)

        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            # No hmac field
        }

        assert authenticator.verify(event_data) == False

    def test_not_required_mode(self):
        secret = "test_secret"
        authenticator = HMACAuthenticator(secret, required=False)

        event_data = {
            "timestamp": 1234567890.0,
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            # No hmac field
        }

        # Should return True when not required
        assert authenticator.verify(event_data) == True

    def test_empty_secret(self):
        authenticator = HMACAuthenticator("")

        event_data = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
        }

        signed_event = authenticator.sign(event_data)
        assert authenticator.verify(signed_event) == True


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestValidateTimestampCoverageGaps:
    """Cover lines 26, 29-30 in src/analytics/authentication.py.

    So what: these paths prevent replay attacks — if validate_timestamp silently
    accepts None or non-numeric timestamps, any old or forged event passes HMAC
    verification and could inject false threat signals.
    """

    def test_missing_timestamp_returns_false(self):
        """Event with no timestamp key → ts is None → return False (line 26).
        So what: a proxy-generated event without a timestamp field must be
        rejected — a silent accept would skip the replay-protection window."""
        from src.analytics.authentication import validate_timestamp

        result = validate_timestamp({"src_ip": "1.2.3.4", "action": "allow"})
        assert result is False

    def test_non_numeric_timestamp_returns_false(self):
        """Non-numeric timestamp string → float() raises → return False (lines 29-30).
        So what: an attacker injecting 'timestamp: hacked' must be rejected;
        if float() raises uncaught, the auth middleware crashes instead."""
        from src.analytics.authentication import validate_timestamp

        result = validate_timestamp({"timestamp": "not_a_number"})
        assert result is False

    def test_none_timestamp_value_returns_false(self):
        """Explicit None timestamp → ts is None → return False (line 26).
        So what: an explicitly null timestamp must not slip through as zero."""
        from src.analytics.authentication import validate_timestamp

        result = validate_timestamp({"timestamp": None})
        assert result is False


class TestHMACWithStreamConsumer:
    """Test HMAC integration with stream consumer."""

    def test_stream_consumer_hmac_validation(self):
        # Test that stream consumer can be initialized with HMAC
        from src.analytics.stream_consumer import StreamConsumer

        secret = "test_secret"
        consumer = StreamConsumer(
            redis_url="redis://localhost", hmac_secret=secret, hmac_required=True
        )

        assert consumer.hmac_auth.secret == secret
        assert consumer.hmac_auth.required == True
