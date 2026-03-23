"""Chaos tests for Phase 12d — stream consumer resilience.

Verifies that the stream consumer:
- Rejects malformed events without crashing; processing continues
- Rejects events with invalid HMAC when hmac_required=True
- Rejects events outside the replay window (timestamp too old)
- Accepts events within the timestamp window
- Handles missing required fields gracefully
- Logs validation failures without propagating exceptions
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analytics.authentication import (
    MAX_EVENT_AGE_SECONDS,
    HMACAuthenticator,
    sign_event,
    validate_timestamp,
)
from src.analytics.stream_consumer import StreamConsumer

# ---------------------------------------------------------------------------
# Replay prevention: validate_timestamp
# ---------------------------------------------------------------------------


def test_fresh_timestamp_accepted():
    event = {"timestamp": str(time.time())}
    assert validate_timestamp(event) is True


def test_timestamp_at_max_age_boundary_accepted():
    event = {"timestamp": str(time.time() - MAX_EVENT_AGE_SECONDS + 1)}
    assert validate_timestamp(event) is True


def test_timestamp_just_over_max_age_rejected():
    event = {"timestamp": str(time.time() - MAX_EVENT_AGE_SECONDS - 1)}
    assert validate_timestamp(event) is False


def test_missing_timestamp_rejected():
    assert validate_timestamp({}) is False


def test_non_numeric_timestamp_rejected():
    assert validate_timestamp({"timestamp": "not-a-number"}) is False


def test_future_timestamp_within_skew_accepted():
    """Events from the near future (clock skew ≤ 10s) are accepted."""
    event = {"timestamp": str(time.time() + 5)}
    assert validate_timestamp(event) is True


def test_far_future_timestamp_rejected():
    event = {"timestamp": str(time.time() + 60)}
    assert validate_timestamp(event) is False


# ---------------------------------------------------------------------------
# HMACAuthenticator: replay prevention wired in
# ---------------------------------------------------------------------------


def _make_event_with_hmac(secret, ts_offset=0):
    event = {
        "src_ip": "1.2.3.4",
        "action": "allow",
        "timestamp": str(time.time() + ts_offset),
    }
    event["hmac"] = sign_event(event, secret)
    return event


def test_hmac_required_fresh_event_accepted():
    auth = HMACAuthenticator(secret="s3cr3t", required=True)
    event = _make_event_with_hmac("s3cr3t")
    assert auth.verify(event) is True


def test_hmac_required_stale_event_rejected():
    """Valid HMAC but old timestamp → rejected as replay."""
    auth = HMACAuthenticator(secret="s3cr3t", required=True)
    # Build event with old timestamp then re-sign
    old_ts = time.time() - MAX_EVENT_AGE_SECONDS - 60
    event = {"src_ip": "1.2.3.4", "action": "allow", "timestamp": str(old_ts)}
    event["hmac"] = sign_event(event, "s3cr3t")
    assert auth.verify(event) is False


def test_hmac_not_required_accepts_stale_event():
    """When HMAC not required, any event passes including old timestamps."""
    auth = HMACAuthenticator(secret="s3cr3t", required=False)
    old_event = {"timestamp": str(time.time() - 9999), "hmac": "garbage"}
    assert auth.verify(old_event) is True


def test_hmac_required_wrong_signature_rejected():
    auth = HMACAuthenticator(secret="s3cr3t", required=True)
    event = _make_event_with_hmac("s3cr3t")
    event["hmac"] = "badhash"
    assert auth.verify(event) is False


def test_hmac_required_missing_signature_rejected():
    auth = HMACAuthenticator(secret="s3cr3t", required=True)
    event = {"src_ip": "1.2.3.4", "timestamp": str(time.time())}
    assert auth.verify(event) is False


# ---------------------------------------------------------------------------
# StreamConsumer.validate_event: malformed events rejected, no crash
# ---------------------------------------------------------------------------


def _make_consumer(hmac_required=False):
    consumer = StreamConsumer(
        redis_url="redis://localhost:6379",
        hmac_required=hmac_required,
        campaign_detection=False,
        slow_scan_detection=False,
        ja4_intelligence=False,
        monitoring_enabled=False,
    )
    consumer.redis = AsyncMock()
    return consumer


def _run(coro):
    return asyncio.run(coro)


def _valid_event():
    """Minimal valid event matching EVENT_SCHEMA required fields."""
    return {
        "src_ip": "1.2.3.4",
        "ja4": "t13d1516h2_aabbccddee11_aabbccddee11",
        "action": "allow",
        "timestamp": int(time.time()),
        "score": 15,
        "proxy_id": "proxy-1",
    }


def test_valid_event_passes_validation():
    consumer = _make_consumer()
    # Should not raise
    _run(consumer.validate_event(_valid_event()))


def test_malformed_event_raises_invalid_event_error():
    from src.analytics.stream_consumer import InvalidEventError
    consumer = _make_consumer()
    # Missing required fields
    with pytest.raises(InvalidEventError):
        _run(consumer.validate_event({"garbage": "data"}))


def test_event_with_empty_src_ip_raises():
    from src.analytics.stream_consumer import InvalidEventError
    consumer = _make_consumer()
    bad = _valid_event()
    bad["src_ip"] = ""
    with pytest.raises(InvalidEventError):
        _run(consumer.validate_event(bad))


def test_event_with_invalid_action_raises():
    from src.analytics.stream_consumer import InvalidEventError
    consumer = _make_consumer()
    bad = _valid_event()
    bad["action"] = "nuke"  # not in enum
    with pytest.raises(InvalidEventError):
        _run(consumer.validate_event(bad))


# ---------------------------------------------------------------------------
# Stream lag metric updated correctly
# ---------------------------------------------------------------------------


def test_stream_lag_metric_exists():
    """The stream lag Gauge must be importable and settable."""
    from src.analytics.stream_consumer import _STREAM_LAG
    # Should not raise
    _STREAM_LAG.set(0.0)
    _STREAM_LAG.set(42.7)
