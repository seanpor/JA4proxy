"""
Unit tests for Phase 54 Behavioral Attribution.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.security.behavioral import BehavioralAnalyzer
from src.security.models import ConnectionContext, RiskSignal


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.sadd = AsyncMock(return_value=1)
    client.scard = AsyncMock(return_value=1)
    client.zadd = AsyncMock(return_value=1)
    client.zrange = AsyncMock(return_value=[])
    client.zremrangebyscore = AsyncMock(return_value=0)
    client.expire = AsyncMock(return_value=True)
    return client


@pytest.fixture
def analyzer(mock_redis):
    config = {
        "behavioral": {
            "enabled": True,
            "probing_unique_sni_threshold": 3,
            "burst_count_threshold": 3,
            "burst_window_ms": 100,
        }
    }
    return BehavioralAnalyzer(mock_redis, config)


@pytest.mark.asyncio
async def test_sequential_probing_detection(analyzer, mock_redis):
    afp = "test_fp"
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="ja4", sni="host1.com")

    # 1. First probe
    mock_redis.scard.return_value = 1
    signals = await analyzer.get_signals(ctx, afp)
    assert len(signals) == 0

    # 2. Second probe
    mock_redis.scard.return_value = 2
    ctx.sni = "host2.com"
    signals = await analyzer.get_signals(ctx, afp)
    assert len(signals) == 0

    # 3. Third probe -> Hit threshold (3)
    mock_redis.scard.return_value = 3
    ctx.sni = "host3.com"
    signals = await analyzer.get_signals(ctx, afp)
    assert len(signals) == 1
    assert signals[0].name == "behavioral_probing"
    assert signals[0].score == 30


@pytest.mark.asyncio
async def test_coordinated_burst_detection(analyzer, mock_redis):
    afp = "test_fp"
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="ja4", sni="target.com")

    # Mock 3 unique IPs in the window
    mock_redis.zrange.return_value = [b"1.1.1.1:123", b"2.2.2.2:124", b"3.3.3.3:125"]

    signals = await analyzer.get_signals(ctx, afp)

    # Verify signal generated
    assert any(s.name == "behavioral_burst" for s in signals)
    burst_signal = next(s for s in signals if s.name == "behavioral_burst")
    assert burst_signal.score == 25
    assert "3 IPs" in burst_signal.reason


@pytest.mark.asyncio
async def test_fingerprint_drift_logging(analyzer, mock_redis, caplog):
    afp = "test_fp"
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="new_ja4", sni="host.com")

    # Mock NEW fingerprint (sadd returns 1)
    mock_redis.sadd.side_effect = [1, 1]  # 1 for probing set, 1 for known_ja4 set

    with caplog.at_level("WARNING"):
        await analyzer.get_signals(ctx, afp)

    assert "First time seeing this JA4 fingerprint" in caplog.text
    assert "new_ja4" in caplog.text


@pytest.mark.asyncio
async def test_disabled_analyzer(mock_redis):
    config = {"behavioral": {"enabled": False}}
    analyzer = BehavioralAnalyzer(mock_redis, config)

    signals = await analyzer.get_signals(
        ConnectionContext(client_ip="1.1.1.1", ja4="ja4"), "fp"
    )
    assert len(signals) == 0
    mock_redis.sadd.assert_not_called()


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fingerprint_drift_empty_ja4_returns_early(mock_redis):
    """Line 136: _check_fingerprint_drift() returns immediately when ja4 is empty.
    So what: if this guard is missing, sadd is called with an empty string key —
    poisoning the known-ja4 set and potentially suppressing future drift alerts
    for every new fingerprint that would have matched the empty-string sentinel."""
    config = {"behavioral": {"enabled": True}}
    analyzer = BehavioralAnalyzer(mock_redis, config)
    # Call directly with empty ja4 — should return without touching Redis
    await analyzer._check_fingerprint_drift("")
    mock_redis.sadd.assert_not_called()
