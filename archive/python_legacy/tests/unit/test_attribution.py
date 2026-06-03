"""
Unit tests for Phase 32 Attacker Attribution.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.security.attribution import AttackerProfile, AttributionManager
from src.security.models import ConnectionContext, RiskSignal


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.sadd = AsyncMock(return_value=1)
    client.expire = AsyncMock(return_value=True)
    return client


@pytest.fixture
def manager(mock_redis):
    config = {"attribution": {"enabled": True, "min_ips_for_suspicious": 2}}
    return AttributionManager(mock_redis, config)


def test_compute_fingerprint(manager):
    ctx = ConnectionContext(
        client_ip="1.1.1.1",
        ja4="t13d151617_deadbeef",
        ja4x="cert_hash",
        tcp_ja4t="225_8192",
    )
    fp1 = manager.compute_fingerprint(ctx)
    assert len(fp1) == 16

    # Same inputs -> same fingerprint
    fp2 = manager.compute_fingerprint(ctx)
    assert fp1 == fp2

    # Different JA4 -> different fingerprint
    ctx.ja4 = "different"
    fp3 = manager.compute_fingerprint(ctx)
    assert fp1 != fp3


@pytest.mark.asyncio
async def test_update_correlation_new_profile(manager, mock_redis):
    afp = "test_fp"
    ip = "1.2.3.4"

    await manager._update_correlation(afp, ip)

    # Verify Redis interactions
    mock_redis.sadd.assert_called_with(f"attribution:ips:{afp}", ip)
    mock_redis.set.assert_called()

    # Check what was saved
    call_args = mock_redis.set.call_args
    saved_json = call_args[0][1]
    profile = json.loads(saved_json)
    assert profile["fingerprint"] == afp
    assert ip in profile["associated_ips"]
    assert profile["category"] == "unknown"


@pytest.mark.asyncio
async def test_update_correlation_promotion(manager, mock_redis):
    afp = "test_fp"
    ip1 = "1.1.1.1"
    ip2 = "2.2.2.2"

    # Mock existing profile with 1 IP
    existing_profile = AttackerProfile(fingerprint=afp, associated_ips={ip1})
    mock_redis.get.return_value = existing_profile.to_json()

    await manager._update_correlation(afp, ip2)

    # Should be promoted to suspicious because min_ips_for_suspicious=2
    call_args = mock_redis.set.call_args
    saved_json = call_args[0][1]
    profile = json.loads(saved_json)
    assert profile["category"] == "suspicious"
    assert "multi_ip_actor" in profile["tags"]


@pytest.mark.asyncio
async def test_get_signal_malicious(manager, mock_redis):
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="ja4")
    afp = manager.compute_fingerprint(ctx)

    # Mock malicious profile
    profile = AttackerProfile(fingerprint=afp, category="malicious", tags=["botnet_a"])
    mock_redis.get.return_value = profile.to_json()

    signal = await manager.get_signal(ctx)

    assert signal is not None
    assert signal.name == "attribution_malicious"
    assert signal.score == 40
    assert "botnet_a" in signal.reason


@pytest.mark.asyncio
async def test_get_signal_unknown(manager, mock_redis):
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="ja4")

    # Mock unknown profile
    mock_redis.get.return_value = None

    signal = await manager.get_signal(ctx)
    assert signal is None


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_signal_disabled_returns_none(mock_redis):
    """get_signal() returns None immediately when attribution is disabled (line 97).
    So what: if this guard is missing, the disabled manager still issues Redis
    queries and creates background correlation tasks, wasting resources."""
    config = {"attribution": {"enabled": False}}
    mgr = AttributionManager(mock_redis, config)
    ctx = ConnectionContext(client_ip="1.1.1.1", ja4="ja4")
    result = await mgr.get_signal(ctx)
    assert result is None
    mock_redis.get.assert_not_called()


@pytest.mark.asyncio
async def test_get_signal_suspicious_profile_returns_signal(mock_redis):
    """get_signal() returns attribution_suspicious signal for suspicious profiles (lines 118-126).
    So what: if this branch is missing, suspicious actors are silently ignored —
    only explicitly malicious actors contribute to the composite score, leaving a
    gap for actors that haven't yet been confirmed as malicious."""
    config = {"attribution": {"enabled": True}}
    mgr = AttributionManager(mock_redis, config)
    ctx = ConnectionContext(client_ip="5.5.5.5", ja4="t13d...")
    afp = mgr.compute_fingerprint(ctx)

    profile = AttackerProfile(fingerprint=afp, category="suspicious")
    mock_redis.get.return_value = profile.to_json()

    result = await mgr.get_signal(ctx)
    assert result is not None
    assert result.name == "attribution_suspicious"
    assert result.score == 20
    assert afp in result.reason


@pytest.mark.asyncio
async def test_get_signal_unknown_profile_returns_none(mock_redis):
    """get_signal() returns None for an unknown/research category profile (line 126).
    So what: an attributed actor that hasn't been classified yet must not emit a
    signal — if this return is missing, unclassified actors could accidentally
    pass through the malicious check and fall into the wrong branch."""
    config = {"attribution": {"enabled": True}}
    mgr = AttributionManager(mock_redis, config)
    ctx = ConnectionContext(client_ip="9.9.9.9", ja4="t13d...")
    afp = mgr.compute_fingerprint(ctx)

    # Profile exists but is neither malicious nor suspicious
    profile = AttackerProfile(fingerprint=afp, category="research")
    mock_redis.get.return_value = profile.to_json()

    result = await mgr.get_signal(ctx)
    assert result is None
