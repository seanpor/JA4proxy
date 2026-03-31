"""
Unit tests for Phase 23 TI Providers (GreyNoise, AlienVault OTX).
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.security.greynoise import GreyNoiseProvider, GreyNoiseConfig
from src.security.alienvault import AlienVaultOTXProvider, OTXConfig
from src.security.models import RiskSignal


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    # Mock RedisBloom bf()
    client.bf = MagicMock()
    client.bf().add = AsyncMock(return_value=1)
    return client


@pytest.fixture
def mock_local_cache():
    cache = MagicMock()
    cache.greynoise_scores = MagicMock()
    cache.greynoise_scores.get.return_value = None
    cache.alienvault_scores = MagicMock()
    cache.alienvault_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_greynoise_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = GreyNoiseConfig(enabled=True, api_key="test", noise_score=25, riot_score_reduction=15)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Test noise signal
    data = {"noise": True, "riot": False, "classification": "benign"}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "greynoise"
    assert signal.score == 25
    assert "noise" in signal.reason
    
    # Test RIOT signal (reduction)
    data = {"noise": False, "riot": True, "classification": "unknown"}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == -15
    assert "RIOT" in signal.reason
    
    # Test combined
    data = {"noise": True, "riot": True, "classification": "malicious"}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 10 # 25 - 15


@pytest.mark.asyncio
async def test_alienvault_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = OTXConfig(enabled=True, api_key="test", pulse_score=10, score_cap=40)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Test 1 pulse
    data = {"pulse_count": 1}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "alienvault_otx"
    assert signal.score == 10
    
    # Test multiple pulses (capped)
    data = {"pulse_count": 5}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 40


@pytest.mark.asyncio
async def test_greynoise_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = GreyNoiseConfig(enabled=True, api_key="test")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"noise": True, "riot": False, "classification": "malicious"})
    
    # aiohttp session.get() returns an object that is an async context manager
    # We need to mock the context manager itself
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = mock_ctx
    
    await provider._process_lookup("1.1.1.1")
    
    # Verify Redis and Local Cache writes
    mock_redis.setex.assert_called()
    mock_local_cache.greynoise_scores.set.assert_called()


@pytest.mark.asyncio
async def test_ti_provider_get_signal_hot_path(mock_redis, mock_local_cache, mock_session):
    config = GreyNoiseConfig(enabled=True, api_key="test")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Local cache HIT
    mock_local_cache.greynoise_scores.get.return_value = {"noise": True, "riot": False}
    signal = provider.get_signal("1.1.1.1")
    assert signal is not None
    assert signal.score > 0
    
    # Local cache MISS
    mock_local_cache.greynoise_scores.get.return_value = None
    with patch("asyncio.create_task") as mock_task:
        signal = provider.get_signal("2.2.2.2")
        assert signal is None
        mock_task.assert_called()
