"""
Unit tests for Phase 46 ThreatFox Provider.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.threatfox import ThreatFoxConfig, ThreatFoxProvider
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
    cache.threatfox_scores = MagicMock()
    cache.threatfox_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_threatfox_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="test", ioc_score=25, score_cap=60)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Test 1 IOC
    data = {"ioc_count": 1}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "threatfox"
    assert signal.score == 25
    assert "1 IOC" in signal.reason
    
    # Test multiple IOCs
    data = {"ioc_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 50
    
    # Test score capping
    data = {"ioc_count": 3}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 60  # capped at 60
    
    # Test no IOCs (should return None)
    data = {"ioc_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_threatfox_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="test")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "query": "search_ioc",
        "data": [
            {"id": "1", "ioc": "1.2.3.4", "threat_type": "malware"},
            {"id": "2", "ioc": "1.2.3.4", "threat_type": "botnet"}
        ]
    })
    
    # aiohttp session.post() returns an object that is an async context manager
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx
    
    # Test the lookup process
    await provider._process_lookup("1.2.3.4")
    
    # Verify Redis was called to cache the result
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "threatfox:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["ioc_count"] == 2


@pytest.mark.asyncio
async def test_threatfox_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=False)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    
    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_threatfox_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="test", score_cap=100)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock cache hit
    cached_data = {"ioc_count": 2}
    mock_local_cache.threatfox_scores.get.return_value = cached_data
    
    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 50  # 2 * 25
    
    # Verify no API lookup was triggered (cache hit)
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_threatfox_config_reload(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="old_key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    
    new_config_dict = {
        "threatfox": {
            "enabled": True,
            "api_key": "new_key",
            "ioc_score": 30
        }
    }
    
    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.ioc_score == 30