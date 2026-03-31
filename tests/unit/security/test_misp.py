"""
Unit tests for Phase 46 MISP Provider.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.misp import MISPConfig, MISPProvider
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
    cache.misp_scores = MagicMock()
    cache.misp_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_misp_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="test", base_url="https://misp.test", attribute_score=20, score_cap=50)
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Test 1 attribute
    data = {"attribute_count": 1}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "misp"
    assert signal.score == 20
    assert "1 attribute" in signal.reason
    
    # Test multiple attributes
    data = {"attribute_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 40
    
    # Test score capping
    data = {"attribute_count": 10}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 50  # capped at 50
    
    # Test no attributes (should return None)
    data = {"attribute_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_misp_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="test", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "response": [
            {"id": "1", "value": "1.2.3.4", "type": "ip-dst"},
            {"id": "2", "value": "1.2.3.4", "type": "ip-dst"}
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
    assert call_args[0][0] == "misp:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["attribute_count"] == 2


@pytest.mark.asyncio
async def test_misp_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=False)
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    
    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_misp_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="test", base_url="https://misp.test", score_cap=100)
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock cache hit
    cached_data = {"attribute_count": 3}
    mock_local_cache.misp_scores.get.return_value = cached_data
    
    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 60  # 3 * 20
    
    # Verify no API lookup was triggered (cache hit)
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_misp_config_reload(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="old_key", base_url="https://old.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    
    new_config_dict = {
        "misp": {
            "enabled": True,
            "api_key": "new_key",
            "base_url": "https://new.test",
            "attribute_score": 25
        }
    }
    
    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.base_url == "https://new.test"
    assert provider._config.attribute_score == 25