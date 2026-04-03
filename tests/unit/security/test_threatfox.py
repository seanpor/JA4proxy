"""
Unit tests for Phase 46 ThreatFox Provider.
Phase 59a: circuit breaker and retry wiring added.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
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


# ---------------------------------------------------------------------------
# Phase 59a: circuit breaker and retry tests
# ---------------------------------------------------------------------------


def _make_ctx(status: int, body: dict):
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=body)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


_TF_OK_BODY = {
    "data": [
        {"id": "1", "ioc": "1.2.3.4", "threat_type": "malware"},
    ]
}


@pytest.mark.asyncio
async def test_threatfox_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_threatfox_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("threatfox", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_threatfox_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("threatfox")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = ThreatFoxConfig(enabled=True, api_key="key")
        provider = ThreatFoxProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


@pytest.mark.asyncio
async def test_threatfox_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = ThreatFoxConfig(enabled=True, api_key="key")
        provider = ThreatFoxProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.post.side_effect = OSError("connection refused")
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


@pytest.mark.asyncio
async def test_threatfox_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; session.post called 3 times."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, _TF_OK_BODY)
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OSError("transient error")
        return success_ctx

    mock_session.post.side_effect = side_effect

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    assert call_count == 3
    mock_redis.setex.assert_called_once()