"""
Unit tests for Phase 46 VirusTotal Provider.
Phase 59a: circuit breaker and retry wiring added.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.models import RiskSignal
from src.security.virustotal import VirusTotalConfig, VirusTotalProvider


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
    cache.virustotal_scores = MagicMock()
    cache.virustotal_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_virustotal_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(
        enabled=True, 
        api_key="test", 
        malicious_score=30, 
        suspicious_score=15, 
        score_cap=70
    )
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Test only malicious detections
    data = {"malicious_count": 1, "suspicious_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "virustotal"
    assert signal.score == 30
    assert "1 malicious detection" in signal.reason
    
    # Test only suspicious detections
    data = {"malicious_count": 0, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 30  # 2 * 15
    assert "2 suspicious detection" in signal.reason
    
    # Test mixed detections
    data = {"malicious_count": 1, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 60  # 30 + 30
    assert "1 malicious detection" in signal.reason
    assert "2 suspicious detection" in signal.reason
    
    # Test score capping
    data = {"malicious_count": 3, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 70  # capped at 70
    
    # Test no detections (should return None)
    data = {"malicious_count": 0, "suspicious_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_virustotal_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "undetected": 50,
                    "harmless": 10
                }
            }
        }
    })
    
    # aiohttp session.get() returns an object that is an async context manager
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = mock_ctx
    
    # Test the lookup process
    await provider._process_lookup("1.2.3.4")
    
    # Verify Redis was called to cache the result
    mock_redis.setex.assert_called()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "virustotal:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["malicious_count"] == 3
    assert cached_data["suspicious_count"] == 1


@pytest.mark.asyncio
async def test_virustotal_quota_management(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", daily_quota=2)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "suspicious": 0}
            }
        }
    })
    
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = mock_ctx
    
    # First lookup should work
    await provider._process_lookup("1.2.3.4")
    assert provider._quota_used_today == 1
    
    # Second lookup should work
    await provider._process_lookup("5.6.7.8")
    assert provider._quota_used_today == 2
    
    # Third lookup should be blocked by quota - test _maybe_lookup which checks quota
    mock_session.get.reset_mock()
    mock_redis.get.return_value = None  # Force cache miss
    await provider._maybe_lookup("9.10.11.12")
    # Should not call the API due to quota (should return early in _maybe_lookup)
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=False)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    
    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_virustotal_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", score_cap=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    # Mock cache hit
    cached_data = {"malicious_count": 2, "suspicious_count": 1}
    mock_local_cache.virustotal_scores.get.return_value = cached_data
    
    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 75  # (2 * 30) + (1 * 15)
    
    # Verify no API lookup was triggered (cache hit)
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_config_reload(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="old_key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    
    new_config_dict = {
        "virustotal": {
            "enabled": True,
            "api_key": "new_key",
            "malicious_score": 35,
            "suspicious_score": 20,
            "daily_quota": 200
        }
    }
    
    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.malicious_score == 35
    assert provider._config.suspicious_score == 20
    assert provider._config.daily_quota == 200


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


_VT_OK_BODY = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 1, "suspicious": 0}
        }
    }
}


@pytest.mark.asyncio
async def test_virustotal_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called()


@pytest.mark.asyncio
async def test_virustotal_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("virustotal", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("virustotal")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
        provider = VirusTotalProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


@pytest.mark.asyncio
async def test_virustotal_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
        provider = VirusTotalProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.side_effect = OSError("connection refused")
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


@pytest.mark.asyncio
async def test_virustotal_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; session.get called 3 times."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, _VT_OK_BODY)
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OSError("transient error")
        return success_ctx

    mock_session.get.side_effect = side_effect

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    assert call_count == 3
    mock_redis.setex.assert_called()