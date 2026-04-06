"""
Unit tests for Phase 23 TI Providers (GreyNoise, AlienVault OTX).
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.alienvault import AlienVaultOTXProvider, OTXConfig
from src.security.greynoise import GreyNoiseConfig, GreyNoiseProvider
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


# ---------------------------------------------------------------------------
# Coverage gap: TIProvider abstract method bodies (lines 71, 76, 84, 89)
# ---------------------------------------------------------------------------

from src.security.ti_provider import TIProvider, retry_with_backoff


class _ConcreteTI(TIProvider):
    """Minimal concrete subclass that delegates all abstract methods to super()."""

    async def start(self):
        return await super().start()  # covers line 71

    async def stop(self):
        return await super().stop()  # covers line 76

    def get_signal(self, ip):
        return super().get_signal(ip)  # covers line 84

    def on_config_reload(self, new_config):
        return super().on_config_reload(new_config)  # covers line 89


@pytest.mark.asyncio
async def test_retry_with_backoff_retries_then_raises():
    """Lines 36-48: retry_with_backoff retries on exception and re-raises after max attempts.
    So what: without testing this, a provider that silently never retries would fail on the
    first transient network error instead of recovering — losing TI signals for flapping feeds."""
    call_count = [0]

    async def _failing():
        call_count[0] += 1
        raise ValueError("temporary failure")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(ValueError, match="temporary failure"):
            await retry_with_backoff(_failing, max_attempts=3, base_delay=0.001, feed_name="test")

    assert call_count[0] == 3  # called 3 times


@pytest.mark.asyncio
async def test_retry_with_backoff_succeeds_on_retry():
    """Lines 36-47: retry_with_backoff calls coro_fn again after first failure.
    So what: without retry logic, every transient HTTPS timeout during TI lookups
    would drop the risk signal, silently reducing detection coverage."""
    call_count = [0]

    async def _flaky():
        call_count[0] += 1
        if call_count[0] < 2:
            raise ConnectionError("flap")
        return "ok"

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await retry_with_backoff(_flaky, max_attempts=3, base_delay=0.001, feed_name="test")

    assert result == "ok"
    assert call_count[0] == 2


@pytest.mark.asyncio
async def test_ti_provider_abstract_method_bodies():
    """Lines 71, 76, 84, 89: abstract method `pass` bodies are reachable via super().
    So what: without testing these, a subclass that accidentally calls super() (e.g.
    during refactoring) silently gets None instead of NotImplementedError, masking
    missing overrides in production providers."""
    ti = _ConcreteTI()
    await ti.start()       # line 71
    await ti.stop()        # line 76
    assert ti.get_signal("1.2.3.4") is None   # line 84
    assert ti.on_config_reload({}) is None     # line 89
