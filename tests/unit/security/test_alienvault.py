"""
Unit tests for Phase 59a — AlienVault OTX circuit breaker and retry wiring.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.alienvault import AlienVaultOTXProvider, OTXConfig
from src.security.models import RiskSignal


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    client.bf = MagicMock()
    client.bf().add = AsyncMock(return_value=1)
    client.expire = AsyncMock(return_value=True)
    return client


@pytest.fixture
def mock_local_cache():
    cache = MagicMock()
    cache.alienvault_scores = MagicMock()
    cache.alienvault_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    return MagicMock()


def _make_ctx(status: int, body: dict):
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=body)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


# ---------------------------------------------------------------------------
# Backwards compatibility — no health_monitor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(
        200, {"pulse_info": {"count": 3}}
    )

    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — open circuit skips API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("alienvault_otx", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Circuit breaker — success records success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("alienvault_otx")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = OTXConfig(enabled=True, api_key="key")
        provider = AlienVaultOTXProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(
            200, {"pulse_info": {"count": 2}}
        )

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — failure records failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = OTXConfig(enabled=True, api_key="key")
        provider = AlienVaultOTXProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.side_effect = OSError("connection refused")

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# Retry — fails twice then succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; session.get called 3 times."""
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, {"pulse_info": {"count": 1}})

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
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Signal logic sanity check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = OTXConfig(enabled=True, api_key="key", pulse_score=15, score_cap=45)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    signal = provider._to_signal("1.2.3.4", {"pulse_count": 2})
    assert signal is not None
    assert signal.score == 30

    signal = provider._to_signal("1.2.3.4", {"pulse_count": 0})
    assert signal is None
