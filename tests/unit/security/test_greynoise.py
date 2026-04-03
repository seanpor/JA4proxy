"""
Unit tests for Phase 59a — GreyNoise circuit breaker and retry wiring.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.greynoise import GreyNoiseConfig, GreyNoiseProvider
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
    cache.greynoise_scores = MagicMock()
    cache.greynoise_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    return MagicMock()


def _make_ctx(status: int, body: dict):
    """Build an async context-manager that returns an aiohttp-like response."""
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
async def test_greynoise_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(
        200, {"noise": True, "riot": False, "classification": "malicious"}
    )

    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — open circuit skips API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("greynoise", failure_threshold=1)
    cb.record_failure()  # Open the circuit immediately (threshold=1)
    assert cb.is_open()

    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Circuit breaker — success path records success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked on the circuit breaker."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("greynoise")

    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(
            200, {"noise": True, "riot": False, "classification": "malicious"}
        )

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — failure path records failure and re-raises
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called and exception is swallowed by worker."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        # Simulate network error on every attempt
        mock_session.get.side_effect = OSError("connection refused")

        # _process_lookup catches the final exception internally
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# Retry — fails twice then succeeds; three HTTP calls made
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; the session is called 3 times total."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(
        200, {"noise": True, "riot": False, "classification": "malicious"}
    )

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
# Signal logic sanity check (unchanged from Phase 23)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = GreyNoiseConfig(enabled=True, api_key="key", noise_score=25, riot_score_reduction=15)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    signal = provider._to_signal("1.2.3.4", {"noise": True, "riot": False, "classification": "malicious"})
    assert signal is not None
    assert signal.score == 25

    signal = provider._to_signal("1.2.3.4", {"noise": False, "riot": True, "classification": "unknown"})
    assert signal is not None
    assert signal.score == -15

    signal = provider._to_signal("1.2.3.4", {"noise": False, "riot": False, "classification": "unknown"})
    assert signal is None
