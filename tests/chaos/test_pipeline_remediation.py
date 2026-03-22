"""Reproduction tests for Phase 18: Security Audit Remediation.

Demonstrates how broad exception handling in the pipeline masks 
code-level bugs (e.g., NameError, AttributeError).
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.models import ConnectionContext, RiskSignal
from src.security.pipeline import Pipeline, _SIGNAL_ERROR, _SIGNAL_SKIPPED


def _make_pipeline():
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
        },
        "geoip": {"country_blacklist": []},
        "mtls": {"enabled": False, "ca_cert_path": None},
    }
    cache = LocalCache({})
    redis_mock = MagicMock()
    return Pipeline(config=config, local_cache=cache, redis_client=redis_mock)


def _ctx(ip="1.2.3.4", sni="example.com"):
    return ConnectionContext(
        client_ip=ip,
        ja4="t13d1516h2_aabbccddee11_112233445566",
        sni=sni,
    )


@pytest.mark.asyncio
async def test_bug_increments_error_metric():
    """Verify that a NameError (bug) increments the _SIGNAL_ERROR metric."""
    pipeline = _make_pipeline()
    
    # Get current value
    try:
        initial_val = _SIGNAL_ERROR.labels(module="sni_analyzer")._value.get()
    except Exception:
        initial_val = 0
    
    # Mock SNI analyzer to raise a NameError (bug)
    with patch.object(pipeline._sni_analyzer, "analyze", side_effect=NameError("bug")):
        ctx = _ctx()
        await pipeline._collect_signals(ctx)
        
        # Verify metric incremented
        new_val = _SIGNAL_ERROR.labels(module="sni_analyzer")._value.get()
        assert new_val == initial_val + 1


@pytest.mark.asyncio
async def test_dependency_failure_increments_skipped_metric():
    """Verify that a ConnectionError increments the _SIGNAL_SKIPPED metric."""
    pipeline = _make_pipeline()
    
    # Get current value
    try:
        initial_val = _SIGNAL_SKIPPED.labels(module="asn_classifier", reason="timeout_or_conn_error")._value.get()
    except Exception:
        initial_val = 0
    
    # Mock ASN classifier to raise a ConnectionError (dependency failure)
    with patch.object(pipeline._asn_classifier, "signals", side_effect=ConnectionError("redis down")):
        ctx = _ctx()
        await pipeline._collect_signals(ctx)
        
        # Verify metric incremented
        new_val = _SIGNAL_SKIPPED.labels(module="asn_classifier", reason="timeout_or_conn_error")._value.get()
        assert new_val == initial_val + 1


@pytest.mark.asyncio
async def test_analytics_dependency_failure():
    """Verify that analytics Redis failure increments _SIGNAL_SKIPPED."""
    pipeline = _make_pipeline()
    
    try:
        initial_val = _SIGNAL_SKIPPED.labels(module="analytics", reason="timeout_or_conn_error")._value.get()
    except Exception:
        initial_val = 0
        
    # Mock redis.get to raise ConnectionError
    pipeline._redis.get.side_effect = ConnectionError("redis connection lost")
    
    ctx = _ctx()
    await pipeline._collect_signals(ctx)
    
    new_val = _SIGNAL_SKIPPED.labels(module="analytics", reason="timeout_or_conn_error")._value.get()
    assert new_val == initial_val + 1
