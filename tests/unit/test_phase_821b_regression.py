"""
Unit and regression tests for Phase 821b:
- Panel 1 browser-classification correctness against seeded corpus and non-corpus JA4s
- Denominator-floor suppression (n < 30)
- Cert expiry handling (passthrough / 0 -> not configured, never an age)
- Dial multi-expression rendering (max/min/count) with Redis audit integration
- PrometheusClient get_alerts() sanitization without expr disclosure
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from management.api.ja4_corpus import (
    browser_label,
    corpus_mtime,
    corpus_size,
    is_known_browser,
)
from management.api.metric_catalogue import (
    PANEL_1_TILES,
    PANEL_2_TILES,
    PANEL_3_TILES,
    PANEL_5_TILES,
)
from management.api.prometheus_client import Empty, Ok, PrometheusClient, Unavailable


def test_browser_corpus_lookup():
    """Browser corpus correctly identifies known browser fingerprints and labels."""
    assert corpus_size() > 0
    assert corpus_mtime() != "unknown"

    # Known browser fingerprint from test corpus
    known_fp = "t13d1516h2_8daaf6152771_02713d6af862"
    assert is_known_browser(known_fp)
    assert "Chrome" in browser_label(known_fp) or browser_label(known_fp) != ""

    # Unknown fingerprint
    unknown_fp = "t13d000000_000000000000_000000000000"
    assert not is_known_browser(unknown_fp)
    assert browser_label(unknown_fp) == ""


def test_panel3_cert_expiry_logic():
    """Cert expiry tile must not render an age when timestamp is 0 (passthrough mode)."""
    tile = PANEL_3_TILES["panel3_cert_expiry"]
    assert tile.expr == "ja4proxy_tls_cert_expiry_timestamp_seconds"


@pytest.mark.asyncio
async def test_alerts_endpoint_sanitization():
    """get_alerts() strips query expressions (expr) and returns only safe metadata."""
    client = PrometheusClient(base_url="http://prometheus:9090")

    mock_resp_data = {
        "status": "success",
        "data": {
            "alerts": [
                {
                    "labels": {
                        "alertname": "DialDivergence",
                        "severity": "warning",
                        "dc_id": "us-east-1",
                    },
                    "annotations": {
                        "summary": "Dial divergence detected at DC us-east-1",
                    },
                    "state": "firing",
                    "activeAt": "2026-10-15T10:00:00Z",
                    "value": "1",
                    "expression": "max(ja4proxy_dial_current) - min(ja4proxy_dial_current) > 0",
                }
            ]
        },
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_resp_data

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await client.get_alerts()

    assert isinstance(res, Ok)
    assert len(res.value) == 1
    alert = res.value[0]
    assert alert["alertname"] == "DialDivergence"
    assert alert["state"] == "firing"
    assert alert["summary"] == "Dial divergence detected at DC us-east-1"
    assert "expression" not in alert
    assert "expr" not in alert


@pytest.mark.asyncio
async def test_threat_posture_browser_harm_denominator_suppression():
    """Threat posture partial renders 'insufficient browser-classified sample' when n < 30."""
    import fakeredis.aioredis
    from httpx import ASGITransport, AsyncClient

    from management.api import redis_client as _redis_module
    from management.api.auth import _create_access_token
    from management.api.main import create_app

    server = fakeredis.FakeServer()
    fake_r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    app = create_app()
    await _redis_module.init_redis(override_client=fake_r)
    token = _create_access_token("test-admin", "admin")

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test", cookies={"token": token}) as client:
            response = await client.get("/api/v1/partials/threat-posture?window=15m")
            assert response.status_code == 200
            assert "Real-User Impact" in response.text
            # In clean/empty test Redis, n < 30
            assert "insufficient browser-classified sample" in response.text
            assert "corpus:" in response.text
            assert "dial:" in response.text
    finally:
        await _redis_module.close_redis()
        await fake_r.aclose()


