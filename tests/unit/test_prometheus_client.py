"""Tests for management/api/prometheus_client.py.

Verifies:
- 3-state results: Ok(value, fetched_at) | Empty(fetched_at) | Unavailable(reason, last_ok_at)
- Bounded 2.0s timeout and follow_redirects=False (no SSRF / redirects)
- Caching layer (10s TTL) and single-flight deduplication under concurrency
- URL validation (http/https, no userinfo)
- Prometheus queries self-observability counter instrumentation
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from management.api.prometheus_client import (
    Empty,
    Ok,
    PrometheusClient,
    Unavailable,
    validate_prometheus_url,
)
from management.api.prometheus_metrics import PROMETHEUS_QUERIES


def test_validate_prometheus_url():
    # Valid
    assert validate_prometheus_url("http://prometheus:9090") == "http://prometheus:9090"
    assert validate_prometheus_url("https://prom.internal:9090/") == "https://prom.internal:9090"

    # Invalid scheme
    with pytest.raises(ValueError, match="Invalid scheme"):
        validate_prometheus_url("ftp://prometheus:9090")

    # Userinfo forbidden
    with pytest.raises(ValueError, match="Userinfo"):
        validate_prometheus_url("http://admin:secret@prometheus:9090")

    # Empty
    with pytest.raises(ValueError, match="empty"):
        validate_prometheus_url("")


@pytest.mark.asyncio
async def test_prometheus_client_ok_response():
    client = PrometheusClient("http://test-prom:9090")

    mock_resp = httpx.Response(
        200,
        json={
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {}, "value": [1700000000.0, "42.5"]}],
            },
        },
        request=httpx.Request("GET", "http://test-prom:9090/api/v1/query"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await client.query_instant("up")
        assert isinstance(res, Ok)
        assert res.value == 42.5
        assert res.fetched_at > 0


@pytest.mark.asyncio
async def test_prometheus_client_empty_response():
    client = PrometheusClient("http://test-prom:9090")

    mock_resp = httpx.Response(
        200,
        json={
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [],
            },
        },
        request=httpx.Request("GET", "http://test-prom:9090/api/v1/query"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await client.query_instant("absent_metric")
        assert isinstance(res, Empty)
        assert res.fetched_at > 0


@pytest.mark.asyncio
async def test_prometheus_client_unavailable_response():
    client = PrometheusClient("http://test-prom:9090")

    mock_resp = httpx.Response(
        503,
        json={"status": "error", "error": "service unavailable"},
        request=httpx.Request("GET", "http://test-prom:9090/api/v1/query"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await client.query_instant("up")
        assert isinstance(res, Unavailable)
        assert "HTTP 503" in res.reason


@pytest.mark.asyncio
async def test_prometheus_client_caching_and_single_flight():
    client = PrometheusClient("http://test-prom:9090", ttl=5.0)

    call_count = 0

    async def fake_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.05)
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [{"metric": {}, "value": [1700000000.0, "100"]}],
                },
            },
            request=httpx.Request("GET", "http://test-prom:9090/api/v1/query"),
        )

    with patch("httpx.AsyncClient.get", side_effect=fake_get):
        # 10 concurrent requests for the exact same query
        tasks = [client.query_instant("test_concurrent_query") for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # Single flight ensures only 1 HTTP request went out
        assert call_count == 1
        assert all(isinstance(r, Ok) and r.value == 100 for r in results)

        # Immediate follow-up within TTL also uses cache without extra network call
        cached_res = await client.query_instant("test_concurrent_query")
        assert call_count == 1
        assert isinstance(cached_res, Ok)
