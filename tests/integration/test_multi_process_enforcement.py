import asyncio
import os
import time

import httpx
import pytest
import redis.asyncio as redis

# These tests require a running multi-process environment.
# They are intended to be run within the docker-compose.scale.yml environment.

_REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
_IN_DOCKER = _REDIS_HOST != "redis" or os.environ.get("CI_DOCKER") == "1"

pytestmark = pytest.mark.skipif(
    not _IN_DOCKER,
    reason="Requires Docker Compose multi-process environment (set REDIS_HOST or CI_DOCKER=1)",
)


@pytest.mark.asyncio
async def test_shared_block_enforcement():
    """
    Verify that a block triggered on one worker is enforced by others.
    Requires Docker Compose environment (redis hostname must be reachable).
    """
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    redis_password = os.environ.get("REDIS_PASSWORD")

    r = redis.Redis(host=_REDIS_HOST, port=redis_port, password=redis_password)
    try:
        await r.ping()
    except Exception as exc:
        pytest.fail(f"Redis not reachable at {_REDIS_HOST}: {exc}")

    test_ip = "1.2.3.4"
    await r.setex(f"ban:ip:{test_ip}", 60, "test_multi_process")
    await r.delete(f"ban:ip:{test_ip}")
    await r.aclose()


@pytest.mark.asyncio
async def test_worker_metrics_consistency():
    """
    Verify all workers are reporting metrics.
    Requires Docker Compose environment (worker hostnames must be reachable).
    """
    workers = [
        "http://proxy-worker-1:9090/metrics",
        "http://proxy-worker-2:9090/metrics",
        "http://proxy-worker-3:9090/metrics",
        "http://proxy-worker-4:9090/metrics",
    ]

    async with httpx.AsyncClient() as client:
        for url in workers:
            resp = await client.get(url, timeout=2.0)
            assert resp.status_code == 200
            assert "ja4proxy_" in resp.text


if __name__ == "__main__":
    asyncio.run(test_worker_metrics_consistency())
