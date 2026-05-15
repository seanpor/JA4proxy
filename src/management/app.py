import asyncio
import json
import os
import re
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional

import aiohttp
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from src.management.redis_client import RedisManager
from src.management.schemas import (
    DeepHealthResponse,
    DialUpdate,
    HealthResponse,
    JA4Entry,
)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

# Phase 86a — Proxy metrics URL (for deep health endpoint)
PROXY_METRICS_URL = os.getenv("PROXY_METRICS_URL", "http://localhost:9090")

redis_manager = RedisManager(REDIS_HOST, REDIS_PORT, 0, REDIS_PASSWORD)


def _parse_prometheus_text(text: str) -> Dict[str, float]:
    """Parse Prometheus text exposition format into a flat dict.

    Handles counters, gauges, and histograms (sums and counts).
    Labelled metrics include the full label in the key, e.g.:
    ``ja4proxy_connections_total{action="block"}``
    """
    result: Dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match: metric_name{label="value"} 42.0
        m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{.*?\})?)\s+([\d.eE+-]+)$", line)
        if m:
            result[m.group(1)] = float(m.group(2))
            continue
    return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_manager.connect()
    yield
    await redis_manager.close()


app = FastAPI(title="JA4 Proxy Management API", version="1.0.0", lifespan=lifespan)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # nosemgrep
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    try:
        dial = await redis_manager.get_dial()
        return HealthResponse(status="ok", redis_connected=True, dial=dial)
    except Exception:
        return HealthResponse(status="error", redis_connected=False, dial=0)


@app.get("/api/v1/health/deep", response_model=DeepHealthResponse)
async def get_health_deep() -> DeepHealthResponse:
    """Phase 86a — Deep health: combines Redis state with proxy Prometheus metrics."""
    # Redis connectivity (timing + state)
    redis_ok = False
    redis_latency_ms = 0.0
    dial = 0
    active_bans = 0
    try:
        t0 = time.monotonic()
        await redis_manager._client.ping()  # direct ping for latency measurement
        redis_latency_ms = (time.monotonic() - t0) * 1000
        redis_ok = True
        dial = await redis_manager.get_dial()

        # Count active bans via SCAN (safer than KEYS for production)
        cursor = 0
        ban_count = 0
        while True:
            cursor, keys = await redis_manager._client.scan(
                cursor=cursor, match="ja4proxy:ban:*", count=500
            )
            ban_count += len(keys)
            if cursor == 0:
                break
        active_bans = ban_count
    except Exception:
        # Fail-open: return what we can without Redis
        return DeepHealthResponse(
            status="error",
            redis_connected=False,
            redis_latency_ms=0.0,
            dial=0,
            active_connections=0,
            connections_total=0,
            block_rate_pct=0.0,
            active_bans=0,
            cert_days_remaining=None,
        )

    # Proxy metrics (from Prometheus text endpoint)
    active_connections = 0
    connections_total = 0
    blocks_total = 0
    cert_days_remaining: Optional[float] = None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{PROXY_METRICS_URL}/metrics",
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    metrics = _parse_prometheus_text(text)

                    active_connections = int(
                        metrics.get("ja4proxy_active_connections", 0)
                    )
                    connections_total = int(
                        metrics.get("ja4proxy_connections_total", 0)
                    )
                    blocks_total = int(
                        metrics.get('ja4proxy_connections_total{action="block"}', 0)
                        + metrics.get('ja4proxy_connections_total{action="ban"}', 0)
                        + metrics.get('ja4proxy_connections_total{action="tarpit"}', 0)
                        + metrics.get(
                            'ja4proxy_connections_total{action="rate_limit"}', 0
                        )
                    )

                    # Cert expiry → days remaining
                    cert_ts = metrics.get(
                        "ja4proxy_tls_cert_expiry_timestamp_seconds", 0
                    )
                    if cert_ts > 0:
                        remaining = cert_ts - time.time()
                        cert_days_remaining = max(0, remaining / 86400)
    except Exception:
        # Fail-open: metrics unavailable but Redis is fine
        pass

    # Compute block rate
    block_rate_pct = 0.0
    if connections_total > 0:
        block_rate_pct = round(blocks_total / connections_total * 100, 2)

    # Overall status
    if not redis_ok:
        status = "error"
    elif redis_latency_ms > 50:
        status = "degraded"
    else:
        status = "ok"

    return DeepHealthResponse(
        status=status,
        redis_connected=redis_ok,
        redis_latency_ms=round(redis_latency_ms, 2),
        dial=dial,
        active_connections=active_connections,
        connections_total=connections_total,
        block_rate_pct=block_rate_pct,
        active_bans=active_bans,
        cert_days_remaining=(
            round(cert_days_remaining, 1) if cert_days_remaining is not None else None
        ),
    )


@app.get("/api/v1/metrics/summary", response_model=DeepHealthResponse)
async def get_metrics_summary():
    """Phase 86a — Alias for /api/v1/health/deep.
    Exists so monitoring tools can poll a single endpoint named 'metrics/summary'."""
    return await get_health_deep()


@app.get("/api/v1/dial")
async def get_dial():
    dial = await redis_manager.get_dial()
    return {"dial": dial}


@app.put("/api/v1/dial")
async def update_dial(update: DialUpdate):
    await redis_manager.set_dial(update.value)
    return {"status": "success", "dial": update.value}


@app.get("/api/v1/lists/ja4/{list_type}")
async def get_ja4_list(list_type: str):
    if list_type not in ["whitelist", "blacklist"]:
        raise HTTPException(status_code=404, detail="List not found")
    entries = await redis_manager.get_list(list_type)
    return {"entries": entries}


@app.post("/api/v1/lists/ja4/{list_type}")
async def add_ja4_entry(list_type: str, entry: JA4Entry):
    if list_type not in ["whitelist", "blacklist"]:
        raise HTTPException(status_code=404, detail="List not found")
    await redis_manager.add_to_list(list_type, entry.fingerprint)
    return {"status": "success"}


@app.delete("/api/v1/lists/ja4/{list_type}/{fingerprint}")
async def remove_ja4_entry(list_type: str, fingerprint: str):
    if list_type not in ["whitelist", "blacklist"]:
        raise HTTPException(status_code=404, detail="List not found")
    await redis_manager.remove_from_list(list_type, fingerprint)
    return {"status": "success"}


async def event_generator() -> AsyncGenerator[str, None]:
    async for event in redis_manager.get_events():
        yield f"data: {event}\n\n"


@app.get("/api/v1/events")
async def events(request: Request):
    return StreamingResponse(event_generator(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8090)
