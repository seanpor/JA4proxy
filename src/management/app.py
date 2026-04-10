import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from src.management.redis_client import RedisManager
from src.management.schemas import DialUpdate, HealthResponse, JA4Entry

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

redis_manager = RedisManager(REDIS_HOST, REDIS_PORT, 0, REDIS_PASSWORD)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_manager.connect()
    yield
    await redis_manager.close()

app = FastAPI(title="JA4 Proxy Management API", version="1.0.0", lifespan=lifespan)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health", response_model=HealthResponse)
async def get_health():
    try:
        dial = await redis_manager.get_dial()
        return {
            "status": "ok",
            "redis_connected": True,
            "dial": dial
        }
    except Exception:
        return {
            "status": "error",
            "redis_connected": False,
            "dial": 0
        }

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
