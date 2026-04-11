from typing import List, Optional

from pydantic import BaseModel, Field


class DialUpdate(BaseModel):
    value: int = Field(..., ge=0, le=100)

class JA4Entry(BaseModel):
    fingerprint: str

class HealthResponse(BaseModel):
    status: str
    redis_connected: bool
    dial: int


class DeepHealthResponse(BaseModel):
    """Phase 86a — Deep health response with all monitoring fields."""
    status: str                           # "ok" | "degraded" | "error"
    redis_connected: bool
    redis_latency_ms: float
    dial: int
    active_connections: int
    connections_total: int
    block_rate_pct: float
    active_bans: int
    cert_days_remaining: Optional[float]  # None if cert expiry unknown
