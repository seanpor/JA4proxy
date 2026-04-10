from typing import List

from pydantic import BaseModel, Field


class DialUpdate(BaseModel):
    value: int = Field(..., ge=0, le=100)

class JA4Entry(BaseModel):
    fingerprint: str

class HealthResponse(BaseModel):
    status: str
    redis_connected: bool
    dial: int
