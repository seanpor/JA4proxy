"""Pydantic request/response models for the management API.

All models use strict validation with descriptive field constraints to
ensure API contract adherence and clear error messages.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ── Auth models ───────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    """Credentials submitted to POST /auth/login."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """Successful login response body (token is in httpOnly cookie)."""

    message: str = "Login successful"


# ── Dial models ───────────────────────────────────────────────────────────────


class DialValue(BaseModel):
    """Response from GET /api/v1/dial."""

    value: int = Field(..., ge=0, le=100, description="Current dial setting (0-100)")
    updated_at: Optional[str] = Field(
        None, description="ISO8601 timestamp of last update"
    )


class DialUpdateRequest(BaseModel):
    """Body for PUT /api/v1/dial."""

    value: int = Field(
        ..., ge=0, le=100, description="New dial value (0-100, max ±10 change)"
    )


# ── List models ───────────────────────────────────────────────────────────────


class ListEntries(BaseModel):
    """Response from GET /api/v1/lists/{list_type}/{list_name}."""

    entries: list[str] = Field(default_factory=list)
    count: int = Field(..., ge=0)


class ListAddResponse(BaseModel):
    """Response from POST /api/v1/lists/{list_type}/{list_name}/{entry}."""

    message: str
    entry: str


class ListRemoveResponse(BaseModel):
    """Response from DELETE /api/v1/lists/{list_type}/{list_name}/{entry}."""

    message: str
    entry: str


# ── Ban models ────────────────────────────────────────────────────────────────


class BanEntry(BaseModel):
    """A single active ban record."""

    ip: str
    reason: str = "manual"
    ttl_remaining: Optional[int] = Field(
        None, description="Remaining TTL in seconds; None means persistent"
    )


class BanList(BaseModel):
    """Response from GET /api/v1/bans."""

    bans: list[BanEntry] = Field(default_factory=list)
    count: int = Field(..., ge=0)


class BanCreateRequest(BaseModel):
    """Body for POST /api/v1/bans/{ip}."""

    ttl: int = Field(3600, ge=1, description="TTL in seconds (default 3600)")
    reason: str = Field("manual", min_length=1, max_length=256)


class BanCreateResponse(BaseModel):
    """Response from POST /api/v1/bans/{ip}."""

    message: str
    ip: str
    ttl: int
    reason: str


class BanRemoveResponse(BaseModel):
    """Response from DELETE /api/v1/bans/{ip}."""

    message: str
    ip: str


# ── Health models ─────────────────────────────────────────────────────────────


class HealthResponse(BaseModel):
    """Response from GET /api/v1/health."""

    status: str = Field(..., description="ok | degraded")
    redis: str = Field(..., description="ok | unavailable")
    proxy_instances: int = Field(
        0, ge=0, description="Number of live proxy instances detected"
    )
    geoip: str = Field(..., description="ok | unavailable")
    uptime_seconds: float = Field(..., ge=0)


# ── Audit models ──────────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    """A single management audit log entry."""

    timestamp: str
    action: str
    user: str
    detail: dict[str, Any] = Field(default_factory=dict)
    ip: str


class AuditLog(BaseModel):
    """Response from GET /api/v1/audit."""

    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = Field(..., ge=0)


# ── Config models ─────────────────────────────────────────────────────────────


class ConfigReloadResponse(BaseModel):
    """Response from POST /api/v1/config/reload."""

    message: str = "Config reload signal published"
    published_to: str = "config.reload"
