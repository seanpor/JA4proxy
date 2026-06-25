"""Pydantic request/response models for the management API.

All models use strict validation with descriptive field constraints to
ensure API contract adherence and clear error messages.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field, field_validator

# ── RBAC ─────────────────────────────────────────────────────────────────────


class Role(str, Enum):
    """Role vocabulary for bearer token access control."""

    auditor = "auditor"
    analyst = "analyst"
    operator = "operator"
    admin = "admin"


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
    revert_after_hours: Optional[int] = Field(
        None, ge=1, le=24,
        description="Auto-revert the dial to its current value after N hours (1-24).",
    )


class EmergencyDialRequest(BaseModel):
    """Body for POST /api/v1/dial/emergency — bypasses the ±10 step limit."""

    value: Optional[int] = Field(
        None, ge=0, le=100,
        description="Exact dial value. Mutually exclusive with preset.",
    )
    preset: Optional[str] = Field(
        None,
        description="Named preset: block_known_bad (50), active_defense (75), lockdown (90).",
    )
    revert_after_hours: int = Field(
        1, ge=1, le=4,
        description="Auto-revert after N hours (1-4). Default 1.",
    )

    @field_validator("preset")
    @classmethod
    def validate_preset(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in EMERGENCY_PRESETS:
            allowed = ", ".join(sorted(EMERGENCY_PRESETS))
            raise ValueError(f"Unknown preset {v!r}. Allowed: {allowed}")
        return v


EMERGENCY_PRESETS: dict[str, int] = {
    "block_known_bad": 50,
    "active_defense": 75,
    "lockdown": 90,
}


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


class BanExtendRequest(BaseModel):
    """Body for PATCH /api/v1/bans/{ip}."""

    extend_ttl_seconds: int = Field(
        ..., gt=0, le=86400 * 30, description="Seconds to add to the remaining TTL"
    )
    reason: Optional[str] = Field(
        None,
        description="Optional note; does not overwrite the existing ban reason",
    )


class BanExtendResponse(BaseModel):
    """Response from PATCH /api/v1/bans/{ip}."""

    ip: str
    new_expires_at: str = Field(..., description="ISO-8601 UTC timestamp of new expiry")
    previous_ttl: int
    new_ttl: int


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
    published_to: str = "config:reload"


# ── Token models (MFA/SSO Hardening) ───────────────────────────────────────────────────


class TokenCreate(BaseModel):
    """Request body for POST /api/v1/tokens."""

    name: str = Field(..., min_length=1, max_length=128)
    role: Role
    expires_at: Optional[str] = Field(
        None,
        description="ISO 8601 UTC timestamp; must be in the future if provided",
    )

    @field_validator("expires_at")
    @classmethod
    def expires_at_must_be_future(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            dt = datetime.fromisoformat(v)
        except ValueError as exc:
            raise ValueError(
                f"expires_at is not a valid ISO 8601 timestamp: {v!r}"
            ) from exc
        # Ensure timezone-aware comparison
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return v


class TokenResponse(BaseModel):
    """Token metadata — no hash, no plaintext."""

    id: str
    name: str
    role: str
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None


class TokenCreateResponse(TokenResponse):
    """Returned once on creation — includes the plaintext token."""

    token: str


class TokenListResponse(BaseModel):
    """Response from GET /api/v1/tokens."""

    tokens: List[TokenResponse] = Field(default_factory=list)
    count: int = Field(..., ge=0)


class TokenRotateResponse(BaseModel):
    """Response from POST /api/v1/tokens/{id}/rotate."""

    id: str
    token: str  # new plaintext token


# ── Resource model (MFA/SSO Hardening Cluster 3) ──────────────────────────────────────


class ManagedBy(str, Enum):
    """Source of truth for a list entry."""

    terraform = "terraform"
    operator = "operator"
    api = "api"
    analytics = "analytics"
    legacy = "legacy"
    migration = "migration"
    feed = "feed"  # phase-85: threat-intel feed runner
    operator_k8s = "operator_k8s"  # phase-94a: Kubernetes operator


class ResourceCreate(BaseModel):
    """Request body for POST /api/v1/{allowlist|blocklist|watchlist}."""

    entry: str = Field(..., min_length=1, max_length=512)
    managed_by: ManagedBy = ManagedBy.operator
    note: str = ""
    expires_at: Optional[str] = Field(
        None,
        description="ISO 8601 UTC timestamp; if in the past the entry is accepted but filtered on read",
    )
    list_type: Optional[str] = Field(
        None,
        description="Used internally; inferred from route path if absent",
    )


class ResourceResponse(BaseModel):
    """Full resource envelope returned by canonical list endpoints."""

    id: str
    entry: str
    list_type: str
    managed_by: str
    note: str
    created_at: str
    created_by: str
    expires_at: Optional[str] = None


class ResourceListResponse(BaseModel):
    """Response from GET /api/v1/{allowlist|blocklist|watchlist}."""

    entries: list[ResourceResponse]
    count: int


# ── Threat Intelligence feed models (Phase 85) ────────────────────────────────


class TIFeedStatus(BaseModel):
    """Single-feed status as returned by the threat-intel routes."""

    id: str
    type: str
    enabled: bool = False
    runtime_override: Optional[bool] = None
    status: str = "unknown"
    circuit_state: str = "closed"
    last_poll_at: Optional[str] = None
    next_poll_at: Optional[str] = None
    indicators_managed: int = 0
    last_24h_additions: int = 0
    last_24h_removals: int = 0
    last_error: Optional[str] = None
    error_count_24h: int = 0


class TIFeedListResponse(BaseModel):
    """Response from GET /api/v1/threat-intel/feeds."""

    feeds: list[TIFeedStatus] = Field(default_factory=list)
    count: int = Field(..., ge=0)


class TIFeedPollResponse(BaseModel):
    """Response from POST /api/v1/threat-intel/feeds/{feed_id}/poll."""

    poll_id: str
    feed_id: str
    message: str = "Poll triggered"


class TIFeedToggleResponse(BaseModel):
    """Response from enable/disable endpoints."""

    feed_id: str
    enabled: bool
    message: str
