"""Pydantic v2 request/response models for the Management UI API.

All models use Pydantic v2 conventions. IP addresses are validated with
the ipaddress stdlib module to ensure correctness for both IPv4 and IPv6.
JA4 fingerprints are validated against the canonical regex pattern.
"""

import ipaddress
import re
from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator

# JA4 fingerprint canonical pattern: letter + version + d/i + 4 digits + alpn +
# underscore + 12 hex chars + underscore + 12 hex chars
# e.g. t13d1516h2_8daaf6152771_02713d6af862
_JA4_PATTERN = re.compile(
    r"^[a-z][0-9]{2}[a-z][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$"
)


def _validate_ip(v: str) -> str:
    """Validate and canonicalise an IP address string."""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError(f"Invalid IP address: {v!r}")


def _validate_cidr(v: str) -> str:
    """Validate and canonicalise a CIDR string."""
    try:
        net = ipaddress.ip_network(v, strict=False)
        return str(net)
    except ValueError:
        raise ValueError(f"Invalid CIDR: {v!r}")


def _validate_ja4(v: str) -> str:
    """Validate a JA4 fingerprint format."""
    if not _JA4_PATTERN.match(v):
        raise ValueError(
            f"Invalid JA4 fingerprint format: {v!r}. "
            "Expected pattern like t13d1516h2_8daaf6152771_02713d6af862"
        )
    return v


# ── Ban models ────────────────────────────────────────────────────────────────

class BanAddRequest(BaseModel):
    """Request to add an IP ban."""

    ip: str
    reason: str
    ttl_s: int = 3600  # default 1 hour; 0 = permanent

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        return _validate_ip(v)

    @field_validator("ttl_s")
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        if v < 0:
            raise ValueError("ttl_s must be >= 0 (0 = permanent)")
        return v


class BanEntry(BaseModel):
    """Response entry for a single IP ban."""

    ip: str
    reason: str
    ttl_s: Optional[int] = None  # None = permanent


class CIDRAddRequest(BaseModel):
    """Request to add a CIDR block."""

    cidr: str
    reason: str
    ttl_s: int = 0  # 0 = permanent by default for manual CIDR blocks

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        return _validate_cidr(v)


class CIDREntry(BaseModel):
    """Response entry for a single CIDR block."""

    cidr: str
    reason: str
    ttl_s: Optional[int] = None


# ── Pagination wrapper ────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    """Generic paginated response."""

    items: list[Any]
    total: int
    page: int
    per_page: int


# ── Fingerprint models ────────────────────────────────────────────────────────

class FingerprintAddRequest(BaseModel):
    """Request to add a JA4 fingerprint to blacklist or whitelist."""

    fingerprint: str
    reason: str = ""

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        return _validate_ja4(v)


class FingerprintEntry(BaseModel):
    """Response entry for a JA4 fingerprint."""

    fingerprint: str
    reason: str = ""


class CandidateEntry(BaseModel):
    """Response entry for a JA4 candidate fingerprint."""

    fingerprint: str
    count: float  # score from the sorted set
    reason: str = ""


# ── Dial models ───────────────────────────────────────────────────────────────

class DialResponse(BaseModel):
    """Current dial state."""

    dial: int
    blocking_acknowledged: bool


class DialUpdateRequest(BaseModel):
    """Request to change the dial value."""

    dial: int
    reason: str = ""

    @field_validator("dial")
    @classmethod
    def validate_dial(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("dial must be between 0 and 100")
        return v


class DialAcknowledgeRequest(BaseModel):
    """Request to acknowledge that blocking will occur."""

    acknowledged: bool


# ── Policy models ─────────────────────────────────────────────────────────────

VALID_BYPASS_NAMES = frozenset([
    "alpn_browser_bypass",
    "ja4_whitelist_bypass",
    "mtls_bypass",
    "static_ip_allowlist",
    "ja4_blacklist_bypass",
    "country_blacklist_bypass",
    "spamhaus_bypass",
    "tls_version_bypass",
])


class BypassEntry(BaseModel):
    """State of a single bypass."""

    name: str
    enabled: bool
    description: str = ""


class BypassUpdateRequest(BaseModel):
    """Request to enable/disable a bypass."""

    enabled: bool


# ── Config models ─────────────────────────────────────────────────────────────

class ThresholdConfig(BaseModel):
    """Action threshold configuration (score 0–100 per action)."""

    flag: int = 20
    rate_limit: int = 35
    tarpit: int = 55
    block: int = 70
    ban: int = 85

    @model_validator(mode="after")
    def validate_ordering(self) -> "ThresholdConfig":
        """Thresholds must be in ascending order."""
        values = [self.flag, self.rate_limit, self.tarpit, self.block, self.ban]
        for v in values:
            if not 0 <= v <= 100:
                raise ValueError(f"All thresholds must be between 0 and 100, got {v}")
        if not (self.flag <= self.rate_limit <= self.tarpit <= self.block <= self.ban):
            raise ValueError(
                "Thresholds must be in ascending order: "
                "flag <= rate_limit <= tarpit <= block <= ban"
            )
        return self


class ThresholdUpdateRequest(BaseModel):
    """Request to update action thresholds."""

    flag: Optional[int] = None
    rate_limit: Optional[int] = None
    tarpit: Optional[int] = None
    block: Optional[int] = None
    ban: Optional[int] = None

    @field_validator("flag", "rate_limit", "tarpit", "block", "ban", mode="before")
    @classmethod
    def validate_range(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not 0 <= v <= 100:
            raise ValueError(f"Threshold must be between 0 and 100, got {v}")
        return v


class CountriesBlocklistUpdate(BaseModel):
    """Request to replace the country blocklist."""

    countries: list[str]

    @field_validator("countries")
    @classmethod
    def validate_country_codes(cls, v: list[str]) -> list[str]:
        for code in v:
            if not re.match(r"^[A-Z]{2}$", code):
                raise ValueError(f"Invalid country code: {code!r} (must be 2 uppercase letters)")
        return v


class FeatureUpdate(BaseModel):
    """Request to enable/disable a feature flag."""

    enabled: bool


# ── Integration status models ─────────────────────────────────────────────────

class IntegrationStatus(BaseModel):
    """Status of an external integration."""

    name: str
    status: str  # "healthy" | "degraded" | "disabled" | "error"
    last_updated: Optional[str] = None
    detail: Optional[str] = None


# ── Audit log models ──────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    """A single audit log entry."""

    event: str
    actor_ip: Optional[str] = None
    detail: Optional[dict[str, Any]] = None
    timestamp: Optional[str] = None


# ── Health models ─────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Health check response."""

    status: str  # "healthy" | "degraded"
    version: str = "13.0.0"


class HealthDetailResponse(BaseModel):
    """Detailed health breakdown (authenticated)."""

    status: str
    redis: Any  # True if connected, "error" if not
    version: str = "13.0.0"


# ── SSE event models ──────────────────────────────────────────────────────────

class ConnectionEvent(BaseModel):
    """Live connection event for SSE feed."""

    event_type: str = "connection"
    ip: str
    action: str
    score: int
    ja4: Optional[str] = None


class BanEvent(BaseModel):
    """Ban event for SSE feed."""

    event_type: str = "ban"
    ip: str
    reason: str
    ttl_s: Optional[int] = None


class HeartbeatEvent(BaseModel):
    """Heartbeat event for SSE keep-alive."""

    event_type: str = "heartbeat"
