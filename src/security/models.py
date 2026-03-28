from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class RiskSignal:
    """A single scored signal from a security module.

    Attributes:
        name: Unique snake_case name for this signal (e.g. "ja4_whitelist").
        score: Raw risk score contribution (-100 to 100).
        reason: Human-readable explanation for the signal.
        weight: The weight to apply to the score.
    """

    name: str
    score: int
    reason: str
    weight: float = 1.0


@dataclass
class ConnectionContext:
    """Immutable snapshot of a connection's observable metadata."""

    client_ip: str
    ja4: str = ""
    ja4x: str | None = None  # JA4X extended fingerprint (Phase 16)
    alpn: str | None = None
    has_valid_client_cert: bool = False
    client_certificate: bytes | None = None
    sni: str | None = None
    tls_version: int | None = None
    country: str | None = None
    cipher_list: list[int] = field(default_factory=list)
    tcp_ja4t: str = ""
    tcp_window_size: int = 0
    tcp_ttl: int = 0
    tcp_options: str = ""
    connection_lifespan_ms: int = 0
    tls_alerts: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Result of processing one connection through the pipeline."""

    action: str
    bypassed: bool = False
    bypass_reason: str | None = None
    score: int | None = None
    signals: List[Any] = field(default_factory=list)
    dial: int | None = None
    counterfactuals: dict = field(default_factory=dict)
