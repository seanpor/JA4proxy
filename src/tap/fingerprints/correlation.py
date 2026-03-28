"""
Fingerprint correlation record (Phase 20, Group 5-L).

Aggregates all fingerprint results for one connection into a single
Redis-serialisable dataclass.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.tap.fingerprints.os_fingerprint import OSFingerprintResult
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues


@dataclass
class ConnectionFingerprints:
    """All fingerprint data collected for a single TCP/QUIC connection."""

    conn_id: str
    timestamp: datetime
    client_ip: str
    server_ip: str
    server_port: int
    # Fingerprint strings — None if extractor returned None or data not seen
    ja4: Optional[str] = None
    ja4s: Optional[str] = None
    ja4t: Optional[str] = None
    ja4ts: Optional[str] = None  # server-side JA4T (if available)
    ja4h: Optional[str] = None
    ja4l: Optional[str] = None
    ja4x: Optional[str] = None
    ja4ssh: Optional[str] = None
    h2_fingerprint: Optional[str] = None
    quic_fingerprint: Optional[str] = None
    os_fingerprint: Optional[str] = None
    tls_ext_values: Optional[JA4TLSExtValues] = None
    os_detail: Optional[OSFingerprintResult] = None
    # Extra fields populated by FingerprintExtractor
    cert_is_expired: bool = False
    cert_is_self_signed: bool = False
    h2_matched_client: Optional[str] = None
    risk_score: int = 0
    action: str = "observe"
    signals: list[dict] = field(default_factory=list)

    def to_redis_dict(self) -> dict[str, str]:
        """Serialise to a flat dict of string values for Redis HSET.

        None values are omitted.  Complex fields are JSON-encoded.
        """
        d: dict[str, str] = {
            "conn_id": self.conn_id,
            "timestamp": self.timestamp.isoformat(),
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "server_port": str(self.server_port),
            "risk_score": str(self.risk_score),
            "action": self.action,
        }
        # Optional fingerprint strings
        for key in (
            "ja4",
            "ja4s",
            "ja4t",
            "ja4ts",
            "ja4h",
            "ja4l",
            "ja4x",
            "ja4ssh",
            "h2_fingerprint",
            "quic_fingerprint",
            "os_fingerprint",
        ):
            val = getattr(self, key)
            if val is not None:
                d[key] = val

        if self.cert_is_expired:
            d["cert_is_expired"] = "1"
        if self.cert_is_self_signed:
            d["cert_is_self_signed"] = "1"
        if self.h2_matched_client is not None:
            d["h2_matched_client"] = self.h2_matched_client

        if self.tls_ext_values is not None:
            d["tls_ext_values"] = json.dumps(
                {
                    "supported_groups": self.tls_ext_values.supported_groups,
                    "key_share_groups": self.tls_ext_values.key_share_groups,
                    "sig_algs": self.tls_ext_values.sig_algs,
                    "psk_modes": self.tls_ext_values.psk_modes,
                    "grease_values": self.tls_ext_values.grease_values,
                    "has_compress_cert": self.tls_ext_values.has_compress_cert,
                    "has_alps": self.tls_ext_values.has_alps,
                    "padding_len": self.tls_ext_values.padding_len,
                    "session_ticket_len": self.tls_ext_values.session_ticket_len,
                },
                separators=(",", ":"),
            )

        if self.signals:
            d["signals"] = json.dumps(self.signals, separators=(",", ":"))

        return d

    @classmethod
    def from_redis_dict(cls, d: dict) -> "ConnectionFingerprints":
        """Deserialise from a Redis HGETALL dict (all string values)."""
        ts_raw = d.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except Exception:
            ts = datetime.now(tz=timezone.utc)

        tls_ext: Optional[JA4TLSExtValues] = None
        if "tls_ext_values" in d:
            try:
                raw = json.loads(d["tls_ext_values"])
                tls_ext = JA4TLSExtValues(
                    supported_groups=raw.get("supported_groups", []),
                    key_share_groups=raw.get("key_share_groups", []),
                    sig_algs=raw.get("sig_algs", []),
                    psk_modes=raw.get("psk_modes", []),
                    grease_values=raw.get("grease_values", []),
                    has_compress_cert=raw.get("has_compress_cert", False),
                    has_alps=raw.get("has_alps", False),
                    padding_len=raw.get("padding_len"),
                    session_ticket_len=raw.get("session_ticket_len", 0),
                )
            except Exception:
                pass

        signals: list[dict] = []
        if "signals" in d:
            try:
                signals = json.loads(d["signals"])
            except Exception:
                pass

        return cls(
            conn_id=d.get("conn_id", str(uuid.uuid4())),
            timestamp=ts,
            client_ip=d.get("client_ip", ""),
            server_ip=d.get("server_ip", ""),
            server_port=int(d.get("server_port", 0)),
            ja4=d.get("ja4"),
            ja4s=d.get("ja4s"),
            ja4t=d.get("ja4t"),
            ja4ts=d.get("ja4ts"),
            ja4h=d.get("ja4h"),
            ja4l=d.get("ja4l"),
            ja4x=d.get("ja4x"),
            ja4ssh=d.get("ja4ssh"),
            h2_fingerprint=d.get("h2_fingerprint"),
            quic_fingerprint=d.get("quic_fingerprint"),
            os_fingerprint=d.get("os_fingerprint"),
            tls_ext_values=tls_ext,
            os_detail=None,  # Not round-tripped via Redis (too complex)
            cert_is_expired=d.get("cert_is_expired") == "1",
            cert_is_self_signed=d.get("cert_is_self_signed") == "1",
            h2_matched_client=d.get("h2_matched_client"),
            risk_score=int(d.get("risk_score", 0)),
            action=d.get("action", "observe"),
            signals=signals,
        )
