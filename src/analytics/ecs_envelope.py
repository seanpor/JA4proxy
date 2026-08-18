"""Translate the proxy's ECS stream envelope into the analytics event schema.

WHY THIS EXISTS
---------------
The Go proxy and this analytics node were written against each other but never
actually connected: a blocking-read bug (phase-826 layer 1) meant the consumer
had never read a single event, so the fact that the two ends speak different
schemas was invisible until 2026-08-17.

The proxy XADDs ONE field, ``event``, holding an ECS JSON document:

    {"@timestamp": "...", "event.action": "allow", "event.risk_score": 35,
     "source.ip": "1.2.3.4", "ja4proxy.fingerprint.ja4": "t13d...",
     "ja4proxy.node_id": "...", ...}

The consumer's schema (``event_schemas.EVENT_SCHEMA``) wants flat, differently
named fields: ``timestamp`` (epoch seconds), ``src_ip``, ``score``, ``action``,
``ja4``, ``proxy_id``.

ECS is the format that wins: it is the documented, standards-based shape
already used for webhook/SIEM delivery, and adapting here keeps the change off
the proxy's hot path.

SIGNATURE HANDLING
------------------
The HMAC covers the raw ``event`` string exactly as it arrived on the wire, not
a re-encoded object. Verifying a reconstructed dict would require Go's and
Python's JSON encoders to agree on key order, float formatting and unicode
escaping — they do not reliably, and the resulting failures would be silent and
traffic-dependent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Dict, Optional

# Actions the proxy's decider can emit. The original set omitted flag,
# rate_limit and ban — and rate_limit is the only non-allow action a
# monitor-mode deployment produces in volume, so those events were rejected
# precisely when they were most interesting.
VALID_ACTIONS = ("allow", "block", "monitor", "tarpit", "flag", "rate_limit", "ban")

_ENVELOPE_FIELD = "event"
_SIGNATURE_FIELD = "hmac"


def is_ecs_envelope(entry: Dict[str, Any]) -> bool:
    """True if a stream entry is the proxy's ECS envelope rather than a flat event."""
    return _ENVELOPE_FIELD in entry


def verify_envelope_signature(entry: Dict[str, Any], secret: str) -> bool:
    """Constant-time HMAC-SHA256 check over the raw envelope bytes."""
    signature = entry.get(_SIGNATURE_FIELD)
    if not signature:
        return False
    raw = entry.get(_ENVELOPE_FIELD) or ""
    if isinstance(raw, str):
        raw = raw.encode()
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _epoch(value: Any) -> Optional[float]:
    """RFC3339 (with or without nanoseconds) or a number -> epoch seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    # Python's fromisoformat rejects more than 6 fractional digits; Go's
    # RFC3339Nano emits up to 9.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        for ch in tail:
            if ch.isdigit():
                digits += ch
            else:
                tail = tail[len(digits):]
                break
        else:
            tail = ""
        text = f"{head}.{digits[:6]}{tail}"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def normalise(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten an ECS envelope into the analytics event schema.

    Returns the parsed event with both the mapped names and the original ECS
    keys retained (EVENT_SCHEMA sets additionalProperties: True), so downstream
    detectors can reach fields this mapping does not rename.

    Raises ValueError if the envelope is not parseable — the caller treats that
    as an invalid event rather than crashing the consumer loop.
    """
    raw = entry.get(_ENVELOPE_FIELD)
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        ecs = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unparseable ECS envelope: {exc}") from exc
    if not isinstance(ecs, dict):
        raise ValueError("ECS envelope is not a JSON object")

    out: Dict[str, Any] = dict(ecs)

    ts = _epoch(ecs.get("@timestamp"))
    if ts is not None:
        out["timestamp"] = ts
    if "source.ip" in ecs:
        out["src_ip"] = ecs["source.ip"]
    if "event.risk_score" in ecs:
        out["score"] = ecs["event.risk_score"]
    if "event.action" in ecs:
        out["action"] = ecs["event.action"]
    if "ja4proxy.fingerprint.ja4" in ecs:
        out["ja4"] = ecs["ja4proxy.fingerprint.ja4"]
    # node_id is the per-instance identifier; service.name is a constant and
    # would make every node indistinguishable, so it is only a last resort.
    proxy_id = ecs.get("ja4proxy.node_id") or ecs.get("service.name")
    if proxy_id:
        out["proxy_id"] = proxy_id

    # Carry the signature through so it is not mistaken for an unsigned event.
    if _SIGNATURE_FIELD in entry:
        out[_SIGNATURE_FIELD] = entry[_SIGNATURE_FIELD]
    return out
