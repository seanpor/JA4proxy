"""
HTTP/2 SETTINGS frame fingerprint extractor (Phase 20, Group 5-J).

Parses the HTTP/2 connection preface and SETTINGS frame from a reassembled
stream and matches it against a database of known client fingerprints.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# HTTP/2 SETTINGS frame constants
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_FRAME_TYPE_SETTINGS = 0x4
_FRAME_TYPE_WINDOW_UPDATE = 0x8

# SETTINGS parameter IDs
_SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE",
    0x2: "ENABLE_PUSH",
    0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE",
    0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE",
    0x8: "ENABLE_CONNECT_PROTOCOL",
    0xf010: "NO_RFC7540_PRIORITIES",
}


@dataclass
class H2Signature:
    """A known HTTP/2 client fingerprint entry."""

    client_id: str
    settings_order: list[str]     # parameter names in send order
    settings: dict[str, int]      # name → value
    window_update: Optional[int]  # WINDOW_UPDATE increment value, or None if not sent


@dataclass
class H2FingerprintResult:
    """HTTP/2 SETTINGS fingerprint result."""

    fingerprint: str
    settings: dict[str, int]
    settings_order: list[str]
    window_update_increment: Optional[int]
    matched_client: Optional[str]
    confidence: float


# Minimal built-in database
_BUILTIN_DB: list[H2Signature] = [
    H2Signature(
        client_id="chrome_120",
        settings_order=[
            "HEADER_TABLE_SIZE",
            "ENABLE_PUSH",
            "INITIAL_WINDOW_SIZE",
            "MAX_HEADER_LIST_SIZE",
        ],
        settings={
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_HEADER_LIST_SIZE": 262144,
        },
        window_update=15663105,
    ),
    H2Signature(
        client_id="firefox_121",
        settings_order=[
            "HEADER_TABLE_SIZE",
            "INITIAL_WINDOW_SIZE",
            "MAX_FRAME_SIZE",
        ],
        settings={
            "HEADER_TABLE_SIZE": 65536,
            "INITIAL_WINDOW_SIZE": 131072,
            "MAX_FRAME_SIZE": 16384,
        },
        window_update=12517377,
    ),
    H2Signature(
        client_id="curl",
        settings_order=["MAX_CONCURRENT_STREAMS"],
        settings={"MAX_CONCURRENT_STREAMS": 100},
        window_update=None,
    ),
]


def load_h2_database(path: Path) -> list[H2Signature]:
    """Load HTTP/2 client signature database from a YAML file."""
    try:
        import yaml  # type: ignore[import]

        with open(path) as f:
            raw = yaml.safe_load(f)

        sigs: list[H2Signature] = []
        for entry in raw.get("signatures", []):
            sigs.append(
                H2Signature(
                    client_id=entry["id"],
                    settings_order=entry.get("settings_order", []),
                    settings=entry.get("settings", {}),
                    window_update=entry.get("window_update"),
                )
            )
        return sigs if sigs else list(_BUILTIN_DB)
    except Exception:
        return list(_BUILTIN_DB)


def extract_h2_fingerprint(
    http2_stream: bytes,
    database: Optional[list[H2Signature]] = None,
) -> Optional[H2FingerprintResult]:
    """Parse HTTP/2 stream bytes and extract SETTINGS frame fingerprint.

    Args:
        http2_stream: Reassembled HTTP/2 stream bytes, starting from the
            client connection preface or the first frame.
        database:     Known fingerprint database; uses built-in if None.

    Returns:
        H2FingerprintResult on success, None on non-HTTP/2 or malformed input.
    """
    try:
        return _parse(http2_stream, database or _BUILTIN_DB)
    except Exception:
        return None


def _parse(
    data: bytes,
    db: list[H2Signature],
) -> Optional[H2FingerprintResult]:
    pos = 0

    # Skip the client connection preface if present
    if data[:len(_H2_PREFACE)] == _H2_PREFACE:
        pos += len(_H2_PREFACE)

    settings: dict[str, int] = {}
    settings_order: list[str] = []
    window_update: Optional[int] = None
    found_settings = False

    # Parse frames until we find SETTINGS (and optionally WINDOW_UPDATE)
    while pos + 9 <= len(data):
        frame_len = struct.unpack_from("!I", bytes([0]) + data[pos:pos + 3])[0]
        frame_type = data[pos + 3]
        _flags = data[pos + 4]
        _stream_id = struct.unpack_from("!I", data, pos + 5)[0] & 0x7FFFFFFF
        payload = data[pos + 9:pos + 9 + frame_len]
        pos += 9 + frame_len

        if frame_type == _FRAME_TYPE_SETTINGS:
            found_settings = True
            # Each setting is 6 bytes: identifier (2) + value (4)
            for i in range(0, len(payload) - 5, 6):
                ident = struct.unpack_from("!H", payload, i)[0]
                value = struct.unpack_from("!I", payload, i + 2)[0]
                name = _SETTINGS_NAMES.get(ident, f"0x{ident:04x}")
                settings[name] = value
                settings_order.append(name)

        elif frame_type == _FRAME_TYPE_WINDOW_UPDATE and len(payload) >= 4:
            window_update = struct.unpack_from("!I", payload)[0] & 0x7FFFFFFF

        # Stop after we have SETTINGS and possibly WINDOW_UPDATE
        if found_settings and window_update is not None:
            break

    if not found_settings:
        return None

    # Compute fingerprint hash
    settings_str = ",".join(
        f"{k}={settings[k]}" for k in settings_order
    )
    wu_str = str(window_update) if window_update is not None else "none"
    fp_hash = hashlib.sha256(f"{settings_str}|wu={wu_str}".encode()).hexdigest()[:12]
    fingerprint = f"h2_{fp_hash}"

    # Match against database
    matched_client, confidence = _match_db(settings, settings_order, window_update, db)

    return H2FingerprintResult(
        fingerprint=fingerprint,
        settings=settings,
        settings_order=settings_order,
        window_update_increment=window_update,
        matched_client=matched_client,
        confidence=confidence,
    )


def _match_db(
    settings: dict,
    order: list,
    window_update: Optional[int],
    db: list[H2Signature],
) -> tuple[Optional[str], float]:
    best_client: Optional[str] = None
    best_score = 0.0

    for sig in db:
        score = 0.0
        total = len(sig.settings) + (1 if sig.window_update is not None else 0)
        if total == 0:
            continue

        # Settings values
        for name, expected in sig.settings.items():
            if settings.get(name) == expected:
                score += 1.0

        # Window update
        if sig.window_update is not None:
            if window_update == sig.window_update:
                score += 1.0

        # Settings order bonus
        if sig.settings_order == order:
            score += 0.5

        conf = score / (total + 0.5)
        if conf > best_score:
            best_score = conf
            best_client = sig.client_id

    return (best_client, min(best_score, 1.0)) if best_score > 0.3 else (None, 0.0)
