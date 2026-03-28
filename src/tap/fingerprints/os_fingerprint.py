"""
OS fingerprinting from TCP SYN options (p0f-style) (Phase 20, Group 5-I).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.tap.fingerprints.ja4t import (
    extract_ja4t_from_syn,
)


@dataclass
class OSSignature:
    """A single OS fingerprint entry from the database."""

    fingerprint_id: str
    label: str
    window_sizes: list[int]  # [0] means "any"
    mss: Optional[int]  # None = any
    options_order: str
    wscale: Optional[int]  # None = any
    ttl_range: tuple[int, int]  # (min, max) inclusive
    df: Optional[bool]  # None = don't care


@dataclass
class OSFingerprintResult:
    """OS fingerprint match result."""

    fingerprint_id: str
    label: str
    confidence: float
    ttl: int
    df: bool
    window_size: int
    mss: Optional[int]
    wscale: Optional[int]
    options_str: str
    raw_hash: str


# Built-in minimal OS database — covers the most common cases.
_BUILTIN_DB: list[OSSignature] = [
    OSSignature(
        fingerprint_id="linux_5x_default",
        label="Linux 5.x (default)",
        window_sizes=[29200, 65160, 65535],
        mss=1460,
        options_order="MSTNW",
        wscale=None,  # any
        ttl_range=(60, 64),
        df=True,
    ),
    OSSignature(
        fingerprint_id="linux_4x_default",
        label="Linux 4.x (default)",
        window_sizes=[29200, 65160],
        mss=1460,
        options_order="MSTNW",
        wscale=None,
        ttl_range=(60, 64),
        df=True,
    ),
    OSSignature(
        fingerprint_id="windows_10_default",
        label="Windows 10/11",
        window_sizes=[65535, 8192, 64240],
        mss=1460,
        options_order="MSNWT",
        wscale=8,
        ttl_range=(112, 128),
        df=True,
    ),
    OSSignature(
        fingerprint_id="windows_server_2019",
        label="Windows Server 2019/2022",
        window_sizes=[65535, 64240],
        mss=1460,
        options_order="MSNWT",
        wscale=8,
        ttl_range=(112, 128),
        df=True,
    ),
    OSSignature(
        fingerprint_id="macos_11x_default",
        label="macOS 11+ (Big Sur/Ventura/Sonoma)",
        window_sizes=[65535],
        mss=1460,
        options_order="MNWST",
        wscale=6,
        ttl_range=(60, 64),
        df=True,
    ),
    OSSignature(
        fingerprint_id="freebsd_13x",
        label="FreeBSD 13.x",
        window_sizes=[65535],
        mss=1460,
        options_order="MNWST",
        wscale=6,
        ttl_range=(60, 64),
        df=True,
    ),
]


def load_os_database(path: Path) -> list[OSSignature]:
    """Load OS signature database from a YAML file.

    Falls back to the built-in database on any error.
    """
    try:
        import yaml  # type: ignore[import]

        with open(path) as f:
            raw = yaml.safe_load(f)

        sigs: list[OSSignature] = []
        for entry in raw.get("signatures", []):
            sigs.append(
                OSSignature(
                    fingerprint_id=entry["id"],
                    label=entry["label"],
                    window_sizes=entry.get("window_sizes", [0]),
                    mss=entry.get("mss"),
                    options_order=entry.get("options_order", ""),
                    wscale=entry.get("wscale"),
                    ttl_range=tuple(entry.get("ttl_range", [1, 255])),
                    df=entry.get("df"),
                )
            )
        return sigs if sigs else list(_BUILTIN_DB)
    except Exception:
        return list(_BUILTIN_DB)


def match_os(
    syn_tcp_opts: bytes,
    window_size: int,
    ttl: int,
    df: bool,
    database: Optional[list[OSSignature]] = None,
) -> OSFingerprintResult:
    """Match SYN options against the OS database.

    Args:
        syn_tcp_opts: Raw TCP options bytes from SYN packet.
        window_size:  TCP window size.
        ttl:          IP TTL.
        df:           IP DF (Don't Fragment) bit.
        database:     OS signature database; uses built-in if None.

    Returns:
        OSFingerprintResult — always returns; never raises.
    """
    try:
        return _match(syn_tcp_opts, window_size, ttl, df, database or _BUILTIN_DB)
    except Exception:
        return _unknown(syn_tcp_opts, window_size, ttl, df)


def _match(
    opts: bytes,
    window_size: int,
    ttl: int,
    df: bool,
    db: list[OSSignature],
) -> OSFingerprintResult:
    ja4t = extract_ja4t_from_syn(opts, window_size)
    options_str = ja4t.options_order
    raw_hash = ja4t.fingerprint

    best_sig: Optional[OSSignature] = None
    best_score = -1.0

    for sig in db:
        score = _score(
            sig, window_size, ja4t.mss, options_str, ja4t.window_scale, ttl, df
        )
        if score > best_score:
            best_score = score
            best_sig = sig

    confidence = min(best_score / 5.0, 1.0) if best_score > 0 else 0.0

    if best_sig is not None and confidence > 0.2:
        return OSFingerprintResult(
            fingerprint_id=best_sig.fingerprint_id,
            label=best_sig.label,
            confidence=confidence,
            ttl=ttl,
            df=df,
            window_size=window_size,
            mss=ja4t.mss,
            wscale=ja4t.window_scale,
            options_str=options_str,
            raw_hash=raw_hash,
        )

    return _unknown(opts, window_size, ttl, df)


def _score(
    sig: OSSignature,
    window_size: int,
    mss: Optional[int],
    options_order: str,
    wscale: Optional[int],
    ttl: int,
    df: bool,
) -> float:
    score = 0.0

    # Window size match (high weight)
    if 0 in sig.window_sizes or window_size in sig.window_sizes:
        score += 2.0

    # MSS match
    if sig.mss is None or sig.mss == mss:
        score += 1.0

    # Options order match (fuzzy: check if signature order is a prefix/suffix)
    if sig.options_order and options_order:
        if sig.options_order == options_order:
            score += 2.0
        elif sig.options_order in options_order or options_order in sig.options_order:
            score += 0.5

    # TTL match
    lo, hi = sig.ttl_range
    if lo <= ttl <= hi:
        score += 1.0

    # DF bit match
    if sig.df is None or sig.df == df:
        score += 0.5

    # Window scale
    if sig.wscale is None or sig.wscale == wscale:
        score += 0.5

    return score


def _unknown(
    opts: bytes,
    window_size: int,
    ttl: int,
    df: bool,
) -> OSFingerprintResult:
    return OSFingerprintResult(
        fingerprint_id="unknown",
        label="Unknown",
        confidence=0.0,
        ttl=ttl,
        df=df,
        window_size=window_size,
        mss=None,
        wscale=None,
        options_str="",
        raw_hash="",
    )
