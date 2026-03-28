"""
JA4H — HTTP/1.1 header fingerprint extractor (Phase 20, Group 5-D).

Parses reassembled HTTP/1.1 request bytes and returns a JA4HResult.
Format: {method}{version}{cookie?}{referer?}{header_count:02d}{accept_language_hash}_{header_name_hash}_{cookie_value_hash}
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class JA4HResult:
    """HTTP/1.1 header fingerprint."""

    fingerprint: str
    method: str
    http_version: str
    headers: dict[str, str]
    accept_language: Optional[str]
    user_agent: Optional[str]
    cookie_count: int
    referer: Optional[str]


def extract_ja4h(http_request: bytes) -> Optional[JA4HResult]:
    """Parse HTTP/1.1 request bytes and return JA4H fingerprint.

    Args:
        http_request: Reassembled HTTP request bytes.

    Returns:
        JA4HResult on success, None if headers are incomplete or non-HTTP.
    """
    try:
        return _parse(http_request)
    except Exception:
        return None


def _parse(data: bytes) -> Optional[JA4HResult]:
    # Must have complete headers (terminated by \\r\\n\\r\\n)
    try:
        text = data.decode("latin-1", errors="replace")
    except Exception:
        return None

    sep = "\r\n\r\n"
    if sep not in text:
        return None

    header_section = text.split(sep, 1)[0]
    lines = header_section.split("\r\n")
    if not lines:
        return None

    # Request line
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 3:
        return None
    method = parts[0].upper()
    # Validate method is a reasonable HTTP verb
    if not method.isalpha() or len(method) > 20:
        return None
    http_version_raw = parts[2]
    if http_version_raw.startswith("HTTP/"):
        ver = http_version_raw[5:]
        if ver == "1.1":
            http_version = "11"
        elif ver == "1.0":
            http_version = "10"
        elif ver == "2":
            http_version = "20"
        else:
            http_version = ver.replace(".", "")[:2]
    else:
        return None

    # Parse headers preserving order
    headers: dict[str, str] = {}
    header_names_ordered: list[str] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name_lower = name.strip().lower()
        value_stripped = value.strip()
        headers[name_lower] = value_stripped
        header_names_ordered.append(name_lower)

    accept_language = headers.get("accept-language")
    user_agent = headers.get("user-agent")
    referer = headers.get("referer") or headers.get("referrer")

    # Count cookies
    cookie_header = headers.get("cookie", "")
    cookie_count = len([c for c in cookie_header.split(";") if c.strip()]) if cookie_header else 0
    has_cookie = "c" if cookie_count > 0 else "n"
    has_referer = "r" if referer else "n"

    header_count = len(header_names_ordered)

    # Hash 1: sorted header names (excluding cookie and referer values)
    lang_hash = _hash12(accept_language or "")
    name_hash = _hash_header_names(header_names_ordered)
    cookie_hash = _hash12(cookie_header)

    fingerprint = (
        f"{method[:2].lower()}{http_version}{has_cookie}{has_referer}"
        f"{header_count:02d}{lang_hash}_{name_hash}_{cookie_hash}"
    )

    return JA4HResult(
        fingerprint=fingerprint,
        method=method,
        http_version=http_version,
        headers=headers,
        accept_language=accept_language,
        user_agent=user_agent,
        cookie_count=cookie_count,
        referer=referer,
    )


def _hash12(s: str) -> str:
    if not s:
        return "000000000000"
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]


def _hash_header_names(names: list) -> str:
    """Hash the ordered list of header names (excluding Cookie/Referer for privacy)."""
    filtered = [n for n in names if n not in ("cookie", "referer", "referrer")]
    if not filtered:
        return "000000000000"
    s = ",".join(filtered)
    return hashlib.sha256(s.encode()).hexdigest()[:12]
