"""Decompose a JA4 fingerprint into the facts it actually encodes.

WHY THIS EXISTS
---------------
A JA4 fingerprint is not an opaque hash. Its first segment is a structured,
human-readable summary of the TLS ClientHello, and the project had never
surfaced it anywhere — the console displayed the raw string and nothing else,
so "why was this blocked?" could only be answered with a score.

    t13d1516h2_8daaf6152771_b186095e22b6
    │ │ │ │  │  └── extensions + signature algorithms hash
    │ │ │ │  └───── cipher suite hash
    │ │ │ └──────── ALPN: first+last char of the negotiated protocol
    │ │ └────────── extension count
    │ └──────────── cipher count
    └────────────── transport, TLS version, SNI presence

Decoding costs nothing — the information is already in the string — and it is
what makes a block explicable to a human: "TLS 1.3, no SNI, 9 ciphers, no ALPN"
is a recognisable non-browser client in a way that a 12-character hash is not.

Spec: https://github.com/FoxIO-LLC/ja4 — JA4 is the client TLS fingerprint;
JA4S/JA4H/JA4X/JA4T are separate fingerprints with their own formats and are
NOT parsed here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# The a-segment is fixed width: 1 + 2 + 1 + 2 + 2 + 2.
_JA4_RE = re.compile(
    r"^(?P<transport>[a-z])"
    r"(?P<version>[0-9a-z]{2})"
    r"(?P<sni>[di])"
    r"(?P<ciphers>\d{2})"
    r"(?P<extensions>\d{2})"
    r"(?P<alpn>..)"
    r"_(?P<cipher_hash>[0-9a-f]{12})"
    r"_(?P<extension_hash>[0-9a-f]{12})$"
)

_TRANSPORT = {"t": "TCP", "q": "QUIC", "d": "DTLS"}
_VERSION = {
    "13": "TLS 1.3",
    "12": "TLS 1.2",
    "11": "TLS 1.1",
    "10": "TLS 1.0",
    "s3": "SSL 3.0",
    "s2": "SSL 2.0",
    "00": "unknown",
}
# ALPN is encoded as the first and last character of the protocol string, so
# "http/1.1" -> "h1" and "h2" -> "h2". Only the common values are named.
_ALPN = {
    "h2": "HTTP/2",
    "h1": "HTTP/1.1",
    "00": "none offered",
    "h3": "HTTP/3",
}


@dataclass
class Field:
    """One decoded component, ready to render."""

    label: str
    raw: str
    value: str
    note: str = ""


@dataclass
class DecodedJA4:
    valid: bool
    raw: str
    fields: List[Field] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    # Machine-readable, for callers that want to branch rather than display.
    parts: Dict[str, str] = field(default_factory=dict)

    @property
    def is_browser_like(self) -> Optional[bool]:
        """Heuristic only — deliberately not a verdict.

        Returns None when we cannot tell. ALPN is attacker-controlled (a bot
        can simply send h2), which is exactly why alpn_browser_bypass is OFF by
        default in this project. This property exists to caption a UI hint, and
        must never be used to allow or block.
        """
        if not self.valid:
            return None
        alpn = self.parts.get("alpn", "")
        if alpn == "00":
            return False
        if alpn in ("h2", "h1", "h3"):
            return True
        return None


def decode(ja4: str) -> DecodedJA4:
    """Parse a JA4 string. Never raises — an unparseable input is reported."""
    raw = (ja4 or "").strip()
    m = _JA4_RE.match(raw)
    if not m:
        return DecodedJA4(
            valid=False,
            raw=raw,
            error="Not a JA4 client fingerprint (expected a_b_c, e.g. "
            "t13d1516h2_8daaf6152771_b186095e22b6).",
        )

    g = m.groupdict()
    transport = _TRANSPORT.get(g["transport"], f"unknown ({g['transport']})")
    version = _VERSION.get(g["version"], f"unknown ({g['version']})")
    sni_present = g["sni"] == "d"
    alpn_raw = g["alpn"]
    alpn = _ALPN.get(alpn_raw, f"other ({alpn_raw})")

    fields = [
        Field(
            "Transport",
            g["transport"],
            transport,
            "QUIC implies HTTP/3." if transport == "QUIC" else "",
        ),
        Field(
            "TLS version",
            g["version"],
            version,
            "Below TLS 1.2 is obsolete and unusual from a current browser."
            if g["version"] in ("11", "10", "s3", "s2")
            else "",
        ),
        Field(
            "SNI",
            g["sni"],
            "present (connecting to a hostname)"
            if sni_present
            else "absent (connecting to a bare IP)",
            ""
            if sni_present
            else "Browsers effectively always send SNI; its absence suggests a "
            "scanner or a client addressing the IP directly.",
        ),
        Field(
            "Cipher suites",
            g["ciphers"],
            f"{int(g['ciphers'])} offered",
            "A short cipher list is typical of a purpose-built tool; browsers "
            "offer many for compatibility."
            if int(g["ciphers"]) <= 5
            else "",
        ),
        Field("Extensions", g["extensions"], f"{int(g['extensions'])} offered"),
        Field(
            "ALPN",
            alpn_raw,
            alpn,
            "No ALPN at all is common in scripted clients and C2 tooling. "
            "Note ALPN is attacker-controlled — it is a hint, not proof."
            if alpn_raw == "00"
            else "ALPN is attacker-controlled: a bot can send this too.",
        ),
        Field(
            "Cipher hash",
            g["cipher_hash"],
            "truncated SHA-256 of the cipher list",
            "Identical hashes mean an identical cipher list, in the same order.",
        ),
        Field(
            "Extension hash",
            g["extension_hash"],
            "truncated SHA-256 of extensions + signature algorithms",
        ),
    ]

    summary = (
        f"{transport}, {version}, SNI {'present' if sni_present else 'absent'}, "
        f"{int(g['ciphers'])} ciphers, {int(g['extensions'])} extensions, "
        f"ALPN {alpn}"
    )

    return DecodedJA4(valid=True, raw=raw, fields=fields, summary=summary, parts=g)
