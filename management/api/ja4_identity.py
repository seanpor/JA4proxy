"""Name a JA4 fingerprint: "Chrome on Windows", "Cobalt Strike Beacon".

WHY THIS EXISTS
---------------
`ja4_decode.py` explains a fingerprint's STRUCTURE — TLS 1.3, 12 ciphers, ALPN
h2. Useful, but it cannot tell an operator the thing they actually want to know:
*what is this*. A console that shows `t13d1516h2_8daaf6152771_b0da82dd1658` and
a score is asking the person under incident pressure to be a JA4 expert.

Two sources, deliberately kept apart because their trust levels differ:

  * config/known_bad_fingerprints.yml — research-quality tool fingerprints with
    a category, a citation and a confidence. Already shipped for the Phase 85
    seed feed; reused here rather than duplicated.
  * config/known_clients.yml — benign client software.

IMPORTANT: an identification is a LABEL, never a verdict. A JA4 is not a
signature — it describes a TLS stack, and different software sharing a stack
shares a fingerprint. Anything derived from a library (Python requests, Go
net/http, curl) will collide with every other user of that library, benign or
not. So the console must present the name, the confidence and the source, and
must never let a name alone drive an allow/block decision. Naming a fingerprint
"Chrome on Windows" makes it *explicable*, not *trusted* — that is what the JA4
whitelist is for, and it is an explicit operator action.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWN_BAD = REPO_ROOT / "config" / "known_bad_fingerprints.yml"
KNOWN_CLIENTS = REPO_ROOT / "config" / "known_clients.yml"


@dataclass(frozen=True)
class Identity:
    """What we believe a fingerprint is, and how much to trust that."""

    name: str
    category: str
    source: str
    confidence: int
    malicious: bool

    @property
    def badge(self) -> str:
        """Short label for the UI."""
        return "Known tool" if self.malicious else "Known client"

    @property
    def caveat(self) -> str:
        """Always shown beside the name. A fingerprint is not an identity."""
        if self.malicious:
            return (
                "Research-quality attribution. A JA4 describes a TLS stack, so "
                "unrelated software built on the same library shares it — treat "
                "as a strong hint, not proof."
            )
        return (
            "Identifies the TLS stack, not the user. A bot using the same "
            "library presents the same fingerprint, which is why naming a "
            "client never allows it — only the JA4 whitelist does."
        )


def _load(path: Path) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return []  # fail open: an unreadable catalogue must not break the page
    entries = data.get("fingerprints") or []
    return entries if isinstance(entries, list) else []


@functools.lru_cache(maxsize=1)
def _catalogue() -> dict[str, Identity]:
    """JA4 -> Identity. Built once; the files are read-only config."""
    out: dict[str, Identity] = {}
    for entry in _load(KNOWN_CLIENTS):
        ja4 = str(entry.get("ja4", "")).strip()
        if ja4:
            out[ja4] = Identity(
                name=str(entry.get("name", "Unknown client")),
                category=str(entry.get("category", "client")),
                source=str(entry.get("source", "")),
                confidence=int(entry.get("confidence", 0) or 0),
                malicious=False,
            )
    # Known-bad wins a collision: if a fingerprint appears in both lists that is
    # itself the interesting fact, and under-warning is the worse error.
    for entry in _load(KNOWN_BAD):
        ja4 = str(entry.get("ja4", "")).strip()
        if ja4:
            out[ja4] = Identity(
                name=str(entry.get("name", "Unknown tool")),
                category=str(entry.get("category", "tool")),
                source=str(entry.get("source", "")),
                confidence=int(entry.get("confidence", 0) or 0),
                malicious=True,
            )
    return out


def identify(ja4: Optional[str]) -> Optional[Identity]:
    """Return what this fingerprint is, or None if we have never seen it.

    None is the common case and an honest answer — most real traffic is not in
    any catalogue. The UI must say "not in the catalogue", never imply the
    fingerprint is therefore safe or suspicious.
    """
    if not ja4 or not isinstance(ja4, str):
        return None
    return _catalogue().get(ja4.strip())
