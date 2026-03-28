"""
JA4SSH — SSH client/server fingerprint extractor (Phase 20, Group 5-G).

Parses a raw SSH_MSG_KEXINIT payload and returns a JA4SSHResult.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class JA4SSHResult:
    """SSH client or server fingerprint from KEXINIT."""

    fingerprint: str
    direction: str  # "client" | "server"
    kex_algorithms: list[str]
    host_key_algorithms: list[str]
    encryption_client_to_server: list[str]
    encryption_server_to_client: list[str]
    mac_client_to_server: list[str]
    mac_server_to_client: list[str]
    compression_client_to_server: list[str]


def extract_ja4ssh(
    kexinit_payload: bytes,
    direction: str,
) -> Optional[JA4SSHResult]:
    """Parse a raw SSH KEXINIT payload and return JA4SSH fingerprint.

    Args:
        kexinit_payload: Raw bytes of the SSH KEXINIT message, starting
            immediately after the SSH binary packet framing, i.e. the first
            byte is the message type byte (0x14 = MSG_KEXINIT).
        direction: ``"client"`` or ``"server"``.

    Returns:
        JA4SSHResult on success, None on malformed / incomplete input.
    """
    try:
        return _parse(kexinit_payload, direction)
    except Exception:
        return None


def _parse(data: bytes, direction: str) -> Optional[JA4SSHResult]:
    if not data:
        return None

    pos = 0

    # Message type byte (0x14 = SSH_MSG_KEXINIT)
    if data[0] != 0x14:
        return None
    pos += 1

    # Cookie (16 random bytes)
    if pos + 16 > len(data):
        return None
    pos += 16

    # Read 10 name-list fields
    lists: list[list[str]] = []
    for _ in range(10):
        lst, pos = _read_name_list(data, pos)
        if lst is None:
            return None
        lists.append(lst)

    (
        kex_algorithms,
        host_key_algorithms,
        enc_c2s,
        enc_s2c,
        mac_c2s,
        mac_s2c,
        comp_c2s,
        comp_s2c,
        _lang_c2s,
        _lang_s2c,
    ) = lists

    # Compute JA4SSH fingerprint
    dir_char = "c" if direction == "client" else "s"
    kex_hash = _hash12(",".join(kex_algorithms))
    enc_hash = _hash12(",".join(enc_c2s if direction == "client" else enc_s2c))
    mac_hash = _hash12(",".join(mac_c2s if direction == "client" else mac_s2c))

    kex_count = len(kex_algorithms)
    enc_count = len(enc_c2s)

    fingerprint = (
        f"ja4ssh_{dir_char}{kex_count:02d}{enc_count:02d}"
        f"_{kex_hash}_{enc_hash}_{mac_hash}"
    )

    return JA4SSHResult(
        fingerprint=fingerprint,
        direction=direction,
        kex_algorithms=kex_algorithms,
        host_key_algorithms=host_key_algorithms,
        encryption_client_to_server=enc_c2s,
        encryption_server_to_client=enc_s2c,
        mac_client_to_server=mac_c2s,
        mac_server_to_client=mac_s2c,
        compression_client_to_server=comp_c2s,
    )


def _read_name_list(data: bytes, pos: int) -> tuple[Optional[list[str]], int]:
    """Read an SSH name-list (uint32 length-prefixed comma-separated string)."""
    if pos + 4 > len(data):
        return None, pos
    length = struct.unpack_from("!I", data, pos)[0]
    pos += 4
    if pos + length > len(data):
        return None, pos
    raw = data[pos : pos + length].decode("ascii", errors="ignore")
    pos += length
    names = [n for n in raw.split(",") if n] if raw else []
    return names, pos


def _hash12(s: str) -> str:
    if not s:
        return "000000000000"
    return hashlib.sha256(s.encode()).hexdigest()[:12]
