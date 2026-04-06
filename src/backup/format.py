"""
Binary format for JA4proxy backup artifacts.

Legacy format (no header): a sequence of length-prefixed entries. Each entry
encodes one Redis key and its serialized value (as returned by Redis DUMP):

    [4 bytes: big-endian uint32 key_length]
    [key_length bytes: UTF-8 key name]
    [4 bytes: big-endian uint32 value_length]
    [value_length bytes: Redis DUMP-format value]

New format (Phase 57a+): a 9-byte header prepended before the entry stream:

    [4 bytes: magic "JA4B"]
    [1 byte:  format version (currently 1)]
    [4 bytes: big-endian uint32 flags bitmask]
    <entry stream as before>

The format is backward-compatible. ``decode_entries()`` transparently handles
both old (no header) and new (with header) artifacts.

Restore uses ``redis.restore(key, 0, dump_data, replace=True)`` which handles
all Redis data types transparently.
"""

import struct
from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Header constants (Phase 57a)
# ---------------------------------------------------------------------------

MAGIC = b"JA4B"
FORMAT_VERSION = 1
HEADER_SIZE = 9  # 4 (magic) + 1 (version) + 4 (flags)

# Flags bitmask values
FLAG_FULL = 0x01
FLAG_INCREMENTAL = 0x02
FLAG_ENCRYPTED = 0x04

_BACKUP_TYPE_TO_FLAG: dict[str, int] = {
    "full": FLAG_FULL,
    "incremental": FLAG_INCREMENTAL,
}
_FLAG_TO_BACKUP_TYPE: dict[int, str] = {
    FLAG_FULL: "full",
    FLAG_INCREMENTAL: "incremental",
}


def encode_header(backup_type: str, flags: int) -> bytes:
    """Return a 9-byte header for new-format backup artifacts.

    Layout: [4B magic "JA4B"][1B version][4B flags big-endian uint32]

    Args:
        backup_type: ``"full"`` or ``"incremental"``.
        flags: Bitmask combining FLAG_FULL, FLAG_INCREMENTAL, FLAG_ENCRYPTED, etc.

    Returns:
        Exactly 9 bytes.
    """
    return MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">I", flags)


def decode_header(data: bytes) -> tuple[str, int]:
    """Decode a 9-byte backup artifact header.

    Args:
        data: Bytes starting at the beginning of a new-format artifact.

    Returns:
        ``(backup_type, flags)`` tuple where *backup_type* is ``"full"`` or
        ``"incremental"`` and *flags* is the raw bitmask integer.

    Raises:
        ValueError: If the magic bytes are wrong or data is too short.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Header too short: expected {HEADER_SIZE} bytes, got {len(data)}"
        )
    magic = data[:4]
    if magic != MAGIC:
        raise ValueError(f"Bad magic bytes: expected {MAGIC!r}, got {magic!r}")

    (flags,) = struct.unpack(">I", data[5:9])

    # Resolve the primary backup type from flags (FULL takes precedence)
    if flags & FLAG_FULL:
        backup_type = "full"
    elif flags & FLAG_INCREMENTAL:
        backup_type = "incremental"
    else:
        backup_type = "full"  # default / unknown

    return backup_type, flags


def is_legacy_format(data: bytes) -> bool:
    """Return True if *data* does NOT start with the JA4B magic bytes.

    Old-format backup artifacts begin with a 4-byte big-endian uint32 key
    length.  New-format artifacts begin with ``b"JA4B"``.  A false positive
    (a legacy key whose first 4 bytes happen to equal ``b"JA4B"``) is
    astronomically unlikely with real Redis key names.

    Args:
        data: Raw bytes from a backup artifact file (or the beginning thereof).

    Returns:
        ``True`` for legacy (pre-Phase-57a) artifacts; ``False`` for new-format.
    """
    if len(data) < 4:
        return True
    return data[:4] != MAGIC


def encode_entry(key: str, dump_data: bytes) -> bytes:
    """Encode a single key–value pair for backup storage.

    Args:
        key: Redis key name.
        dump_data: Redis DUMP-serialized value for the key.

    Returns:
        Length-prefixed binary encoding suitable for appending to a backup artifact.
    """
    key_bytes = key.encode("utf-8")
    return (
        struct.pack(">I", len(key_bytes))
        + key_bytes
        + struct.pack(">I", len(dump_data))
        + dump_data
    )


def decode_entries(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Decode all key–value pairs from backup artifact data.

    Transparently handles both legacy (no header) and new-format (9-byte
    ``JA4B`` header) artifacts.  The header, when present, is skipped before
    iterating entries.  Truncated trailing bytes are silently skipped
    (consistent with Redis RDB behaviour).

    Args:
        data: Raw bytes from a backup artifact file.

    Yields:
        (key_name, dump_data) tuples in the order they were backed up.
    """
    # Phase 57a: skip 9-byte header if present
    start_offset = HEADER_SIZE if not is_legacy_format(data) else 0

    offset = start_offset
    total = len(data)

    while offset < total:
        # Read key length
        if offset + 4 > total:
            break
        (key_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4

        # Read key name
        if offset + key_len > total:
            break
        key = data[offset : offset + key_len].decode("utf-8")
        offset += key_len

        # Read value length
        if offset + 4 > total:
            break
        (val_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4

        # Read value
        if offset + val_len > total:
            break
        val = data[offset : offset + val_len]
        offset += val_len

        yield key, val
