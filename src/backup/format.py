"""
Binary format for JA4proxy backup artifacts.

Format: a sequence of length-prefixed entries. Each entry encodes one Redis key
and its serialized value (as returned by Redis DUMP):

    [4 bytes: big-endian uint32 key_length]
    [key_length bytes: UTF-8 key name]
    [4 bytes: big-endian uint32 value_length]
    [value_length bytes: Redis DUMP-format value]

The format is self-describing and does not require a separate header. Decoders
read until the data is exhausted or a truncated entry is encountered (which
terminates iteration gracefully).

Restore uses ``redis.restore(key, 0, dump_data, replace=True)`` which handles
all Redis data types transparently.
"""

import struct
from collections.abc import Iterator


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

    Iterates entries until the data is exhausted or a truncated/corrupt entry
    is encountered. Truncated trailing bytes are silently skipped (consistent
    with Redis RDB behaviour).

    Args:
        data: Raw bytes from a backup artifact file.

    Yields:
        (key_name, dump_data) tuples in the order they were backed up.
    """
    offset = 0
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
