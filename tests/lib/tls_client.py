"""Minimal TLS ClientHello builder and sender for integration tests.

Builds raw TLS 1.3 / 1.2 ClientHello messages without relying on a live TLS
stack.  Used to test proxy bypass decisions (ALPN, JA4 blacklist, etc.) by
sending crafted ClientHellos and observing whether the proxy accepts or RSTs.
"""
import os
import socket
import struct


def _pack_u8(v: int) -> bytes:
    return struct.pack("!B", v)


def _pack_u16(v: int) -> bytes:
    return struct.pack("!H", v)


def _pack_u24(v: int) -> bytes:
    return struct.pack("!I", v)[1:]  # 3 bytes big-endian


def _len_prefix(data: bytes, size: int) -> bytes:
    """Prefix *data* with its length encoded in *size* bytes."""
    if size == 1:
        return struct.pack("!B", len(data)) + data
    if size == 2:
        return struct.pack("!H", len(data)) + data
    if size == 3:
        return _pack_u24(len(data)) + data
    raise ValueError(f"unsupported size {size}")


def build_client_hello(
    alpn: list[str] | None = None,
    tls13: bool = True,
    sni: str = "example.com",
    ciphers: list[int] | None = None,
) -> bytes:
    """Build a minimal TLS ClientHello record.

    Parameters
    ----------
    alpn:  List of ALPN protocol names to advertise (e.g. ["h2"]).
    tls13: If True, offer TLS 1.3 cipher suites; otherwise TLS 1.2 suites.
    sni:   Server Name Indication hostname (empty string → no SNI extension).

    Returns the raw bytes of a complete TLS record (type 22, version 0x0301).
    """
    # Random (28 bytes) + session ID (0 bytes)
    random_bytes = os.urandom(28)
    gmt_unix_time = struct.pack("!I", 0)
    random_field = gmt_unix_time + random_bytes  # 32 bytes total

    session_id = b""  # empty

    # Cipher suites (caller can override for deterministic JA4 fingerprints)
    if ciphers is None:
        if tls13:
            ciphers = [
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2 compat)
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            ]
        else:
            ciphers = [
                0xC02C,
                0xC02B,
                0x009C,
                0x009D,
            ]
    cipher_data = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_suite_bytes = _len_prefix(cipher_data, 2)

    compression_methods = b"\x01\x00"  # 1 method: null

    # Extensions
    extensions = b""

    # SNI extension (type 0x0000)
    if sni:
        sni_bytes = sni.encode()
        server_name_list = _pack_u8(0) + _len_prefix(sni_bytes, 2)  # type=host_name
        sni_ext_data = _len_prefix(server_name_list, 2)
        extensions += _pack_u16(0x0000) + _len_prefix(sni_ext_data, 2)

    # Supported versions extension (type 0x002B) — required for TLS 1.3
    if tls13:
        versions = struct.pack("!HH", 0x0304, 0x0303)  # TLS 1.3, TLS 1.2
        extensions += _pack_u16(0x002B) + _len_prefix(_len_prefix(versions, 1), 2)

    # Supported groups (type 0x000A)
    groups = struct.pack("!HH", 0x001D, 0x0017)  # x25519, secp256r1
    extensions += _pack_u16(0x000A) + _len_prefix(_len_prefix(groups, 2), 2)

    # Signature algorithms (type 0x000D)
    sig_algs = struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0503)
    extensions += _pack_u16(0x000D) + _len_prefix(_len_prefix(sig_algs, 2), 2)

    # ALPN extension (type 0x0010)
    if alpn:
        proto_list = b"".join(_len_prefix(p.encode(), 1) for p in alpn)
        alpn_data = _len_prefix(proto_list, 2)
        extensions += _pack_u16(0x0010) + _len_prefix(alpn_data, 2)

    extensions_block = _len_prefix(extensions, 2)

    # ClientHello body
    legacy_version = b"\x03\x03"  # TLS 1.2 record version (always used for ClientHello)
    hello_body = (
        legacy_version
        + random_field
        + _len_prefix(session_id, 1)
        + cipher_suite_bytes
        + compression_methods
        + extensions_block
    )

    # Handshake header: type=1 (ClientHello), length
    handshake = _pack_u8(1) + _pack_u24(len(hello_body)) + hello_body

    # TLS record: type=22 (Handshake), legacy_version=0x0301, length
    record = b"\x16\x03\x01" + _len_prefix(handshake, 2)

    return record


def send_clienthello_and_check(
    host: str,
    port: int,
    hello: bytes,
    timeout: float = 3.0,
) -> dict:
    """Send a raw ClientHello to *host*:*port* and return connection state.

    Returns a dict with:
        connected (bool) — TCP connection was accepted
        rst       (bool) — connection was RST immediately
        response  (bytes) — first bytes received (may be empty)
    """
    result = {"connected": False, "rst": False, "response": b""}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["connected"] = True
        sock.settimeout(timeout)
        try:
            sock.sendall(hello)
            try:
                data = sock.recv(4096)
                result["response"] = data
            except (socket.timeout, ConnectionResetError):
                result["rst"] = True
        except ConnectionResetError:
            result["rst"] = True
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except ConnectionRefusedError:
        result["rst"] = True
    except OSError:
        pass
    return result
