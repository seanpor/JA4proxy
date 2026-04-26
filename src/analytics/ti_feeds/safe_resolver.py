"""SSRF protection utilities for threat-intel feed clients.

Provides is_publicly_routable_ip() to block RFC1918 private IPs, loopback, and link-local,
and SafeResolver — an aiohttp.AbstractResolver subclass that fails closed on private
resolutions so DNS-level SSRF cannot reach link-local / RFC1918 / cloud metadata hosts.
"""

from __future__ import annotations

import ipaddress
import logging
import socket

try:  # pragma: no cover - aiohttp is a runtime dep for the feed clients
    from aiohttp.abc import AbstractResolver
    from aiohttp.resolver import DefaultResolver
except ImportError:  # pragma: no cover
    AbstractResolver = object  # type: ignore[assignment,misc]
    DefaultResolver = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_IPV4_PRIVATE = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_IPV6_PRIVATE = (
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)
_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")
_LINK_LOCAL = ipaddress.IPv4Network("169.254.0.0/16")


def is_publicly_routable_ip(ip_str: str) -> bool:
    """Check if an IP is publicly routable.

    Returns False for RFC1918, loopback, link-local, cloud metadata
    (169.254.169.254), and reserved ranges. Also unwraps IPv6
    encapsulations (IPv4-mapped, 6to4, Teredo) so an IPv6-encoded
    private IPv4 can't slip past the check.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if isinstance(ip, ipaddress.IPv6Address):
        # Unwrap IPv4-mapped (::ffff:a.b.c.d)
        if ip.ipv4_mapped is not None:
            return is_publicly_routable_ip(str(ip.ipv4_mapped))
        # Unwrap 6to4 (2002::/16 embeds an IPv4)
        if ip.sixtofour is not None:
            return is_publicly_routable_ip(str(ip.sixtofour))
        # Unwrap Teredo (2001::/32)
        if ip.teredo is not None:
            _, client_ipv4 = ip.teredo
            return is_publicly_routable_ip(str(client_ipv4))

    if ip.is_loopback:
        return False
    if ip.is_multicast:
        return False
    if ip.is_unspecified:
        return False
    if ip.is_reserved:
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        for v4net in _IPV4_PRIVATE:
            if ip in v4net:
                return False
        if ip in _LINK_LOCAL:
            return False
    elif isinstance(ip, ipaddress.IPv6Address):
        for v6net in _IPV6_PRIVATE:
            if ip in v6net:
                return False
        if ip.is_link_local:
            return False

    return True


class SafeResolver(AbstractResolver):
    """aiohttp resolver wrapper that rejects private/metadata IPs post-DNS.

    The inner resolver (aiohttp's DefaultResolver) does the actual lookup; we
    filter the result set. If every resolved address is private, raise
    ``PermissionError`` — wrapping as ``aiohttp.ClientConnectorError`` happens
    naturally upstream when the connector tries to dial.
    """

    def __init__(self, inner: "AbstractResolver | None" = None) -> None:
        if inner is None:
            if DefaultResolver is None:  # pragma: no cover
                raise RuntimeError("aiohttp is required for SafeResolver")
            inner = DefaultResolver()
        self._inner = inner

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list:
        hosts = await self._inner.resolve(host, port, family=family)
        safe = [h for h in hosts if is_publicly_routable_ip(h["host"])]
        if not safe:
            raise PermissionError(f"SSRF blocked: {host} resolved to private IP(s)")
        return safe

    async def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if close is not None:
            await close()


def resolve_host_safe(host: str, port: int) -> list:
    """Resolve hostname, raising ValueError if any resolved IP is private.

    Use this before making HTTP requests to prevent SSRF.
    """
    try:
        infos = socket.getaddrinfo(host, port)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve {host}: {e}") from None

    results = []
    for family, socktype, proto, canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        if not is_publicly_routable_ip(ip_str):
            raise ValueError(f"SSRF blocked: {host} resolved to private IP {ip_str}")
        results.append(sockaddr)

    if not results:
        raise ValueError(f"No publicly routable addresses for {host}")

    return results
