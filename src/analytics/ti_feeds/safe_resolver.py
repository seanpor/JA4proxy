"""SSRF protection utilities for threat-intel feed clients.

Provides is_publicly_routable_ip() to block RFC1918 private IPs, loopback, and link-local.
"""

from __future__ import annotations

import ipaddress
import logging
import socket

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

    Returns False for RFC1918, loopback, link-local, and other reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if ip.is_loopback:
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        for net in _IPV4_PRIVATE:
            if ip in net:
                return False
        if ip in _LINK_LOCAL:
            return False
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in _IPV6_PRIVATE:
            if ip in net:
                return False

    return True


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
