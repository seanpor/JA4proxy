"""IP address utility functions for JA4proxy.

All IP handling follows the cross-cutting IPv6 requirements in CLAUDE.md:
- Normalise to canonical form on ingress
- IPv4-mapped IPv6 addresses are unwrapped to plain IPv4
- Both IPv4 and IPv6 supported throughout
"""

from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address


def canonical_ip(raw_ip: str) -> str:
    """Return the canonical string form of an IP address.

    Normalises:
    - IPv4-mapped IPv6 (::ffff:192.0.2.1) → plain IPv4 (192.0.2.1)
    - Leading zeros stripped
    - IPv6 compressed (2001:0db8::1 → 2001:db8::1)
    - Loopback, link-local, private ranges handled identically

    Args:
        raw_ip: Raw IP string from socket or PROXY protocol header.

    Returns:
        Canonical IP string safe to use as Redis key segment.

    Raises:
        ValueError: If raw_ip is not a valid IP address.
    """
    addr = ip_address(raw_ip)
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr.compressed)


def get_analysis_subnet(ip: str) -> str:
    """Return the analysis subnet for a canonical IP.

    IPv4 → /24 (256 addresses — standard analytics granularity)
    IPv6 → /48 (same approximate user population density as IPv4 /24)

    This subnet string is used as the key for:
    - HyperLogLog per-subnet unique-IP counters
    - Analytics aggregation and campaign detection

    Args:
        ip: Canonical IP address string (already normalised via canonical_ip).

    Returns:
        CIDR notation string, e.g. "192.0.2.0/24" or "2001:db8::/48".
    """
    addr = ip_address(ip)
    if addr.version == 4:
        return str(ip_network(f"{ip}/24", strict=False))
    return str(ip_network(f"{ip}/48", strict=False))
