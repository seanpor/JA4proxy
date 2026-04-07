"""XSOAR integration commands for JA4proxy.

Each function corresponds to an XSOAR command (ja4proxy-ban-ip, etc.).
All functions are async and make HTTP calls to the JA4proxy Management API.

Usage::

    result = await ban_ip(base_url="http://mgmt:8090", token="...", ip="1.2.3.4")
"""

from __future__ import annotations

import aiohttp


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class JA4proxyError(Exception):
    """Raised for non-2xx responses from the JA4proxy Management API."""


class AuthError(JA4proxyError):
    """Raised when the Management API returns 401 Unauthorized."""


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _make_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


async def _request(
    method: str,
    url: str,
    token: str,
    *,
    json: dict | None = None,
    params: dict | None = None,
    timeout: int = 30,
) -> dict:
    """Make an HTTP request and return the parsed JSON body.

    Raises:
        AuthError: if the response status is 401.
        JA4proxyError: if the response status is any other 4xx/5xx.
    """
    async with aiohttp.ClientSession() as session:
        async with session.request(
            method,
            url,
            headers=_make_headers(token),
            json=json,
            params=params,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status == 401:
                raise AuthError(f"401 Unauthorized — check API token")
            if resp.status >= 400:
                body = await resp.text()
                raise JA4proxyError(
                    f"HTTP {resp.status} from {url}: {body}"
                )
            # 204 No Content has no body
            if resp.status == 204:
                return {}
            return await resp.json()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def ban_ip(
    *,
    base_url: str,
    token: str,
    ip: str,
    ttl_seconds: int = 3600,
    reason: str = "",
) -> dict:
    """ja4proxy-ban-ip — POST /api/v1/bans."""
    return await _request(
        "POST",
        f"{base_url}/api/v1/bans",
        token,
        json={"ip": ip, "ttl_seconds": ttl_seconds, "reason": reason},
    )


async def release_ban(
    *,
    base_url: str,
    token: str,
    ip: str,
) -> dict:
    """ja4proxy-release-ban — DELETE /api/v1/bans/{ip}."""
    return await _request(
        "DELETE",
        f"{base_url}/api/v1/bans/{ip}",
        token,
    )


async def get_connection_history(
    *,
    base_url: str,
    token: str,
    ip: str,
    days: int = 7,
) -> dict:
    """ja4proxy-get-connection-history — GET /api/v1/connections?ip={ip}&days={days}."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/connections",
        token,
        params={"ip": ip, "days": str(days)},
    )


async def get_fingerprint_detail(
    *,
    base_url: str,
    token: str,
    ja4: str,
) -> dict:
    """ja4proxy-get-fingerprint-detail — GET /api/v1/fingerprints/{ja4}."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/fingerprints/{ja4}",
        token,
    )


async def add_to_watchlist(
    *,
    base_url: str,
    token: str,
    ip: str,
    reason: str = "",
) -> dict:
    """ja4proxy-add-to-watchlist — POST /api/v1/watchlist."""
    return await _request(
        "POST",
        f"{base_url}/api/v1/watchlist",
        token,
        json={"ip": ip, "reason": reason},
    )


async def get_health(
    *,
    base_url: str,
    token: str,
) -> dict:
    """ja4proxy-get-health — GET /api/v1/health/deep."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/health/deep",
        token,
    )


async def add_to_allowlist(
    *,
    base_url: str,
    token: str,
    ip: str,
    ttl_seconds: int,
    reason: str = "",
) -> dict:
    """ja4proxy-add-to-allowlist — POST /api/v1/allowlist.

    Raises:
        ValueError: if ttl_seconds=0 (no indefinite allowlist entries allowed).
    """
    if ttl_seconds == 0:
        raise ValueError(
            "ttl_seconds must be > 0: indefinite allowlist entries are not permitted. "
            "Provide an explicit expiry (e.g. ttl_seconds=86400 for 24 hours)."
        )
    return await _request(
        "POST",
        f"{base_url}/api/v1/allowlist",
        token,
        json={"ip": ip, "ttl_seconds": ttl_seconds, "reason": reason},
    )


async def get_dial(
    *,
    base_url: str,
    token: str,
) -> dict:
    """ja4proxy-get-dial — GET /api/v1/dial."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/dial",
        token,
    )
