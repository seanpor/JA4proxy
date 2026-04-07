"""Splunk SOAR connector for JA4proxy.

Module-level async functions matching Splunk SOAR app actions.
All functions call the JA4proxy Management API using aiohttp.

Usage::

    result = await block_ip(base_url="http://mgmt:8090", token="...",
                            ip="1.2.3.4", ttl_seconds=3600, reason="high risk")
"""

from __future__ import annotations

import aiohttp


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class JA4proxySoarError(Exception):
    """Raised for non-2xx responses from the JA4proxy Management API."""


class AuthError(JA4proxySoarError):
    """Raised when the API returns 401 Unauthorized."""


# ---------------------------------------------------------------------------
# Internal HTTP helper
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
        AuthError: if the response is 401 Unauthorized.
        JA4proxySoarError: for any other 4xx/5xx response.
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
                raise JA4proxySoarError(
                    f"HTTP {resp.status} from {url}: {body}"
                )
            if resp.status == 204:
                return {}
            return await resp.json()


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


async def block_ip(
    *,
    base_url: str,
    token: str,
    ip: str,
    ttl_seconds: int = 3600,
    reason: str = "",
) -> dict:
    """block_ip action — POST /api/v1/bans."""
    return await _request(
        "POST",
        f"{base_url}/api/v1/bans",
        token,
        json={"ip": ip, "ttl_seconds": ttl_seconds, "reason": reason},
    )


async def unblock_ip(
    *,
    base_url: str,
    token: str,
    ip: str,
) -> dict:
    """unblock_ip action — DELETE /api/v1/bans/{ip}."""
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
    """get_connection_history action — GET /api/v1/connections?ip={ip}&days={days}."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/connections",
        token,
        params={"ip": ip, "days": str(days)},
    )


async def get_fingerprint_history(
    *,
    base_url: str,
    token: str,
    ja4_fingerprint: str,
    days: int = 7,
) -> dict:
    """get_fingerprint_history action — GET /api/v1/fingerprints/{ja4}?days={days}."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/fingerprints/{ja4_fingerprint}",
        token,
        params={"days": str(days)},
    )


async def add_to_watchlist(
    *,
    base_url: str,
    token: str,
    ip: str,
    reason: str = "",
) -> dict:
    """add_to_watchlist action — POST /api/v1/watchlist."""
    return await _request(
        "POST",
        f"{base_url}/api/v1/watchlist",
        token,
        json={"ip": ip, "reason": reason},
    )


async def add_to_allowlist(
    *,
    base_url: str,
    token: str,
    ip: str,
    ttl_seconds: int,
    reason: str = "",
) -> dict:
    """add_to_allowlist action — POST /api/v1/allowlist."""
    return await _request(
        "POST",
        f"{base_url}/api/v1/allowlist",
        token,
        json={"ip": ip, "ttl_seconds": ttl_seconds, "reason": reason},
    )


async def remove_from_allowlist(
    *,
    base_url: str,
    token: str,
    entry_id: str,
) -> dict:
    """remove_from_allowlist action — DELETE /api/v1/allowlist/{id}."""
    return await _request(
        "DELETE",
        f"{base_url}/api/v1/allowlist/{entry_id}",
        token,
    )


async def get_health(
    *,
    base_url: str,
    token: str,
) -> dict:
    """get_health action — GET /api/v1/health/deep."""
    return await _request(
        "GET",
        f"{base_url}/api/v1/health/deep",
        token,
    )
