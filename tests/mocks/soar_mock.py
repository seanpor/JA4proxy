"""
Real aiohttp HTTP server mock for SOAR integration testing.

Usage::

    async with soar_mock_server() as (base_url, token, mock):
        # make requests to base_url using token
        assert mock.requests[-1]["method"] == "POST"
        assert mock.requests[-1]["path"] == "/api/v1/bans"

The mock:
- Listens on a random free port on 127.0.0.1
- Validates "Authorization: Bearer <token>" on every request
  (returns 401 if missing or wrong token)
- Records every received request (method, path, headers, body JSON)
- Returns configurable per-path responses (default: 200 + minimal JSON)

Supported paths:
    POST   /api/v1/bans
    DELETE /api/v1/bans/{ip}
    PATCH  /api/v1/bans/{ip}
    POST   /api/v1/watchlist
    POST   /api/v1/allowlist
    DELETE /api/v1/allowlist/{id}
    GET    /api/v1/connections
    GET    /api/v1/fingerprints/{ja4}
    GET    /api/v1/health/deep
    GET    /api/v1/dial
    PATCH  /api/v1/dial
    POST   /api/v1/tokens/{id}/rotate

Pattern follows tests/mocks/abuseipdb_mock.py.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from typing import Any

from aiohttp import web


# ---------------------------------------------------------------------------
# Default response bodies for each path prefix
# ---------------------------------------------------------------------------

_DEFAULT_RESPONSES: dict[str, Any] = {
    "/api/v1/bans": {"status": "ok", "message": "ban created"},
    "/api/v1/watchlist": {"status": "ok", "message": "added to watchlist"},
    "/api/v1/allowlist": {"status": "ok", "message": "allowlist entry created"},
    "/api/v1/connections": {"connections": []},
    "/api/v1/fingerprints": {"fingerprint": "t13d1516h2_aabbccddeeff_aabbccddeeff", "ips": []},
    "/api/v1/health/deep": {"status": "ok", "nodes": 1},
    "/api/v1/dial": {"dial": 0},
    "/api/v1/tokens": {"token": "new-token-value"},
}

# Paths that are always routable regardless of trailing path segment
_PATH_PREFIXES = list(_DEFAULT_RESPONSES.keys())


def _default_body_for_path(path: str) -> dict:
    """Return the default response body for a given path."""
    for prefix in _PATH_PREFIXES:
        if path.startswith(prefix):
            return _DEFAULT_RESPONSES[prefix]
    return {"status": "ok"}


class SOARMock:
    """Configurable mock HTTP server for the JA4proxy Management API.

    Attributes:
        requests: List of dicts recording every received request.
            Each dict has keys: method, path, headers, body, query.
        token: The valid bearer token. Set at construction time.
    """

    def __init__(self, token: str = "test-operator-token") -> None:
        self.token = token
        self.requests: list[dict] = []
        self._overrides: dict[tuple[str, str], dict] = {}  # (METHOD, path) → response body
        self._status_overrides: dict[tuple[str, str], int] = {}
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self.base_url: str = ""

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def set_response(
        self,
        method: str,
        path: str,
        body: dict,
        status: int = 200,
    ) -> None:
        """Override the response for a specific (method, path) combination."""
        key = (method.upper(), path)
        self._overrides[key] = body
        self._status_overrides[key] = status

    def set_error(self, method: str, path: str, status: int = 500) -> None:
        """Respond with an error status for a specific (method, path)."""
        key = (method.upper(), path)
        self._overrides[key] = {"error": f"HTTP {status}"}
        self._status_overrides[key] = status

    def reset(self) -> None:
        """Clear all recorded requests and response overrides."""
        self.requests.clear()
        self._overrides.clear()
        self._status_overrides.clear()

    # ------------------------------------------------------------------
    # Request recording helpers
    # ------------------------------------------------------------------

    def last_request(self) -> dict | None:
        """Return the most recently recorded request, or None."""
        return self.requests[-1] if self.requests else None

    def requests_for(self, method: str, path: str) -> list[dict]:
        """Return all requests matching a (method, path) pair."""
        return [
            r for r in self.requests
            if r["method"] == method.upper() and r["path"] == path
        ]

    # ------------------------------------------------------------------
    # aiohttp request handler
    # ------------------------------------------------------------------

    async def _handle(self, request: web.Request) -> web.Response:
        # Auth check
        auth = request.headers.get("Authorization", "")
        expected = f"Bearer {self.token}"
        if auth != expected:
            return web.json_response({"error": "Unauthorized"}, status=401)

        # Parse body
        try:
            body = await request.json()
        except Exception:
            body = {}

        # Record request
        self.requests.append(
            {
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "body": body,
                "query": dict(request.rel_url.query),
            }
        )

        # Check for configured override
        key = (request.method, request.path)
        if key in self._overrides:
            return web.json_response(
                self._overrides[key],
                status=self._status_overrides.get(key, 200),
            )

        # Default response
        # RFC 9110 §15.3.5: 204 No Content MUST NOT include a message body.
        if request.method == "DELETE":
            return web.Response(status=204)
        response_body = _default_body_for_path(request.path)
        return web.json_response(response_body, status=200)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        """Start the mock server. Returns the base URL (e.g. http://127.0.0.1:PORT)."""
        self._app = web.Application()
        # Catch-all route — handles every method and path
        self._app.router.add_route("*", "/{path_info:.*}", self._handle)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()

        # Retrieve the actual bound port
        assert self._runner.addresses, "Server failed to bind"
        bound_host, bound_port = self._runner.addresses[0][:2]
        self.base_url = f"http://{bound_host}:{bound_port}"
        return self.base_url

    async def stop(self) -> None:
        """Stop the mock server and release resources."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self._app = None
            self.base_url = ""


# ---------------------------------------------------------------------------
# Async context manager convenience wrapper
# ---------------------------------------------------------------------------


@asynccontextmanager
async def soar_mock_server(token: str = "test-operator-token"):
    """Async context manager that starts a SOARMock and yields (base_url, token, mock).

    Usage::

        async with soar_mock_server() as (base_url, token, mock):
            ...
    """
    mock = SOARMock(token=token)
    base_url = await mock.start()
    try:
        yield base_url, token, mock
    finally:
        await mock.stop()
