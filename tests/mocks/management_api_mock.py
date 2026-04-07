"""
Real aiohttp HTTP server mock for Management API integration testing.

Usage::

    async with management_api_mock_server() as (base_url, token, mock):
        # make requests to base_url using token
        assert any(r["method"] == "POST" for r in mock.requests_made)

The mock:
- Listens on a random free port on 127.0.0.1
- Validates "Authorization: Bearer <token>" on every request
  (returns 401 if missing or wrong token)
- Records every received request in requests_made (method, path, headers, body, query)
- Returns configurable per-path responses (default: 200 + minimal JSON)

Supported paths:
    GET    /api/v1/allowlist
    POST   /api/v1/allowlist
    DELETE /api/v1/allowlist/{id}
    GET    /api/v1/blocklist
    POST   /api/v1/blocklist
    PATCH  /api/v1/dial
    GET    /api/v1/decisions

Pattern follows tests/mocks/soar_mock.py.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from typing import Any

from aiohttp import web


class ManagementAPIMock:
    """Configurable mock HTTP server for the JA4proxy Management API.

    Attributes:
        requests_made: List of dicts recording every received request.
            Each dict has keys: method, path, headers, body, query.
        token: The valid bearer token.  Set at construction time.
    """

    def __init__(
        self,
        token: str = "test-operator-token",
        *,
        allowlist_entries: list[dict] | None = None,
        blocklist_entries: list[dict] | None = None,
        pending_decisions: list[dict] | None = None,
        dial_returns_pending: bool = False,
    ) -> None:
        self.token = token
        self.requests_made: list[dict] = []

        # Configurable state returned by GET endpoints
        self._allowlist_entries: list[dict] = allowlist_entries or []
        self._blocklist_entries: list[dict] = blocklist_entries or []
        self._pending_decisions: list[dict] = pending_decisions or []

        # When True, PATCH /api/v1/dial returns 202 + decision_id instead of 200
        self._dial_returns_pending: bool = dial_returns_pending

        # Accumulates bodies from PATCH /api/v1/config calls
        self._config_patches: list[dict] = []

        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self.base_url: str = ""

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def set_dial_pending(self, pending: bool = True) -> None:
        """Configure the mock to return 202 Accepted on PATCH /api/v1/dial."""
        self._dial_returns_pending = pending

    def reset(self) -> None:
        """Clear all recorded requests."""
        self.requests_made.clear()

    # ------------------------------------------------------------------
    # Request recording helpers
    # ------------------------------------------------------------------

    def last_request(self) -> dict | None:
        """Return the most recently recorded request, or None."""
        return self.requests_made[-1] if self.requests_made else None

    def requests_for(self, method: str, path_prefix: str) -> list[dict]:
        """Return all requests matching a method and path prefix."""
        return [
            r for r in self.requests_made
            if r["method"] == method.upper() and r["path"].startswith(path_prefix)
        ]

    # ------------------------------------------------------------------
    # aiohttp request handlers
    # ------------------------------------------------------------------

    async def _auth_check(self, request: web.Request) -> web.Response | None:
        """Return a 401 response if the bearer token is wrong, else None."""
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {self.token}":
            return web.json_response({"error": "Unauthorized"}, status=401)
        return None

    async def _record(self, request: web.Request) -> dict:
        """Parse and record the incoming request. Returns the recorded dict."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        entry = {
            "method": request.method,
            "path": request.path,
            "headers": dict(request.headers),
            "body": body,
            "query": dict(request.rel_url.query),
        }
        self.requests_made.append(entry)
        return entry

    async def _handle_allowlist_collection(self, request: web.Request) -> web.Response:
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)

        if request.method == "GET":
            return web.json_response(self._allowlist_entries, status=200)

        if request.method == "POST":
            return web.json_response(
                {"id": "new-id", "managed_by": "policy"},
                status=200,
            )

        return web.Response(status=405)

    async def _handle_allowlist_item(self, request: web.Request) -> web.Response:
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)

        if request.method == "DELETE":
            # RFC 9110 §15.3.5: 204 No Content must not include a body.
            return web.Response(status=204)

        return web.Response(status=405)

    async def _handle_blocklist_collection(self, request: web.Request) -> web.Response:
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)

        if request.method == "GET":
            return web.json_response(self._blocklist_entries, status=200)

        if request.method == "POST":
            return web.json_response(
                {"id": "new-block-id", "managed_by": "policy"},
                status=200,
            )

        return web.Response(status=405)

    async def _handle_dial(self, request: web.Request) -> web.Response:
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)

        if request.method == "PATCH":
            if self._dial_returns_pending:
                return web.json_response(
                    {"decision_id": "dec-001", "status": "pending_approval"},
                    status=202,
                )
            return web.json_response({"status": "ok"}, status=200)

        return web.Response(status=405)

    async def _handle_decisions(self, request: web.Request) -> web.Response:
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)

        if request.method == "GET":
            return web.json_response(self._pending_decisions, status=200)

        return web.Response(status=405)

    async def _handle_ip_collection(self, request: web.Request) -> web.Response:
        """Handle GET/POST for /api/v1/{allowlist|blocklist|watchlist}/ips."""
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)
        if request.method == "GET":
            return web.json_response([], status=200)
        if request.method == "POST":
            body = await request.json()
            return web.json_response(
                {"id": "new-ip-id", "managed_by": "policy", **body}, status=200
            )
        return web.Response(status=405)

    async def _handle_ip_item(self, request: web.Request) -> web.Response:
        """Handle DELETE /api/v1/{resource}/ips/{id}."""
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)
        if request.method == "DELETE":
            return web.Response(status=204)
        return web.Response(status=405)

    async def _handle_config(self, request: web.Request) -> web.Response:
        """Handle PATCH /api/v1/config — accepts bypass_toggles updates."""
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)
        if request.method == "PATCH":
            body = await request.json()
            self._config_patches.append(body)
            return web.json_response({"status": "ok"}, status=200)
        return web.Response(status=405)

    async def _handle_catchall(self, request: web.Request) -> web.Response:
        """Fallback for unrecognised paths — records and returns 404."""
        auth_err = await self._auth_check(request)
        if auth_err:
            return auth_err

        await self._record(request)
        return web.json_response({"error": "not found"}, status=404)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        """Start the mock server. Returns the base URL (e.g. http://127.0.0.1:PORT)."""
        self._app = web.Application()

        # Route specific paths before the catch-all
        self._app.router.add_route("GET",    "/api/v1/allowlist",        self._handle_allowlist_collection)
        self._app.router.add_route("POST",   "/api/v1/allowlist",        self._handle_allowlist_collection)
        self._app.router.add_route("DELETE", "/api/v1/allowlist/{id}",   self._handle_allowlist_item)
        self._app.router.add_route("GET",    "/api/v1/blocklist",        self._handle_blocklist_collection)
        self._app.router.add_route("POST",   "/api/v1/blocklist",        self._handle_blocklist_collection)
        self._app.router.add_route("PATCH",  "/api/v1/dial",             self._handle_dial)
        self._app.router.add_route("GET",    "/api/v1/decisions",        self._handle_decisions)
        self._app.router.add_route("PATCH",  "/api/v1/config",           self._handle_config)
        for resource in ("allowlist", "blocklist", "watchlist"):
            self._app.router.add_route("GET",    f"/api/v1/{resource}/ips",       self._handle_ip_collection)
            self._app.router.add_route("POST",   f"/api/v1/{resource}/ips",       self._handle_ip_collection)
            self._app.router.add_route("DELETE", f"/api/v1/{resource}/ips/{{id}}", self._handle_ip_item)
        # Catch-all must be last
        self._app.router.add_route("*",      "/{path_info:.*}",          self._handle_catchall)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()

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
async def management_api_mock_server(
    token: str = "test-operator-token",
    allowlist_entries: list[dict] | None = None,
    blocklist_entries: list[dict] | None = None,
    pending_decisions: list[dict] | None = None,
    dial_returns_pending: bool = False,
):
    """Async context manager that starts a ManagementAPIMock and yields (base_url, token, mock).

    Usage::

        async with management_api_mock_server(
            allowlist_entries=[{"id": "e1", "ja4": "...", "managed_by": "policy"}],
        ) as (base_url, token, mock):
            ...
    """
    mock = ManagementAPIMock(
        token=token,
        allowlist_entries=allowlist_entries,
        blocklist_entries=blocklist_entries,
        pending_decisions=pending_decisions,
        dial_returns_pending=dial_returns_pending,
    )
    base_url = await mock.start()
    try:
        yield base_url, token, mock
    finally:
        await mock.stop()
