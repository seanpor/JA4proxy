"""H8 — CSRF origin validation middleware for the management API.

Safe methods (GET, HEAD, OPTIONS) are always exempt. Bearer-authenticated
requests bypass the check (API tokens are not vulnerable to CSRF). Cookie-
authenticated mutating requests that include an Origin header are validated
against ``MANAGEMENT_CORS_ORIGINS``.

When the Origin header is explicitly present (even if empty), the middleware
validates it against the allowed origins list. When the Origin header is
completely absent, the middleware defers to browser SameSite cookie policy —
modern browsers always include Origin on cross-origin requests, so a missing
Origin indicates a same-origin or non-browser caller.
"""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that validates Origin on cookie-authenticated
    mutating requests."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if request.method in _SAFE_METHODS:
            return await call_next(request)

        # Bearer auth bypasses CSRF — tokens are not cookie-based
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return await call_next(request)

        # Cookie auth: validate Origin when present
        if "token" in request.cookies:
            # Check if Origin header was explicitly sent (even if empty).
            # Browsers always send Origin on cross-origin requests.
            # Missing Origin = same-origin or non-browser; SameSite handles this.
            has_origin = any(
                k == b"origin" for k, _v in request.scope.get("headers", [])
            )
            if has_origin:
                origin = request.headers.get("origin", "").strip()
                allowed = os.environ.get("MANAGEMENT_CORS_ORIGINS", "").split(",")
                allowed = [o.strip() for o in allowed if o.strip()]

                if not origin or origin not in allowed:
                    return JSONResponse(
                        {"detail": "CSRF origin validation failed"},
                        status_code=403,
                    )

        return await call_next(request)
