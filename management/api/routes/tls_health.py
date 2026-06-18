"""TLS certificate health endpoint.

GET /api/v1/tls-health — reads the HAProxy TLS certificate and returns expiry info.

Why this matters: when the HAProxy TLS certificate expires, HAProxy refuses to
restart and the proxy goes completely dark. This endpoint provides early warning
so the SOC team can renew the certificate before it causes an outage.

The certificate path is read from the HAPROXY_TLS_CERT_PATH environment variable
(default: /etc/haproxy/certs/server.pem). In the Docker setup, this file is
bind-mounted into the management container from the haproxy container's cert path.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tls"])

_DEFAULT_CERT_PATH = "/etc/haproxy/certs/server.pem"

_templates: Optional[Jinja2Templates] = None


def set_templates(templates: Jinja2Templates) -> None:
    global _templates
    _templates = templates


def _get_templates() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("tls_health: templates not initialised")
    return _templates


def _read_cert(cert_path: str) -> Optional[dict]:
    """Read and parse the TLS certificate, return a dict with results or None on error."""
    if not os.path.exists(cert_path):
        logger.warning("tls_health | event=cert_not_found | path=%s", cert_path)
        return {
            "status": "error",
            "band": "red",
            "message": f"Certificate file not found: {cert_path}",
            "cert_path": cert_path,
        }

    try:
        with open(cert_path, "rb") as f:
            pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    except Exception as exc:
        logger.warning("tls_health | event=cert_parse_error | path=%s | error=%s", cert_path, exc)
        return {
            "status": "error",
            "band": "red",
            "message": f"Failed to parse certificate: {exc}",
            "cert_path": cert_path,
        }

    try:
        not_after_dt = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_remaining = (not_after_dt - now).days

        if days_remaining > 30:
            status_label, band = "ok", "green"
        elif days_remaining >= 14:
            status_label, band = "warn", "amber"
        else:
            status_label, band = "crit", "red"

        subject = {attr.oid._name: attr.value for attr in cert.subject}
        issuer = {attr.oid._name: attr.value for attr in cert.issuer}

        logger.info(
            "tls_health | event=cert_read | days=%s | band=%s | subject_cn=%s",
            days_remaining, band, subject.get("commonName", "unknown"),
        )

        return {
            "status": status_label,
            "band": band,
            "expires_at": not_after_dt.isoformat(),
            "days_remaining": days_remaining,
            "subject": subject,
            "issuer": issuer,
            "cert_path": cert_path,
        }

    except Exception as exc:
        logger.warning("tls_health | event=cert_processing_error | path=%s | error=%s", cert_path, exc)
        return {
            "status": "error",
            "band": "red",
            "message": f"Error computing expiry: {exc}",
        }


@router.get("/api/v1/tls-health")
async def tls_health(
    request: Request,
    current_user=Depends(get_current_user),
    format: str = Query("json", description="Response format: json or html"),
) -> JSONResponse:
    """Return TLS certificate expiry information."""
    cert_path = os.getenv("HAPROXY_TLS_CERT_PATH", _DEFAULT_CERT_PATH)
    result = _read_cert(cert_path)
    if result is None:
        result = {"status": "error", "band": "red", "message": "Unknown error"}

    if format == "html":
        templates = _get_templates()
        return templates.TemplateResponse(
            request,
            "partials/tls_cert_card.html",
            result,
        )

    return JSONResponse(result)
