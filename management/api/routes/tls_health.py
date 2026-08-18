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


# The card template renders band_color, band_shape, days_remaining, expires_at,
# subject and message. Every non-success branch previously returned only
# status/band/message/cert_path, so rendering raised and the endpoint 500'd —
# the console polled it every few seconds and logged a 500 each time. The
# "certificate not found" red banner an operator sees was in fact a crash.
#
# One shape for every outcome, so a new branch cannot reintroduce this.
_BAND_COLOUR = {"green": "#10b981", "amber": "#f59e0b", "red": "#ef4444", "grey": "#64748b"}
_BAND_SHAPE = {"green": "circle", "amber": "triangle", "red": "square", "grey": "circle"}


def _card(status: str, band: str, message: str, cert_path: str, **extra) -> dict:
    """Build a payload with every key the card template needs."""
    card = {
        "status": status,
        "band": band,
        "band_color": _BAND_COLOUR.get(band, _BAND_COLOUR["grey"]),
        "band_shape": _BAND_SHAPE.get(band, "circle"),
        "message": message,
        "cert_path": cert_path,
        "expires_at": None,
        "days_remaining": None,
        "subject": None,
        "issuer": None,
    }
    card.update(extra)
    return card


def _read_cert(cert_path: str) -> Optional[dict]:
    """Read and parse the TLS certificate, return a dict with results or None on error."""
    if not os.path.exists(cert_path):
        # "Not configured" is NOT an error. HAProxy is an optional component
        # (docker-compose.poc.yml only starts it with WITH_HAPROXY=1), and the
        # management container mounts no cert volume at all — so on a stock
        # deployment this path can never exist. Rendering that as a red error
        # meant the console showed a permanent failure for a component the
        # operator deliberately did not deploy.
        #
        # Same distinction the console applies elsewhere: absent-by-design and
        # broken must not look identical, or the red banner stops meaning
        # anything.
        configured = os.environ.get("HAPROXY_TLS_CERT_PATH") not in (None, "")
        if not configured:
            logger.debug("tls_health | event=cert_not_configured | path=%s", cert_path)
            return _card(
                "not_configured",
                "grey",
                "No TLS certificate configured. HAProxy is optional; set "
                "HAPROXY_TLS_CERT_PATH and mount the certificate to monitor expiry.",
                cert_path,
            )
        # Explicitly configured but missing IS an error — someone expected a
        # cert here and it is not there.
        logger.warning("tls_health | event=cert_not_found | path=%s", cert_path)
        return _card("error", "red", f"Certificate file not found: {cert_path}", cert_path)

    try:
        with open(cert_path, "rb") as f:
            pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    except Exception as exc:
        logger.warning("tls_health | event=cert_parse_error | path=%s | error=%s", cert_path, exc)
        # Do not surface the raw exception to the client (CodeQL py/stack-trace-exposure);
        # the detail is in the log above. The SOC reads logs, not the API payload.
        return {
            "status": "error",
            "band": "red",
            "message": "Failed to parse certificate (see proxy logs for detail)",
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
        # Generic client message; full exception is logged above (CodeQL py/stack-trace-exposure).
        return _card(
            "error", "red",
            "Error computing certificate expiry (see proxy logs for detail)",
            cert_path,
        )


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
        result = _card("error", "red", "Unknown error", cert_path)

    if format == "html":
        templates = _get_templates()
        return templates.TemplateResponse(
            request,
            "partials/tls_cert_card.html",
            result,
        )

    return JSONResponse(result)
