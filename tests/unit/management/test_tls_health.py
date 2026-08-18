"""Tests for GET /api/v1/tls-health (TLS certificate expiry)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, mock_open, patch

import os

import pytest

try:
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def _make_cert(expiry_dt: datetime) -> MagicMock:
    """Build a mock X.509 cert with the given not_valid_after_utc."""
    cert = MagicMock()
    cert.not_valid_after_utc = expiry_dt
    cert.subject = []
    cert.issuer = []
    return cert


@pytest.mark.asyncio
async def test_cert_expiring_in_5_days_returns_red_band(admin_client):
    """A certificate expiring in 5 days => band='red', status='crit'."""
    # The endpoint computes (not_after - now).days, which floors. A bare
    # `now + timedelta(days=5)` is already <5 days away by the time the request
    # runs, so .days floors to 4. The half-day buffer keeps days_remaining at a
    # deterministic 5 regardless of execution drift, without changing the band.
    expiry = datetime.now(timezone.utc) + timedelta(days=5, hours=12)
    mock_cert = _make_cert(expiry)

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=b"pem")), \
         patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.status_code == 200
    data = response.json()
    assert data["band"] == "red"
    assert data["status"] == "crit"
    assert data["days_remaining"] == 5


@pytest.mark.asyncio
async def test_cert_expiring_in_20_days_returns_amber_band(admin_client):
    expiry = datetime.now(timezone.utc) + timedelta(days=20)
    mock_cert = _make_cert(expiry)

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=b"pem")), \
         patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.json()["band"] == "amber"


@pytest.mark.asyncio
async def test_cert_expiring_in_60_days_returns_green_band(admin_client):
    expiry = datetime.now(timezone.utc) + timedelta(days=60)
    mock_cert = _make_cert(expiry)

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=b"pem")), \
         patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.json()["band"] == "green"


@pytest.mark.asyncio
async def test_missing_cert_when_configured_returns_error(admin_client):
    """Configured but absent IS an error — someone expected a cert here."""
    with patch("os.path.exists", return_value=False), \
         patch.dict("os.environ", {"HAPROXY_TLS_CERT_PATH": "/etc/haproxy/certs/server.pem"}):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.status_code == 200
    assert response.json()["status"] == "error"


@pytest.mark.asyncio
async def test_missing_cert_when_unconfigured_is_not_an_error(admin_client):
    """Absent-by-design must not render as a failure.

    HAProxy is optional — docker-compose.poc.yml only starts it with
    WITH_HAPROXY=1, and the management container mounts no cert volume — so on
    a stock deployment the default path can never exist. This previously
    rendered a permanent red "Certificate file not found" banner for a
    component the operator had deliberately not deployed, which is how a
    healthy console came to look broken.

    Absent-by-design and broken must not look identical, or the red banner
    stops meaning anything.
    """
    env = {k: v for k, v in os.environ.items() if k != "HAPROXY_TLS_CERT_PATH"}
    with patch("os.path.exists", return_value=False), \
         patch.dict("os.environ", env, clear=True):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "not_configured", body
    assert body["band"] != "red", "an undeployed optional component must not show red"


@pytest.mark.asyncio
async def test_parse_error_does_not_leak_exception_to_client(admin_client):
    """A cert-parse failure returns a generic message — the raw exception text
    (which CodeQL py/stack-trace-exposure flags) must never reach the client."""
    secret = "s3cr3t-internal-path-/var/run/private.key"
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=b"not-a-pem")), \
         patch(
             "cryptography.x509.load_pem_x509_certificate",
             side_effect=ValueError(secret),
         ):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert secret not in str(body)
