"""Tests for GET /api/v1/tls-health (TLS certificate expiry)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, mock_open, patch

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
    expiry = datetime.now(timezone.utc) + timedelta(days=5)
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
async def test_missing_cert_file_returns_error(admin_client):
    with patch("os.path.exists", return_value=False):
        response = await admin_client.get("/api/v1/tls-health")

    assert response.status_code == 200
    assert response.json()["status"] == "error"
