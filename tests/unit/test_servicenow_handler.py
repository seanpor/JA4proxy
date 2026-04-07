"""Unit tests for integrations/servicenow/ja4proxy_snow_handler.py.

Tests cover:
  - ecs_to_sir() field mapping and severity boundary conditions
  - create_sir_incident() HTTP call and error propagation

Every test asserts on specific values — none rely on "doesn't raise" alone.

Severity thresholds (per Phase 81 §5.1 spec):
  risk_score >= 85  → severity "1" (Critical)
  risk_score <  85  → severity "2" (High)

Boundary tests at exactly 84 and 85 are mandatory.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# Import helper — gives an explicit ImportError if the module doesn't exist
# ---------------------------------------------------------------------------

def _import_handler():
    """Import the ServiceNow handler. Raises ImportError if missing."""
    # Provide required env vars to prevent NameError at import time
    env_patch = {
        "SNOW_INSTANCE": "test.service-now.com",
        "SNOW_USER": "testuser",
        "SNOW_PASS": "testpass",
    }
    with patch.dict(os.environ, env_patch):
        from integrations.servicenow import ja4proxy_snow_handler as handler  # type: ignore[import]
    return handler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def handler():
    """Return the handler module, patching env vars at import time."""
    return _import_handler()


@pytest.fixture
def minimal_event():
    """A minimal ECS event dict with required fields."""
    return {
        "source.ip": "1.2.3.4",
        "event.risk_score": 70,
        "ja4proxy.fingerprint.ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff",
        "ja4proxy.ban_id": "ban-abc123",
        "ja4proxy.signals": [],
    }


# ===========================================================================
# ecs_to_sir() — severity mapping
# ===========================================================================

class TestEcsToSirSeverity:

    def test_ecs_to_sir_high_risk(self, handler, minimal_event):
        """risk_score=90 → severity '1' (Critical)."""
        minimal_event["event.risk_score"] = 90
        payload = handler.ecs_to_sir(minimal_event)
        assert payload["severity"] == "1", (
            f"Expected severity='1' for risk_score=90, got {payload['severity']!r}"
        )

    def test_ecs_to_sir_boundary_high(self, handler, minimal_event):
        """risk_score=85 → severity '1' (boundary — inclusive at 85)."""
        minimal_event["event.risk_score"] = 85
        payload = handler.ecs_to_sir(minimal_event)
        assert payload["severity"] == "1", (
            f"Expected severity='1' for risk_score=85 (boundary), got {payload['severity']!r}"
        )

    def test_ecs_to_sir_boundary_medium(self, handler, minimal_event):
        """risk_score=84 → severity '2' (one below the boundary)."""
        minimal_event["event.risk_score"] = 84
        payload = handler.ecs_to_sir(minimal_event)
        assert payload["severity"] == "2", (
            f"Expected severity='2' for risk_score=84 (one below boundary), got {payload['severity']!r}"
        )

    def test_ecs_to_sir_medium_risk(self, handler, minimal_event):
        """risk_score=70 → severity '2' (High)."""
        minimal_event["event.risk_score"] = 70
        payload = handler.ecs_to_sir(minimal_event)
        assert payload["severity"] == "2", (
            f"Expected severity='2' for risk_score=70, got {payload['severity']!r}"
        )


# ===========================================================================
# ecs_to_sir() — signal formatting
# ===========================================================================

class TestEcsToSirSignals:

    def test_ecs_to_sir_signal_formatting(self, handler, minimal_event):
        """Signals list → description contains 'name(+score): reason' entries."""
        minimal_event["ja4proxy.signals"] = [
            {"name": "asn", "score": 20, "reason": "DC"},
            {"name": "beaconing", "score": 40, "reason": "IAT CV=0.05"},
        ]
        payload = handler.ecs_to_sir(minimal_event)
        desc = payload["description"]
        assert "asn(+20): DC" in desc, (
            f"Expected 'asn(+20): DC' in description, got: {desc!r}"
        )
        assert "beaconing(+40): IAT CV=0.05" in desc, (
            f"Expected 'beaconing(+40): IAT CV=0.05' in description, got: {desc!r}"
        )

    def test_ecs_to_sir_no_signals(self, handler, minimal_event):
        """Empty signals list → description is 'No signals recorded.'"""
        minimal_event["ja4proxy.signals"] = []
        payload = handler.ecs_to_sir(minimal_event)
        assert payload["description"] == "No signals recorded.", (
            f"Expected 'No signals recorded.' for empty signals, got: {payload['description']!r}"
        )


# ===========================================================================
# ecs_to_sir() — field mapping
# ===========================================================================

class TestEcsToSirFieldMapping:

    def test_ecs_to_sir_maps_source_ip(self, handler, minimal_event):
        """source.ip in event → u_source_ip in payload."""
        minimal_event["source.ip"] = "5.6.7.8"
        payload = handler.ecs_to_sir(minimal_event)
        assert payload.get("u_source_ip") == "5.6.7.8", (
            f"Expected u_source_ip='5.6.7.8', got: {payload.get('u_source_ip')!r}"
        )

    def test_ecs_to_sir_maps_ja4_fingerprint(self, handler, minimal_event):
        """ja4proxy.fingerprint.ja4 in event → u_ja4_fingerprint in payload."""
        ja4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        minimal_event["ja4proxy.fingerprint.ja4"] = ja4
        payload = handler.ecs_to_sir(minimal_event)
        assert payload.get("u_ja4_fingerprint") == ja4, (
            f"Expected u_ja4_fingerprint={ja4!r}, got: {payload.get('u_ja4_fingerprint')!r}"
        )

    def test_ecs_to_sir_short_description_includes_ip_and_score(self, handler, minimal_event):
        """short_description includes source IP and risk score."""
        minimal_event["source.ip"] = "1.2.3.4"
        minimal_event["event.risk_score"] = 90
        payload = handler.ecs_to_sir(minimal_event)
        assert "1.2.3.4" in payload["short_description"]
        assert "90" in payload["short_description"] or "score=90" in payload["short_description"]


# ===========================================================================
# create_sir_incident() — HTTP call and error propagation
# ===========================================================================

class TestCreateSirIncident:

    def _mock_post_success(self):
        """Return a mock requests.post that simulates a 201 Created response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.raise_for_status = MagicMock()  # no-op on success
        mock_resp.json.return_value = {"result": {"sys_id": "abc123"}}
        return MagicMock(return_value=mock_resp)

    def _mock_post_error(self, status_code: int):
        """Return a mock requests.post that raises on raise_for_status()."""
        import requests
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        http_err = requests.HTTPError(f"{status_code} error", response=mock_resp)
        mock_resp.raise_for_status.side_effect = http_err
        return MagicMock(return_value=mock_resp)

    def test_create_sir_incident_success(self, handler, minimal_event):
        """mock requests.post returns 201 + sys_id → create_sir_incident returns sys_id."""
        with patch.dict(os.environ, {
            "SNOW_INSTANCE": "company.service-now.com",
            "SNOW_USER": "user",
            "SNOW_PASS": "pass",
        }):
            with patch("integrations.servicenow.ja4proxy_snow_handler.requests.post",
                       self._mock_post_success()):
                result = handler.create_sir_incident(minimal_event)

        assert result == "abc123", (
            f"Expected sys_id='abc123', got: {result!r}"
        )

    def test_create_sir_incident_raises_on_403(self, handler, minimal_event):
        """mock returns 403 → raise_for_status() propagates."""
        with patch.dict(os.environ, {
            "SNOW_INSTANCE": "company.service-now.com",
            "SNOW_USER": "user",
            "SNOW_PASS": "pass",
        }):
            with patch("integrations.servicenow.ja4proxy_snow_handler.requests.post",
                       self._mock_post_error(403)):
                with pytest.raises(requests.HTTPError):
                    handler.create_sir_incident(minimal_event)

    def test_create_sir_incident_raises_on_500(self, handler, minimal_event):
        """mock returns 500 → raises (server error propagated)."""
        with patch.dict(os.environ, {
            "SNOW_INSTANCE": "company.service-now.com",
            "SNOW_USER": "user",
            "SNOW_PASS": "pass",
        }):
            with patch("integrations.servicenow.ja4proxy_snow_handler.requests.post",
                       self._mock_post_error(500)):
                with pytest.raises(Exception):
                    handler.create_sir_incident(minimal_event)
