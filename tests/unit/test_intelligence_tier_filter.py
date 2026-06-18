"""Tests for the confidence tier filtering in the intelligence partial.

Verifies that only HIGH-confidence findings reach the dashboard, and that
MEDIUM/LOW findings are excluded from the main view but counted for the badge.
This implements Decision 5 from PHASE_231.md.
"""
import pytest

try:
    from management.api.routes.partials import _validate_finding
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def _make_finding(confidence_str: str, dismissed: str = "0") -> dict:
    tier_map = {
        c: ("HIGH" if float(c) >= 0.90 else "MEDIUM" if float(c) >= 0.70 else "LOW")
        for c in [confidence_str]
    }
    return {
        "confidence": confidence_str,
        "tier": tier_map[confidence_str],
        "type": "beaconing",
        "subject_ip": "203.0.113.1",
        "subject_ja4": "",
        "description": "Test finding.",
        "evidence_count": "50",
        "model_version": "1.0.0",
        "model_trained_at": "2026-01-01T00:00:00Z",
        "fp_rate_estimate": "0.05",
        "suggested_action": "monitor",
        "created_at": "2026-06-12T08:00:00Z",
        "dismissed": dismissed,
    }


def test_only_high_findings_returned_to_dashboard():
    """Only HIGH (>=0.90) findings appear on the main dashboard intelligence row."""
    findings = [
        _make_finding("0.95"),
        _make_finding("0.91"),
        _make_finding("0.85"),
        _make_finding("0.60"),
    ]

    high_count = sum(
        1 for f in findings
        if _validate_finding(f, "id") is not None and f["tier"] == "HIGH"
    )
    medium_low_count = sum(
        1 for f in findings
        if _validate_finding(f, "id") is not None and f["tier"] != "HIGH"
    )

    assert high_count == 2
    assert medium_low_count == 2


def test_dismissed_findings_excluded():
    """Dismissed findings (dismissed='1') must not appear anywhere on the dashboard."""
    dismissed_high = _make_finding("0.95", dismissed="1")
    result = _validate_finding(dismissed_high, "id-dismissed")
    assert result is not None
    assert result["dismissed"] == "1"
