"""Tests for analytics finding schema validation.

These tests verify that the management console correctly validates and rejects
malformed analytics findings before rendering. This is the core security control
described in the Analytics Trust Boundary section of PHASE_231.md.
"""
import pytest

try:
    from management.api.routes.partials import _validate_finding
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


VALID_FINDING = {
    "confidence": "0.95",
    "tier": "HIGH",
    "type": "beaconing",
    "subject_ip": "203.0.113.42",
    "subject_ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "description": "Client at 203.0.113.42 connects every 30 seconds with millisecond precision.",
    "evidence_count": "120",
    "model_version": "1.2.3",
    "model_trained_at": "2026-06-01T00:00:00Z",
    "fp_rate_estimate": "0.02",
    "suggested_action": "watchlist",
    "created_at": "2026-06-12T08:00:00Z",
    "dismissed": "0",
}


def test_valid_finding_passes():
    result = _validate_finding(VALID_FINDING.copy(), "test-uuid-001")
    assert result is not None
    assert result["id"] == "test-uuid-001"
    assert result["confidence"] == 0.95
    assert result["evidence_count"] == 120


def test_missing_required_field_rejected():
    bad = VALID_FINDING.copy()
    del bad["confidence"]
    result = _validate_finding(bad, "test-uuid-002")
    assert result is None


def test_confidence_above_range_rejected():
    bad = VALID_FINDING.copy()
    bad["confidence"] = "1.5"
    result = _validate_finding(bad, "test-uuid-003")
    assert result is None


def test_confidence_below_range_rejected():
    bad = VALID_FINDING.copy()
    bad["confidence"] = "-0.1"
    result = _validate_finding(bad, "test-uuid-004")
    assert result is None


def test_invalid_type_enum_rejected():
    bad = VALID_FINDING.copy()
    bad["type"] = "blocklist_update"
    result = _validate_finding(bad, "test-uuid-005")
    assert result is None


def test_invalid_suggested_action_rejected():
    bad = VALID_FINDING.copy()
    bad["suggested_action"] = "delete_all"
    result = _validate_finding(bad, "test-uuid-006")
    assert result is None


def test_description_too_long_rejected():
    bad = VALID_FINDING.copy()
    bad["description"] = "x" * 501
    result = _validate_finding(bad, "test-uuid-007")
    assert result is None


def test_html_in_description_rejected_by_enum_or_type():
    bad = VALID_FINDING.copy()
    bad["type"] = "<script>alert(1)</script>"
    result = _validate_finding(bad, "test-uuid-008")
    assert result is None


def test_invalid_tier_rejected():
    bad = VALID_FINDING.copy()
    bad["tier"] = "ULTRA"
    result = _validate_finding(bad, "test-uuid-009")
    assert result is None


def test_optional_fields_can_be_absent():
    finding = VALID_FINDING.copy()
    del finding["subject_ip"]
    del finding["subject_ja4"]
    result = _validate_finding(finding, "test-uuid-010")
    assert result is not None
    assert result["subject_ip"] == ""
    assert result["subject_ja4"] == ""
