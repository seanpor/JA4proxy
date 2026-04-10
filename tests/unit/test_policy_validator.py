"""Unit tests for src/governance/policy_validator.py.

Tests cover all offline validation rules — no network, no API required.

Validator contract:
  validate_policy(yaml_text: str, current_dial: int = 0) -> dict
    Returns the parsed policy dict on success.
    Raises one of:
      PolicySyntaxError    — YAML cannot be parsed
      PolicySchemaError    — unknown field, invalid JA4, invalid CIDR, unknown bypass key
      PolicyTTLError       — expires value is in the past
      PolicyDuplicateError — two identical JA4 fingerprints in the same list
      PolicyValidationError — dial increase > 20 without shadow_mode_approved: true

JA4 fingerprint pattern: [a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}
Example valid JA4:       t13d1516h2_aabbccddeeff_aabbccddeeff

Every test asserts on a specific value or exception — none rely on
"doesn't raise" alone.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Lazy import helper — gives an explicit ImportError if the module is absent.
# The validator does not exist yet (TDD), so tests will FAIL (not ERROR) at
# collection time until the implementation is written.
# ---------------------------------------------------------------------------


def _import_validator():
    """Import the policy validator module. Raises ImportError if not present."""
    from src.governance import policy_validator as pv  # type: ignore[import]
    return pv


# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

_VALID_MINIMAL_YAML = textwrap.dedent("""\
    meta:
      version: "1.0"
      environment: prod
      last_updated: "2026-04-01T00:00:00Z"
      last_updated_by: "ops@example.com"

    dial:
      setting: 10
      changed_by: "ops@example.com"
""")

# Valid JA4 fingerprints — match [a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}
_JA4_VALID_1 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
_JA4_VALID_2 = "t13d1516h2_112233445566_aabbccddeeff"
_JA4_VALID_BLOCK = "t10d170900_9dc949161b6c_b64c0ad42cb7"


# ---------------------------------------------------------------------------
# Helper: build an 'expires' timestamp in the past or future
# ---------------------------------------------------------------------------


def _iso_offset(days: int) -> str:
    """Return an ISO 8601 UTC timestamp offset by *days* from now."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ===========================================================================
# 1. test_valid_minimal_policy
# ===========================================================================


def test_valid_minimal_policy():
    """Minimal valid YAML (meta + dial) passes without raising; returns dict."""
    pv = _import_validator()

    result = pv.validate_policy(_VALID_MINIMAL_YAML)

    assert isinstance(result, dict), (
        f"Expected validate_policy() to return a dict, got {type(result)!r}"
    )
    # The returned dict must contain the parsed dial setting
    assert result.get("dial", {}).get("setting") == 10, (
        f"Expected dial.setting=10 in returned dict, got: {result.get('dial')!r}"
    )


# ===========================================================================
# 2. test_invalid_yaml_syntax
# ===========================================================================


def test_invalid_yaml_syntax():
    """YAML with a tab-indent error raises PolicySyntaxError."""
    pv = _import_validator()

    # Tabs are illegal in YAML indentation — this will fail parsing.
    bad_yaml = "meta:\n\tversion: '1.0'\n"

    import pytest
    with pytest.raises(pv.PolicySyntaxError) as exc_info:
        pv.validate_policy(bad_yaml)

    # The exception must be a PolicySyntaxError (not a generic Exception).
    assert isinstance(exc_info.value, pv.PolicySyntaxError), (
        f"Expected PolicySyntaxError, got {type(exc_info.value)!r}"
    )


# ===========================================================================
# 3. test_unknown_field_raises
# ===========================================================================


def test_unknown_field_raises():
    """Extra top-level field 'rogue_key' raises PolicySchemaError."""
    pv = _import_validator()

    yaml_with_rogue = _VALID_MINIMAL_YAML + textwrap.dedent("""\

        rogue_key:
          some_value: true
    """)

    import pytest
    with pytest.raises(pv.PolicySchemaError) as exc_info:
        pv.validate_policy(yaml_with_rogue)

    err_str = str(exc_info.value).lower()
    assert "rogue_key" in err_str or "unknown" in err_str or "field" in err_str, (
        f"Expected error message to mention 'rogue_key' or 'unknown field', got: {exc_info.value!r}"
    )


# ===========================================================================
# 4. test_expired_ttl_detected
# ===========================================================================


def test_expired_ttl_detected():
    """expires set to 1 year in the past raises PolicyTTLError."""
    pv = _import_validator()

    past_date = _iso_offset(-365)
    yaml_text = textwrap.dedent(f"""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 30
          changed_by: "ops@example.com"

        allowlist:
          fingerprints:
            - ja4: "{_JA4_VALID_1}"
              reason: "Test entry with expired TTL"
              added_by: "ops@example.com"
              expires: "{past_date}"
    """)

    import pytest
    with pytest.raises(pv.PolicyTTLError) as exc_info:
        pv.validate_policy(yaml_text)

    assert isinstance(exc_info.value, pv.PolicyTTLError), (
        f"Expected PolicyTTLError, got {type(exc_info.value)!r}"
    )


# ===========================================================================
# 5. test_dial_increase_gt_20_without_flag
# ===========================================================================


def test_dial_increase_gt_20_without_flag():
    """dial 50→75 (increase of 25) without shadow_mode_approved: true raises PolicyValidationError."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 75
          changed_by: "ops@example.com"
    """)

    import pytest
    # current_dial=50 → increase of 25 → requires shadow_mode_approved: true
    with pytest.raises(pv.PolicyValidationError) as exc_info:
        pv.validate_policy(yaml_text, current_dial=50)

    err_str = str(exc_info.value).lower()
    assert any(keyword in err_str for keyword in ("shadow_mode", "approval", "approved", "increase")), (
        f"Expected error message about shadow_mode_approved, got: {exc_info.value!r}"
    )


# ===========================================================================
# 6. test_dial_increase_gt_20_with_flag
# ===========================================================================


def test_dial_increase_gt_20_with_flag():
    """dial 50→75 (increase of 25) WITH shadow_mode_approved: true passes."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 75
          changed_by: "ops@example.com"
          shadow_mode_approved: true
    """)

    # Must not raise; must return a dict with the dial setting
    result = pv.validate_policy(yaml_text, current_dial=50)

    assert isinstance(result, dict), (
        f"Expected dict result when shadow_mode_approved=true, got {type(result)!r}"
    )
    assert result.get("dial", {}).get("setting") == 75, (
        f"Expected dial.setting=75, got: {result.get('dial')!r}"
    )
    assert result.get("dial", {}).get("shadow_mode_approved") is True, (
        f"Expected dial.shadow_mode_approved=true, got: {result.get('dial')!r}"
    )


# ===========================================================================
# 7. test_dial_decrease_no_flag_required
# ===========================================================================


def test_dial_decrease_no_flag_required():
    """dial 80→50 (decrease of 30) without shadow_mode_approved passes."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 50
          changed_by: "ops@example.com"
    """)

    # current_dial=80, new=50 → decrease → no shadow_mode_approved needed
    result = pv.validate_policy(yaml_text, current_dial=80)

    assert isinstance(result, dict), (
        f"Expected dict result on dial decrease, got {type(result)!r}"
    )
    assert result.get("dial", {}).get("setting") == 50, (
        f"Expected dial.setting=50, got: {result.get('dial')!r}"
    )


# ===========================================================================
# 8. test_invalid_cidr_notation
# ===========================================================================


def test_invalid_cidr_notation():
    """cidr: 'not-a-cidr' in allowlist.ips raises PolicySchemaError."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 30
          changed_by: "ops@example.com"

        allowlist:
          ips:
            - cidr: "not-a-cidr"
              reason: "Invalid CIDR test"
              added_by: "ops@example.com"
    """)

    import pytest
    with pytest.raises(pv.PolicySchemaError) as exc_info:
        pv.validate_policy(yaml_text)

    err_str = str(exc_info.value).lower()
    assert any(keyword in err_str for keyword in ("cidr", "invalid", "network", "address")), (
        f"Expected error mentioning CIDR/address issue, got: {exc_info.value!r}"
    )


# ===========================================================================
# 9. test_invalid_ja4_format
# ===========================================================================


def test_invalid_ja4_format():
    """ja4: 'bad_fingerprint' in allowlist.fingerprints raises PolicySchemaError."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 30
          changed_by: "ops@example.com"

        allowlist:
          fingerprints:
            - ja4: "bad_fingerprint"
              reason: "Should fail JA4 format check"
              added_by: "ops@example.com"
    """)

    import pytest
    with pytest.raises(pv.PolicySchemaError) as exc_info:
        pv.validate_policy(yaml_text)

    err_str = str(exc_info.value).lower()
    assert any(keyword in err_str for keyword in ("ja4", "fingerprint", "format", "pattern", "invalid")), (
        f"Expected error mentioning JA4/fingerprint format, got: {exc_info.value!r}"
    )


# ===========================================================================
# 10. test_duplicate_allowlist_entries
# ===========================================================================


def test_duplicate_allowlist_entries():
    """Two entries with identical JA4 in allowlist.fingerprints raise PolicyDuplicateError."""
    pv = _import_validator()

    yaml_text = textwrap.dedent(f"""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 30
          changed_by: "ops@example.com"

        allowlist:
          fingerprints:
            - ja4: "{_JA4_VALID_1}"
              reason: "First entry"
              added_by: "ops@example.com"
            - ja4: "{_JA4_VALID_1}"
              reason: "Duplicate — same JA4 as above"
              added_by: "ops@example.com"
    """)

    import pytest
    with pytest.raises(pv.PolicyDuplicateError) as exc_info:
        pv.validate_policy(yaml_text)

    err_str = str(exc_info.value).lower()
    assert any(keyword in err_str for keyword in ("duplicate", "already", "twice", "fingerprint", _JA4_VALID_1.lower()[:10])), (
        f"Expected error mentioning duplicate entry, got: {exc_info.value!r}"
    )


# ===========================================================================
# 11. test_bypass_toggle_unknown_key
# ===========================================================================


def test_bypass_toggle_unknown_key():
    """bypass_toggles with key 'unknown_bypass: true' raises PolicySchemaError."""
    pv = _import_validator()

    yaml_text = textwrap.dedent("""\
        meta:
          version: "1.0"
          environment: prod
          last_updated: "2026-04-01T00:00:00Z"
          last_updated_by: "ops@example.com"

        dial:
          setting: 30
          changed_by: "ops@example.com"

        bypass_toggles:
          alpn_browser_bypass: true
          unknown_bypass: true
    """)

    import pytest
    with pytest.raises(pv.PolicySchemaError) as exc_info:
        pv.validate_policy(yaml_text)

    err_str = str(exc_info.value).lower()
    assert any(keyword in err_str for keyword in ("unknown_bypass", "unknown", "bypass", "invalid")), (
        f"Expected error mentioning unknown bypass key, got: {exc_info.value!r}"
    )
