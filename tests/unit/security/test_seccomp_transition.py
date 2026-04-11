"""Unit tests for SeccompTransition (Phase 56b-2).

Tests cover:
- apply_runtime_seccomp always returns bool, never raises.
- is_supported always returns bool, never raises.
- Missing JSON profile → returns False, no exception.
- Malformed JSON → returns False, no exception.
"""

import json
import os
import tempfile

import pytest

from src.security.seccomp_transition import apply_runtime_seccomp, is_supported

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_apply_returns_bool():
    """apply_runtime_seccomp always returns True or False, never raises."""
    result = apply_runtime_seccomp.__wrapped__() if hasattr(apply_runtime_seccomp, "__wrapped__") else apply_runtime_seccomp()
    assert isinstance(result, bool)


def test_is_supported_returns_bool():
    """is_supported always returns bool, never raises."""
    result = is_supported()
    assert isinstance(result, bool)


def test_apply_fails_open_on_missing_profile():
    """Missing JSON profile → returns False, no exception."""
    result = apply_runtime_seccomp(profile_path="/nonexistent/path/seccomp.json")
    assert result is False


def test_apply_fails_open_on_bad_json(tmp_path):
    """Malformed JSON → returns False, no exception."""
    bad_json = tmp_path / "bad_seccomp.json"
    bad_json.write_text("{ this is not valid json !!!! }")

    result = apply_runtime_seccomp(profile_path=str(bad_json))
    assert result is False


def test_apply_fails_open_on_empty_file(tmp_path):
    """Empty file → returns False, no exception."""
    empty = tmp_path / "empty.json"
    empty.write_text("")

    result = apply_runtime_seccomp(profile_path=str(empty))
    assert result is False


def test_apply_with_valid_profile(tmp_path):
    """Valid OCI-format JSON profile → returns bool (True if supported, False otherwise)."""
    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [
            {
                "names": ["read", "write", "close"],
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }
    profile_path = tmp_path / "seccomp.json"
    profile_path.write_text(json.dumps(profile))

    result = apply_runtime_seccomp(profile_path=str(profile_path))
    assert isinstance(result, bool)
    # On Linux with seccomp available this may be True; on other platforms False.
    # Either way it must not raise.


def test_is_supported_consistent():
    """is_supported returns the same value on repeated calls."""
    assert is_supported() == is_supported()


def test_apply_never_raises_on_any_input():
    """apply_runtime_seccomp must never propagate an exception under any circumstances."""
    # Various bad paths
    for path in [None, "", "   ", "/dev/null", "/proc/self/maps"]:
        try:
            result = apply_runtime_seccomp(profile_path=path)  # type: ignore[arg-type]
            assert isinstance(result, bool)
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"apply_runtime_seccomp raised {type(exc).__name__}: {exc}")
