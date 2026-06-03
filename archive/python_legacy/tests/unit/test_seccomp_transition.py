"""Unit tests for SeccompTransition (Phase 56b-2, extended Phase 104).

Tests cover:
- apply_runtime_seccomp always returns bool, never raises.
- is_supported always returns bool, never raises.
- Missing JSON profile → returns False, no exception.
- Malformed JSON → returns False, no exception.
- is_supported on non-Linux / old kernels / parse errors (lines 58-68).
- apply_runtime_seccomp outer exception handler (lines 88-95).
- _apply internal paths: invalid path, not supported, profile not dict (lines 105-156).
- _apply_via_seccomp_lib full path with mocked seccomp library (lines 179-231).
- _oci_action_to_libseccomp action mapping and fallback.
"""

import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from src.security.seccomp_transition import (
    _apply,
    _apply_via_seccomp_lib,
    _oci_action_to_libseccomp,
    apply_runtime_seccomp,
    is_supported,
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_apply_returns_bool():
    """apply_runtime_seccomp always returns True or False, never raises."""
    result = (
        apply_runtime_seccomp.__wrapped__()
        if hasattr(apply_runtime_seccomp, "__wrapped__")
        else apply_runtime_seccomp()
    )
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


# ---------------------------------------------------------------------------
# Phase 104 — coverage gap closure
# ---------------------------------------------------------------------------


class TestIsSupportedEdgeCases:
    """Cover lines 58-68: non-Linux platform, old kernel, parse errors."""

    def test_non_linux_returns_false(self):
        """Line 59: sys.platform != 'linux' → False."""
        with patch("src.security.seccomp_transition.sys") as mock_sys:
            mock_sys.platform = "darwin"
            assert is_supported() is False

    def test_old_kernel_returns_false(self):
        """Kernel < 3.5 → False."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.return_value = "2.6.32-generic"
            assert is_supported() is False

    def test_kernel_35_returns_true(self):
        """Kernel == 3.5 → True."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.return_value = "3.5.0-custom"
            assert is_supported() is True

    def test_modern_kernel_returns_true(self):
        """Kernel 6.1 → True."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.return_value = "6.1.0-20-amd64"
            assert is_supported() is True

    def test_unparsable_release_returns_false(self):
        """Lines 66-68: platform.release() raises → False."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.side_effect = RuntimeError("boom")
            assert is_supported() is False

    def test_garbage_release_string_returns_false(self):
        """Non-numeric kernel version string → exception caught, False."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.return_value = "not-a-version"
            assert is_supported() is False

    def test_single_component_release(self):
        """Kernel with only major version, no minor → minor defaults to 0."""
        with patch("src.security.seccomp_transition.sys") as mock_sys, patch(
            "src.security.seccomp_transition.platform"
        ) as mock_plat:
            mock_sys.platform = "linux"
            mock_plat.release.return_value = "4"
            assert is_supported() is True


class TestApplyOuterExceptionHandler:
    """Cover lines 88-95: outer try/except in apply_runtime_seccomp."""

    def test_internal_apply_raises_returns_false(self):
        """When _apply raises an unexpected exception, the outer handler catches it."""
        with patch(
            "src.security.seccomp_transition._apply", side_effect=RuntimeError("kaboom")
        ):
            result = apply_runtime_seccomp("some/path.json")
            assert result is False


class TestApplyInternalPaths:
    """Cover _apply internal paths: invalid path, not-supported, profile not dict."""

    @pytest.mark.parametrize("bad_path", [None, "", 42, []])
    def test_invalid_profile_path(self, bad_path):
        """Lines 105-111: non-string or empty path → False."""
        assert _apply(bad_path) is False

    def test_not_supported_platform_skips(self, tmp_path):
        """Lines 113-119: is_supported() False → False."""
        profile = tmp_path / "valid.json"
        profile.write_text('{"defaultAction": "SCMP_ACT_ERRNO"}')
        with patch("src.security.seccomp_transition.is_supported", return_value=False):
            assert _apply(str(profile)) is False

    def test_profile_not_dict_returns_false(self, tmp_path):
        """Lines 150-156: JSON that parses to a list → False."""
        profile = tmp_path / "list.json"
        profile.write_text("[1, 2, 3]")
        with patch("src.security.seccomp_transition.is_supported", return_value=True):
            assert _apply(str(profile)) is False

    def test_seccomp_import_unavailable(self, tmp_path):
        """Line 162-168: seccomp library not installed → ImportError → False."""
        profile = tmp_path / "ok.json"
        profile.write_text('{"defaultAction": "SCMP_ACT_ERRNO"}')
        with patch(
            "src.security.seccomp_transition.is_supported", return_value=True
        ), patch("builtins.__import__", side_effect=_import_raise_for_seccomp):
            assert _apply(str(profile)) is False


def _import_raise_for_seccomp(name, *args, **kwargs):
    """Helper: raise ImportError only when importing 'seccomp'."""
    if name == "seccomp":
        raise ImportError("No module named 'seccomp'")
    return __builtins__.__import__(name, *args, **kwargs)  # type: ignore[attr-defined]


class TestApplyViaSeccompLib:
    """Cover lines 179-231: _apply_via_seccomp_lib and _oci_action_to_libseccomp."""

    @pytest.fixture()
    def mock_seccomp(self):
        """Create a mock seccomp module with SyscallFilter."""
        mod = MagicMock()
        mod.ALLOW = 1
        mod.ERRNO = 2
        mod.KILL = 3
        mod.TRAP = 4
        mod.TRACE = 5
        mod.LOG = 6
        mock_filter = MagicMock()
        mod.SyscallFilter.return_value = mock_filter
        return mod

    def test_successful_apply(self, mock_seccomp):
        """Lines 179-205: happy path — filter created, rules added, load() called."""
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"},
            ],
        }
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is True
        mock_seccomp.SyscallFilter.assert_called_once()
        mock_filter = mock_seccomp.SyscallFilter.return_value
        assert mock_filter.add_rule.call_count == 2
        mock_filter.load.assert_called_once()

    def test_empty_syscalls_list(self, mock_seccomp):
        """No syscall entries → filter still loads successfully."""
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is True

    def test_missing_syscalls_key(self, mock_seccomp):
        """No 'syscalls' key at all → defaults to empty list, still loads."""
        profile = {"defaultAction": "SCMP_ACT_ERRNO"}
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is True

    def test_add_rule_error_skipped(self, mock_seccomp):
        """Lines 193-199: add_rule raises for one syscall → skipped, others processed."""
        mock_filter = mock_seccomp.SyscallFilter.return_value
        mock_filter.add_rule.side_effect = [OSError("unknown syscall"), None]
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {"names": ["bad_syscall", "good_syscall"], "action": "SCMP_ACT_ALLOW"}
            ],
        }
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is True
        mock_filter.load.assert_called_once()

    def test_load_raises_returns_false(self, mock_seccomp):
        """Lines 206-213: ctx.load() raises → returns False."""
        mock_seccomp.SyscallFilter.return_value.load.side_effect = OSError(
            "permission denied"
        )
        profile = {"defaultAction": "SCMP_ACT_ERRNO"}
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is False

    def test_syscall_filter_constructor_raises(self, mock_seccomp):
        """SyscallFilter() raises → returns False."""
        mock_seccomp.SyscallFilter.side_effect = RuntimeError("init failed")
        profile = {"defaultAction": "SCMP_ACT_ERRNO"}
        result = _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        assert result is False

    def test_missing_default_action_uses_errno(self, mock_seccomp):
        """Line 181: no defaultAction → defaults to SCMP_ACT_ERRNO."""
        profile = {"syscalls": []}
        _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        mock_seccomp.SyscallFilter.assert_called_once_with(defaction=mock_seccomp.ERRNO)

    def test_entry_missing_action_defaults_allow(self, mock_seccomp):
        """Line 188: entry without 'action' key → defaults to SCMP_ACT_ALLOW."""
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [{"names": ["read"]}],  # no 'action' key
        }
        _apply_via_seccomp_lib(mock_seccomp, profile, "/fake/path.json")
        mock_filter = mock_seccomp.SyscallFilter.return_value
        mock_filter.add_rule.assert_called_once_with(mock_seccomp.ALLOW, "read")


class TestOCIActionMapping:
    """Cover lines 216-231: _oci_action_to_libseccomp."""

    @pytest.fixture()
    def mock_mod(self):
        mod = MagicMock()
        mod.ALLOW = 1
        mod.ERRNO = 2
        mod.KILL = 3
        mod.TRAP = 4
        mod.TRACE = 5
        mod.LOG = 6
        return mod

    @pytest.mark.parametrize(
        "oci_str,expected_attr",
        [
            ("SCMP_ACT_ALLOW", "ALLOW"),
            ("SCMP_ACT_ERRNO", "ERRNO"),
            ("SCMP_ACT_KILL", "KILL"),
            ("SCMP_ACT_KILL_PROCESS", "KILL"),
            ("SCMP_ACT_TRAP", "TRAP"),
            ("SCMP_ACT_TRACE", "TRACE"),
            ("SCMP_ACT_LOG", "LOG"),
        ],
    )
    def test_known_actions_mapped(self, mock_mod, oci_str, expected_attr):
        result = _oci_action_to_libseccomp(mock_mod, oci_str)
        assert result == getattr(mock_mod, expected_attr)

    def test_unknown_action_defaults_to_errno(self, mock_mod):
        """Line 230: unknown action string → falls back to ERRNO."""
        result = _oci_action_to_libseccomp(mock_mod, "SCMP_ACT_UNKNOWN")
        assert result == mock_mod.ERRNO

    def test_missing_attr_returns_zero(self):
        """Line 231: getattr fallback when module lacks the attribute → 0."""
        bare_mod = SimpleNamespace()  # no ALLOW, ERRNO, etc.
        result = _oci_action_to_libseccomp(bare_mod, "SCMP_ACT_ALLOW")
        assert result == 0
