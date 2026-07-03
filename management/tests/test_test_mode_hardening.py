"""Regression tests for JA4PROXY-2026-0023 — Test secret fallback in production.

The Management API used to read MANAGEMENT_TEST_MODE=1 and return either a
hardcoded JWT signing secret (management/api/auth.py) or skip OIDC ID token
signature verification entirely (management/api/routes/oidc.py). Anyone who
could set that env var on a production container (container escape,
supply-chain, misconfigured deploy) got an authentication bypass.

The hardening:

* auth.is_test_mode() returns False whenever ENVIRONMENT is not an explicit
  dev/test value (JA4PROXY-2026-0093, phase-521: unset/unrecognised
  ENVIRONMENT — e.g. a DMZ deployment — counts as production), so the JWT
  secret fallback and the OIDC signature bypass become unreachable even if
  MANAGEMENT_TEST_MODE=1 is set.
* management.api.main.create_app raises RuntimeError at boot when
  MANAGEMENT_TEST_MODE=1 is set and ENVIRONMENT is not an explicit dev/test
  value, so the misconfiguration fails loudly rather than silently running
  insecure.

These tests lock that behaviour in.
"""

from __future__ import annotations

import os

import pytest


def _clear_env(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for n in names:
        monkeypatch.delenv(n, raising=False)


def test_regression_JA4PROXY_2026_0023_is_test_mode_off_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.auth import is_test_mode

    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
    for env_val in ("production", "PRODUCTION", "prod", "Prod"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert is_test_mode() is False, (
            f"is_test_mode must be False when ENVIRONMENT={env_val!r}, "
            "otherwise MANAGEMENT_TEST_MODE enables auth bypasses in prod"
        )


def test_regression_JA4PROXY_2026_0023_is_test_mode_on_outside_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.auth import is_test_mode

    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
    for env_val in ("dev", "development", "test", "testing", "local", "ci"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert is_test_mode() is True, (
            f"is_test_mode must honour MANAGEMENT_TEST_MODE=1 when "
            f"ENVIRONMENT={env_val!r}"
        )


def test_regression_JA4PROXY_2026_0093_is_test_mode_off_for_unset_or_unrecognised_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JA4PROXY-2026-0093: unset/unrecognised ENVIRONMENT is production.

    Before the fix, "" (unset) and "staging" were treated as "not
    production," so MANAGEMENT_TEST_MODE=1 activated the hardcoded-JWT-secret
    and OIDC-signature-skip escape hatches. JA4proxy is a DMZ appliance where
    ENVIRONMENT being unset or set to something other than an explicit
    dev/test value is entirely plausible, so these must now be treated as
    production and the escape hatches must NOT activate.
    """
    from management.api.auth import is_test_mode

    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
    for env_val in ("", "staging", "dmz", "qa", "prodction"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert is_test_mode() is False, (
            f"is_test_mode must be False when ENVIRONMENT={env_val!r} — "
            "unrecognised/unset values must fail closed as production"
        )


def test_regression_JA4PROXY_2026_0023_is_test_mode_off_when_flag_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.auth import is_test_mode

    _clear_env(monkeypatch, "MANAGEMENT_TEST_MODE", "ENVIRONMENT")
    assert is_test_mode() is False


def test_regression_JA4PROXY_2026_0023_get_secret_raises_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api import auth as auth_module

    _clear_env(monkeypatch, "MANAGEMENT_JWT_SECRET", "MANAGEMENT_TEST_MODE")
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(RuntimeError, match="MANAGEMENT_JWT_SECRET"):
        auth_module._get_secret_key()


def test_regression_JA4PROXY_2026_0023_get_secret_fallback_only_outside_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api import auth as auth_module

    _clear_env(monkeypatch, "MANAGEMENT_JWT_SECRET")

    # In prod the fallback MUST NOT kick in, even if TEST_MODE is on.
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
    with pytest.raises(RuntimeError, match="MANAGEMENT_JWT_SECRET"):
        auth_module._get_secret_key()

    # Outside prod the fallback is still allowed (keeps unit tests running).
    monkeypatch.setenv("ENVIRONMENT", "dev")
    assert auth_module._get_secret_key() == "test-secret-do-not-use-in-production"


def test_regression_JA4PROXY_2026_0023_create_app_refuses_test_mode_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import _enforce_no_test_mode_in_production

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        _enforce_no_test_mode_in_production()

    # 'prod' abbreviation must also trip.
    monkeypatch.setenv("ENVIRONMENT", "prod")
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        _enforce_no_test_mode_in_production()


def test_regression_JA4PROXY_2026_0023_create_app_allows_non_prod_test_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import _enforce_no_test_mode_in_production

    for env_val in ("dev", "test"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
        _enforce_no_test_mode_in_production()  # must not raise


def test_regression_JA4PROXY_2026_0093_create_app_refuses_test_mode_for_unset_or_unrecognised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JA4PROXY-2026-0093: the startup guard must also fire for unset or
    unrecognised ENVIRONMENT, not just ENVIRONMENT=production — that is
    exactly the DMZ-appliance misconfiguration this finding closes."""
    from management.api.main import _enforce_no_test_mode_in_production

    for env_val in ("", "staging", "dmz"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
        with pytest.raises(RuntimeError, match="mutually exclusive"):
            _enforce_no_test_mode_in_production()


def test_regression_JA4PROXY_2026_0023_create_app_allows_prod_without_test_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import _enforce_no_test_mode_in_production

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
    # phase-101 H8: MANAGEMENT_DISABLE_CSRF is also a test-only flag and the
    # prod-startup guard rejects it, so it must be unset for this regression.
    monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)
    # phase-122 M-1: MANAGEMENT_SAML_STRICT=false is also rejected in production.
    monkeypatch.delenv("MANAGEMENT_SAML_STRICT", raising=False)
    _enforce_no_test_mode_in_production()  # must not raise
