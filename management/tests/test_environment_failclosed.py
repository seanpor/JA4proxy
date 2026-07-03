"""Regression tests for JA4PROXY-2026-0093 (HIGH) — security escape hatches
fail open when ENVIRONMENT is not exactly "production".

Before this fix, ``_is_production()`` (three duplicate copies, in auth.py,
main.py, and middleware/csrf.py) returned True ONLY for
``ENVIRONMENT in {"production", "prod"}``. Every test-only security escape
hatch — the hardcoded JWT signing secret, the OIDC signature-verification
skip, the CSRF disable flag, the SAML strict-off flag — and the startup
guard meant to catch them armed, gated on ``not _is_production()``. That
meant an unset, misspelled, or merely unrecognised ``ENVIRONMENT`` (``dmz``,
``staging``, a typo) was treated as "not production," silently activating
these hatches. JA4proxy is deployed as a DMZ security appliance, where
``ENVIRONMENT`` being unset or not exactly ``production``/``prod`` is
entirely plausible.

The fix: a single shared helper in ``management/api/environment.py``.
``is_explicit_nonproduction()`` is True ONLY for a known dev/test value
(``dev``, ``development``, ``test``, ``testing``, ``local``, ``ci``);
``is_production()`` is its inverse, so unset/unrecognised now means
production and every hatch fails CLOSED by default.

These tests fail if the fix is reverted (verified manually by restoring the
old ``_is_production()`` bodies and confirming these fail).
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _clear_env(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for n in names:
        monkeypatch.delenv(n, raising=False)


# ── ENVIRONMENT unset + TEST_MODE=1 must NOT enable test mode ──────────────


def test_unset_environment_with_test_mode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api import auth as auth_module
    from management.api.main import _enforce_no_test_mode_in_production

    _clear_env(monkeypatch, "ENVIRONMENT", "MANAGEMENT_JWT_SECRET")
    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")

    assert auth_module.is_test_mode() is False, (
        "is_test_mode() must be False when ENVIRONMENT is unset — unset must "
        "be treated as production"
    )
    with pytest.raises(RuntimeError, match="MANAGEMENT_JWT_SECRET"):
        auth_module._get_secret_key()
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        _enforce_no_test_mode_in_production()


# ── ENVIRONMENT=dmz + TEST_MODE=1 must NOT enable test mode ─────────────────


def test_dmz_environment_with_test_mode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api import auth as auth_module
    from management.api.main import _enforce_no_test_mode_in_production

    monkeypatch.setenv("ENVIRONMENT", "dmz")
    monkeypatch.delenv("MANAGEMENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")

    assert auth_module.is_test_mode() is False, (
        "is_test_mode() must be False when ENVIRONMENT=dmz — this is exactly "
        "the DMZ-appliance misconfiguration JA4PROXY-2026-0093 closes"
    )
    with pytest.raises(RuntimeError, match="MANAGEMENT_JWT_SECRET"):
        auth_module._get_secret_key()
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        _enforce_no_test_mode_in_production()


# ── ENVIRONMENT=dev + TEST_MODE=1 must still work (local dev unaffected) ───


def test_dev_environment_with_test_mode_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api import auth as auth_module
    from management.api.main import _enforce_no_test_mode_in_production

    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.delenv("MANAGEMENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")

    assert auth_module.is_test_mode() is True, (
        "is_test_mode() must be True for an explicit dev ENVIRONMENT — "
        "local development must not be broken by the fail-closed fix"
    )
    assert (
        auth_module._get_secret_key() == "test-secret-do-not-use-in-production"
    )
    _enforce_no_test_mode_in_production()  # must not raise


# ── ENVIRONMENT unset + MANAGEMENT_DISABLE_CSRF=1 must NOT disable CSRF ─────


def test_unset_environment_csrf_disable_flag_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CSRF-disable escape hatch must not activate for an unset
    ENVIRONMENT, and the main.py startup guard must independently refuse to
    boot with the flag armed outside an explicit dev/test environment."""
    from management.api.environment import is_explicit_nonproduction
    from management.api.main import _enforce_no_test_mode_in_production
    from management.api.middleware.csrf import CSRFMiddleware

    _clear_env(monkeypatch, "ENVIRONMENT")
    monkeypatch.setenv("MANAGEMENT_DISABLE_CSRF", "1")

    assert is_explicit_nonproduction() is False

    # main.py's startup guard independently refuses to boot the full app.
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        _enforce_no_test_mode_in_production()

    # And the middleware itself, exercised directly against a minimal app
    # (bypassing create_app()'s startup guard so we can observe the
    # middleware's own request-time behaviour), still 403s a mutating
    # request without a valid CSRF token.
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/api/v1/dial")
    def _dial() -> dict:
        return {"ok": True}

    with TestClient(app) as client:
        resp = client.post("/api/v1/dial", json={"value": 50})
        assert resp.status_code == 403, (
            f"CSRF must still be enforced when ENVIRONMENT is unset even "
            f"with MANAGEMENT_DISABLE_CSRF=1, got {resp.status_code}: {resp.text}"
        )
        assert resp.json()["error"] == "csrf_token_mismatch"


# ── Single definition invariant — no drift back to per-file copies ─────────


def test_only_one_environment_check_definition() -> None:
    """Guard against re-introducing duplicate ``_is_production()`` copies.

    None of auth.py, main.py, or middleware/csrf.py should define their own
    environment classification any more — they must import the shared
    helpers from management.api.environment.
    """
    import inspect

    from management.api import auth as auth_module
    from management.api import main as main_module
    from management.api.middleware import csrf as csrf_module

    for mod in (auth_module, main_module, csrf_module):
        src = inspect.getsource(mod)
        assert "def _is_production" not in src, (
            f"{mod.__name__} must not define its own _is_production() — "
            "import is_production from management.api.environment"
        )
        assert "def is_production" not in src, (
            f"{mod.__name__} must not redefine is_production() — import it "
            "from management.api.environment"
        )
