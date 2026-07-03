"""Regression tests for JA4PROXY-2026-0096 (MEDIUM) — quickstart compose ships
a known-value MANAGEMENT_JWT_SECRET / MANAGEMENT_ADMIN_PASSWORD default with
no boot guard.

``docker-compose.yml`` (the quickstart file an operator under incident
pressure copies) defaults ``MANAGEMENT_JWT_SECRET`` to the committed literal
``ja4proxy-quickstart-secret-change-me`` and ``MANAGEMENT_ADMIN_PASSWORD`` to
``changeme``. Nothing previously refused to boot on those values, so a
deployment that forgets to override them signs admin JWTs with a key that is
public in this repository / accepts a known password.

The fix: ``management.api.main._enforce_strong_secrets()``, called from
``create_app()``, refuses to boot when the JWT secret is unset, equals the
committed quickstart literal, or is shorter than 32 characters — or when the
admin password is still ``changeme`` with no bcrypt hash configured — unless
``ENVIRONMENT`` is an explicit dev/test value (the same fail-closed rule as
JA4PROXY-2026-0093, so the quickstart itself, which sets ENVIRONMENT=dev,
keeps booting).

These tests fail if the guard is reverted (verified manually: removing the
``_enforce_strong_secrets()`` call from ``create_app()`` makes every
"must raise" test below fail).
"""

from __future__ import annotations

import pytest


def _clear_env(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for n in names:
        monkeypatch.delenv(n, raising=False)


def _clean_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every flag another startup guard reacts to, so each test below
    isolates the secret/password guard specifically."""
    _clear_env(
        monkeypatch,
        "MANAGEMENT_TEST_MODE",
        "MANAGEMENT_DISABLE_CSRF",
        "MANAGEMENT_SAML_STRICT",
    )


# ── MANAGEMENT_JWT_SECRET ────────────────────────────────────────────────────


def test_quickstart_default_secret_rejected_outside_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "ja4proxy-quickstart-secret-change-me")
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "not-the-default")

    with pytest.raises(RuntimeError, match="quickstart default"):
        create_app()


def test_unset_secret_rejected_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "dmz")
    monkeypatch.delenv("MANAGEMENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "not-the-default")

    with pytest.raises(RuntimeError, match="MANAGEMENT_JWT_SECRET"):
        create_app()


def test_short_secret_rejected_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "short-secret")
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "not-the-default")

    with pytest.raises(RuntimeError, match="shorter than"):
        create_app()


def test_strong_secret_boots_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "MANAGEMENT_JWT_SECRET", "a-strong-randomly-generated-secret-value-32plus"
    )
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "not-the-default")

    app = create_app()
    assert app is not None


def test_quickstart_default_secret_allowed_in_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The quickstart (docker-compose.yml sets ENVIRONMENT=dev) must keep
    booting with its committed defaults — this guard must not break
    `make start` / CI."""
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "ja4proxy-quickstart-secret-change-me")
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "changeme")

    app = create_app()
    assert app is not None


# ── MANAGEMENT_ADMIN_PASSWORD ────────────────────────────────────────────────


def test_default_admin_password_rejected_outside_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "MANAGEMENT_JWT_SECRET", "a-strong-randomly-generated-secret-value-32plus"
    )
    monkeypatch.delenv("MANAGEMENT_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "changeme")

    with pytest.raises(RuntimeError, match="changeme"):
        create_app()


def test_admin_password_hash_configured_boots_outside_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from management.api.main import create_app

    _clean_baseline(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "MANAGEMENT_JWT_SECRET", "a-strong-randomly-generated-secret-value-32plus"
    )
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD_HASH", "$2b$12$abcdefghijklmnopqrstuv")
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "changeme")

    app = create_app()
    assert app is not None
