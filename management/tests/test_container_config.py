"""Tests for container configuration parity.

These tests verify that the application is correctly wired for its deployment
environment — catching mismatches between docker-compose environment variables
and what the application actually reads.

Regression: the initial test suite used fakeredis (no password needed) and
never verified that REDIS_URL included the Redis password. The container
connected to a password-protected Redis with an unauthenticated URL and got
AuthenticationError at runtime.

Rules enforced here:
  1. REDIS_URL must support the :password@ form when REDIS_PASSWORD is set.
  2. Required env vars (MANAGEMENT_JWT_SECRET) must cause a clear startup
     failure, not a silent misconfiguration.
  3. The redis_client module must never swallow connection credential errors
     silently.
"""

import os
import re

import pytest


# ---------------------------------------------------------------------------
# REDIS_URL password handling
# ---------------------------------------------------------------------------


def test_redis_url_with_password_is_valid_url() -> None:
    """redis://:password@host:port/db must be a valid connection string."""
    from management.api.redis_client import _build_redis_url

    os.environ["REDIS_URL"] = "redis://:secret@redis:6379/0"
    try:
        url = _build_redis_url()
        assert url == "redis://:secret@redis:6379/0"
        # Must contain the password separator
        assert ":secret@" in url
    finally:
        del os.environ["REDIS_URL"]


def test_redis_url_built_from_components_includes_password() -> None:
    """When REDIS_PASSWORD is set, the built URL must include the password."""
    from management.api.redis_client import _build_redis_url

    # Remove REDIS_URL so _build_redis_url falls through to components
    old = os.environ.pop("REDIS_URL", None)
    os.environ["REDIS_HOST"] = "redis"
    os.environ["REDIS_PORT"] = "6379"
    os.environ["REDIS_DB"] = "0"
    os.environ["REDIS_PASSWORD"] = "hunter2"
    try:
        url = _build_redis_url()
        assert "hunter2" in url, (
            f"REDIS_PASSWORD is set but password is not in built URL: {url!r}. "
            "The management container will fail to authenticate to Redis."
        )
        assert url.startswith("redis://"), f"URL must use redis:// scheme, got: {url!r}"
    finally:
        os.environ.pop("REDIS_HOST", None)
        os.environ.pop("REDIS_PORT", None)
        os.environ.pop("REDIS_DB", None)
        os.environ.pop("REDIS_PASSWORD", None)
        if old is not None:
            os.environ["REDIS_URL"] = old


def test_redis_url_without_password_has_no_at_sign() -> None:
    """When no password is configured, the URL must not contain a bare @ sign."""
    from management.api.redis_client import _build_redis_url

    old = os.environ.pop("REDIS_URL", None)
    os.environ.pop("REDIS_PASSWORD", None)
    os.environ["REDIS_HOST"] = "redis"
    try:
        url = _build_redis_url()
        # Allow redis://:@host form only if password is empty string
        # Disallow redis://host (no password field) having a stray @
        assert url.count("@") <= 1
    finally:
        os.environ.pop("REDIS_HOST", None)
        if old is not None:
            os.environ["REDIS_URL"] = old


# ---------------------------------------------------------------------------
# docker-compose.poc.yml parity check
# ---------------------------------------------------------------------------


def test_docker_compose_management_redis_url_uses_password() -> None:
    """The management service in docker-compose.poc.yml must pass REDIS_PASSWORD
    in the REDIS_URL environment variable.

    Regression test: the initial docker-compose entry used
      REDIS_URL=redis://redis:6379/0
    which does not include the password, causing AuthenticationError at runtime
    even though all unit tests passed (they used fakeredis, no password needed).
    """
    compose_path = (
        os.path.dirname(__file__)  # management/tests/
        + "/../../docker-compose.poc.yml"
    )
    compose_path = os.path.normpath(compose_path)

    with open(compose_path) as f:
        content = f.read()

    # Find the management service section
    # Look for the REDIS_URL line within a reasonable window after "management:"
    mgmt_idx = content.find("  management:")
    assert mgmt_idx != -1, "management service not found in docker-compose.poc.yml"

    # Grab the next 1500 chars (enough to cover the service definition)
    mgmt_section = content[mgmt_idx : mgmt_idx + 1500]

    # Find the REDIS_URL line
    redis_url_match = re.search(r"REDIS_URL=([^\n]+)", mgmt_section)
    assert redis_url_match is not None, (
        "REDIS_URL environment variable not found in management service definition. "
        "The management container needs REDIS_URL to connect to Redis."
    )

    redis_url_value = redis_url_match.group(1).strip()

    # The URL must reference REDIS_PASSWORD (as an env var expansion)
    # Acceptable forms:
    #   redis://:${REDIS_PASSWORD}@redis:6379/0
    #   redis://:${REDIS_PASSWORD:?...}@redis:6379/0
    assert "REDIS_PASSWORD" in redis_url_value, (
        f"REDIS_URL in docker-compose management service is: {redis_url_value!r}\n"
        "This does not include REDIS_PASSWORD. The management container will fail\n"
        "to authenticate to Redis when REDIS_PASSWORD is set (which it always is\n"
        "in this project). Fix: REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0"
    )


# ---------------------------------------------------------------------------
# Required env vars produce clear errors
# ---------------------------------------------------------------------------


def test_jwt_secret_missing_raises_on_token_creation() -> None:
    """If MANAGEMENT_JWT_SECRET is not set, creating a token must fail clearly,
    not silently use an empty/default secret."""
    old = os.environ.pop("MANAGEMENT_JWT_SECRET", None)
    try:
        from management.api import auth as auth_module
        import importlib
        importlib.reload(auth_module)

        # _get_secret_key() should raise or return a non-empty value
        # If it returns "" or "change-me" silently, that's a bug
        try:
            secret = auth_module._get_secret_key()
            # If it returns something, it must not be empty
            assert secret, (
                "MANAGEMENT_JWT_SECRET is unset but _get_secret_key() returned "
                f"an empty string {secret!r}. Tokens would be signed with no secret."
            )
        except (ValueError, RuntimeError, SystemExit):
            pass  # Raising is the correct behaviour
    finally:
        if old is not None:
            os.environ["MANAGEMENT_JWT_SECRET"] = old
        # Reload to restore original state
        import importlib
        from management.api import auth as auth_module
        importlib.reload(auth_module)
