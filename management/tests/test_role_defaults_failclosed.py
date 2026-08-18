"""Regression tests for JA4PROXY-2026-0095 (MEDIUM) — insecure role defaults
on the bearer-token / token-rotate / token-issuance paths.

JA4PROXY-2026-0034 established the rule that a missing or invalid role must
fail closed to the least-privileged role (``auditor``) rather than escalate.
That rule was applied to the cookie-JWT path in ``get_current_user`` but
missed three sibling spots, all in ``management/api/``:

* ``auth.py`` ``get_bearer_user`` — a stored token hash with no/invalid
  ``role`` field defaulted to ``operator`` (write access) instead of
  ``auditor``.
* ``auth.py`` ``get_bearer_user`` — a malformed ``expires_at`` was silently
  ignored, treating the token as non-expiring instead of rejecting it.
* ``auth.py`` ``_create_access_token`` — defaulted the ``role`` parameter to
  ``"admin"``, so any caller that forgot the argument minted an admin token.
* ``routes/tokens.py`` rotate handler — a role-less old token rotated into a
  new ``operator`` token instead of ``auditor``.

None of this is exploitable through the API today (every creation path
always writes a valid role), but a legacy token, a partially-written Redis
hash, or a future caller silently gaining write/admin authority instead of
read-only is the wrong direction for a security appliance to fail.

These tests fail if the fixes are reverted (verified manually: restoring the
old ``operator``/``admin`` defaults and the ``pass`` on malformed expiry
makes each test below fail).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt as _bcrypt
import pytest
from httpx import ASGITransport, AsyncClient

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app

_OPERATOR_ROUTE = "/api/v1/bans"


def _now_plus(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


async def _seed_bearer_token(
    fake_redis,
    token_id: str,
    raw_token: str,
    role_field: str | None,
    expires_at: str | None = None,
) -> None:
    """Write a `mgmt:token:{id}` hash directly, bypassing the create endpoint
    (which always writes a valid role) so we can simulate a corrupt/legacy
    record."""
    stored_hash = _bcrypt.hashpw(raw_token.encode(), _bcrypt.gensalt()).decode()
    fields: dict[str, str] = {
        "id": token_id,
        "name": "legacy-token",
        "hash": stored_hash,
        "created_at": _now_plus(-3600),
        "expires_at": expires_at or "",
        "last_used_at": "",
    }
    if role_field is not None:
        fields["role"] = role_field
    await fake_redis.hset(f"mgmt:token:{token_id}", mapping=fields)
    await fake_redis.sadd("mgmt:token:idx", token_id)


async def _post_ban_with_bearer(app, raw_token: str) -> int:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post(
            _OPERATOR_ROUTE,
            json={"ip": "203.0.113.5", "reason": "regression test ban attempt"},
            headers={
                "Authorization": f"Bearer {raw_token}",
                "Accept": "application/json",
            },
        )
        return r.status_code


@pytest.mark.asyncio
async def test_bearer_token_no_role_field_denied_operator_route(fake_redis) -> None:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    raw = "raw-token-no-role-field"
    await _seed_bearer_token(fake_redis, "tok-no-role", raw, role_field=None)

    status_code = await _post_ban_with_bearer(app, raw)
    assert status_code == 403, (
        f"a role-less bearer token must default to auditor (insufficient for "
        f"an operator route), got {status_code}"
    )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_bearer_token_garbage_role_denied_operator_route(fake_redis) -> None:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    raw = "raw-token-garbage-role"
    await _seed_bearer_token(fake_redis, "tok-garbage-role", raw, role_field="not-a-real-role")

    status_code = await _post_ban_with_bearer(app, raw)
    assert status_code == 403, (
        f"an unrecognised role value must default to auditor, got {status_code}"
    )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_bearer_token_malformed_expiry_rejected(fake_redis) -> None:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    raw = "raw-token-malformed-expiry"
    await _seed_bearer_token(
        fake_redis,
        "tok-malformed-expiry",
        raw,
        role_field="operator",
        expires_at="not-a-real-timestamp",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.get(
            "/api/v1/dial",
            headers={"Authorization": f"Bearer {raw}", "Accept": "application/json"},
        )
        assert r.status_code == 401, (
            f"a malformed expires_at must reject the token (fail closed), "
            f"got {r.status_code}"
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_rotate_role_less_token_becomes_auditor(fake_redis) -> None:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    await _seed_bearer_token(
        fake_redis, "tok-to-rotate", "raw-token-to-rotate", role_field=None
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin", role="admin")},
    ) as admin_client:
        r = await admin_client.post("/api/v1/tokens/tok-to-rotate/rotate")
        assert r.status_code == 200, f"rotate failed: {r.status_code} {r.text}"
        rotated = r.json()

    new_raw = rotated["token"]
    status_code = await _post_ban_with_bearer(app, new_raw)
    assert status_code == 403, (
        "a role-less token rotated with no explicit role must come back as "
        f"auditor (insufficient for an operator route), got {status_code}"
    )

    await _redis_module.close_redis()


def test_create_access_token_requires_role() -> None:
    # The missing argument is the point of the test: `role` must stay
    # mandatory, so that a caller who forgets it fails loudly instead of
    # silently minting a token with a default (and therefore unreviewed)
    # privilege level. Both type-checker and linter are correct to flag the
    # call — they are suppressed rather than appeased.
    with pytest.raises(TypeError):
        # pylint: disable=no-value-for-parameter
        _create_access_token("someone")  # type: ignore[call-arg]
