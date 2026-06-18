"""Tests for the Phase 316e EDL feed (management/api/routes/edl.py)."""

import bcrypt
import pytest

from management.api.routes import edl as edl_module

_RAW_TOKEN = "edl-firewall-token"


async def _mint_token(redis, raw: str = _RAW_TOKEN, role: str = "auditor", token_id: str = "fw1") -> None:
    """Seed a management-API token in the fake Redis token store so the EDL
    auth path (get_bearer_user) accepts it."""
    h = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()
    await redis.sadd("mgmt:token:idx", token_id)
    await redis.hset(
        f"mgmt:token:{token_id}",
        mapping={"name": "firewall", "role": role, "hash": h},
    )


def _enable(monkeypatch, **overrides) -> None:
    cfg = {"enabled": True, "max_entries": 100000, "cache_ttl_seconds": 60, "rate_limit_per_min": 120}
    cfg.update(overrides)
    monkeypatch.setattr(edl_module, "_edl_config", lambda: cfg)


def _key(raw: str = _RAW_TOKEN) -> dict:
    return {"X-API-Key": raw}


@pytest.mark.asyncio
async def test_edl_requires_token(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    resp = await test_client.get("/api/v1/edl/banned_ips")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_edl_invalid_token(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    resp = await test_client.get("/api/v1/edl/banned_ips", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_edl_banned_ips_plaintext(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban:1.2.3.4", "manual", ex=300)
    await fake_redis.set("ban:5.6.7.8", "tap_enforce:ja4t=x", ex=300)

    resp = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    lines = resp.text.split()
    assert "1.2.3.4" in lines and "5.6.7.8" in lines
    assert resp.headers["X-EDL-Count"] == "2"


@pytest.mark.asyncio
async def test_edl_banned_cidrs(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban_cidr:10.0.0.0/24", "rdap", ex=300)
    # An IP ban must NOT appear in the cidr list.
    await fake_redis.set("ban:9.9.9.9", "manual", ex=300)

    resp = await test_client.get("/api/v1/edl/banned_cidrs", headers=_key())
    assert resp.status_code == 200
    assert "10.0.0.0/24" in resp.text
    assert "9.9.9.9" not in resp.text


@pytest.mark.asyncio
async def test_edl_combined(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban:1.2.3.4", "manual", ex=300)
    await fake_redis.set("ban_cidr:10.0.0.0/24", "rdap", ex=300)

    resp = await test_client.get("/api/v1/edl/combined", headers=_key())
    assert resp.status_code == 200
    assert "1.2.3.4" in resp.text and "10.0.0.0/24" in resp.text


@pytest.mark.asyncio
async def test_edl_ipv6(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban:2001:db8::1", "manual", ex=300)

    resp = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert resp.status_code == 200
    assert "2001:db8::1" in resp.text


@pytest.mark.asyncio
async def test_edl_etag_304(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban:1.2.3.4", "manual", ex=300)

    first = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert first.status_code == 200
    etag = first.headers["ETag"]

    second = await test_client.get(
        "/api/v1/edl/banned_ips", headers={**_key(), "If-None-Match": etag}
    )
    assert second.status_code == 304


@pytest.mark.asyncio
async def test_edl_disabled_returns_404(test_client, fake_redis, monkeypatch):
    monkeypatch.setattr(edl_module, "_edl_config", lambda: {"enabled": False})
    await _mint_token(fake_redis)
    resp = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_edl_unknown_list_404(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    resp = await test_client.get("/api/v1/edl/nonsense", headers=_key())
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_edl_failopen_serves_empty_on_redis_error(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)

    async def _boom(*_a, **_k):
        raise RuntimeError("redis down")

    monkeypatch.setattr(edl_module, "_scan_suffixes", _boom)
    resp = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    # Fail-open: 200 with an empty body, never a 5xx that chokes the poller.
    assert resp.status_code == 200
    assert resp.text == ""
    assert resp.headers["X-EDL-Count"] == "0"


@pytest.mark.asyncio
async def test_edl_token_via_query_param(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch)
    await _mint_token(fake_redis)
    await fake_redis.set("ban:1.2.3.4", "manual", ex=300)
    resp = await test_client.get(f"/api/v1/edl/banned_ips?token={_RAW_TOKEN}")
    assert resp.status_code == 200
    assert "1.2.3.4" in resp.text


@pytest.mark.asyncio
async def test_edl_rate_limit(test_client, fake_redis, monkeypatch):
    _enable(monkeypatch, rate_limit_per_min=1)
    await _mint_token(fake_redis)
    first = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert first.status_code == 200
    second = await test_client.get("/api/v1/edl/banned_ips", headers=_key())
    assert second.status_code == 429
    assert "Retry-After" in second.headers
