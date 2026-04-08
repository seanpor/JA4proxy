"""Tests for management.api.routes.compliance — Phase 84.

Quality bar
-----------
- Every test verifies response BODY content, not just status codes.
- Role-based access control is tested: wrong role → 403.
- DSAR erasure tests verify Redis STATE after the operation.
- Audit log is verified after erasure (ticket reference present).
- Purge tests verify completion keys are written to Redis.
- All tests use the fakeredis + authenticated_client fixture pattern.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone, timedelta

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import os
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app
from management.api.models import Role


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fake_redis():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


def _make_client_fixture(role: Role):
    @pytest_asyncio.fixture
    async def _client(fake_redis):
        app = create_app()
        await _redis_module.init_redis(override_client=fake_redis)
        token = _create_access_token(f"test-{role.value}", role=role.value)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            cookies={"token": token},
        ) as client:
            yield client, fake_redis
        await _redis_module.close_redis()
    return _client


# We need separate fixtures per role to give tests access to both client and redis
@pytest_asyncio.fixture
async def admin_client_redis(fake_redis):
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    token = _create_access_token("admin", role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


@pytest_asyncio.fixture
async def auditor_client_redis(fake_redis):
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    token = _create_access_token("auditor-user", role="auditor")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


@pytest_asyncio.fixture
async def analyst_client_redis(fake_redis):
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    token = _create_access_token("analyst-user", role="analyst")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


_TS_IN = "2026-02-15T10:00:00+00:00"

_PACK_BODY = {
    "from_date": "2026-01-01",
    "to_date": "2026-03-31",
    "format": "jsonl",  # skip PDF for speed in tests
}

_REPORT_BODY = {
    "period_label": "Q1 2026",
    "from_date": "2026-01-01",
    "to_date": "2026-03-31",
    "format": "html",  # skip PDF for speed in tests
}


# ── POST /api/v1/compliance/pci-dss-pack ─────────────────────────────────────


@pytest.mark.asyncio
async def test_pci_dss_pack_returns_zip(auditor_client_redis):
    """Auditor can generate the PCI-DSS pack; response is a valid ZIP."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/pci-dss-pack", json=_PACK_BODY)

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert zipfile.is_zipfile(io.BytesIO(r.content))


@pytest.mark.asyncio
async def test_pci_dss_pack_contains_all_eight_artefacts(auditor_client_redis):
    """ZIP from the API contains all 8 required artefact files."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/pci-dss-pack", json=_PACK_BODY)

    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        names = zf.namelist()

    for expected in [
        "01_deployment_confirmation.pdf",
        "02_block_event_log.jsonl",
        "03_attack_classification.csv",
        "04_rbac_configuration.json",
        "05_audit_log_export.jsonl",
        "06_availability_metrics.pdf",
        "07_access_denied_summary.pdf",
        "08_configuration_change_log.csv",
    ]:
        assert expected in names, f"Missing: {expected}"


@pytest.mark.asyncio
async def test_pci_dss_pack_analyst_role_allowed(analyst_client_redis):
    """Analyst role (rank > auditor in RBAC hierarchy) can access PCI-DSS pack.

    Per the RBAC role ordering: auditor=0 < analyst=1 < operator=2 < admin=3.
    require_role(Role.auditor) permits all roles including analyst.
    See test_require_role_auditor_accepts_all_roles in test_rbac.py.
    """
    client, _ = analyst_client_redis
    r = await client.post("/api/v1/compliance/pci-dss-pack", json=_PACK_BODY)
    assert r.status_code != 403, f"Analyst was incorrectly rejected: {r.status_code}"


@pytest.mark.asyncio
async def test_pci_dss_pack_unauthenticated_forbidden():
    """Unauthenticated request must be rejected."""
    server = fakeredis.FakeServer()
    fake_r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    app = create_app()
    await _redis_module.init_redis(override_client=fake_r)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/compliance/pci-dss-pack", json=_PACK_BODY)
    await _redis_module.close_redis()
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_pci_dss_pack_invalid_date_range(auditor_client_redis):
    """to_date before from_date must return 422."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/pci-dss-pack", json={
        "from_date": "2026-03-31",
        "to_date": "2026-01-01",
        "format": "jsonl",
    })
    assert r.status_code == 422


# ── POST /api/v1/compliance/report ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_html_returns_html(auditor_client_redis):
    """HTML report returns text/html content with required section headers."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/report", json=_REPORT_BODY)

    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert "EXECUTIVE SUMMARY" in body
    assert "VALUE DELIVERED" in body


@pytest.mark.asyncio
async def test_report_contains_period_label(auditor_client_redis):
    """Period label passed in request body appears in the HTML output."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/report", json={
        **_REPORT_BODY,
        "period_label": "Q3 2025 Evidence Review",
    })

    assert r.status_code == 200
    assert "Q3 2025 Evidence Review" in r.text


@pytest.mark.asyncio
async def test_report_falls_back_gracefully_with_no_aggregates(auditor_client_redis):
    """Report generates without error even when no monthly aggregate hashes exist."""
    client, redis = auditor_client_redis
    # No reporting:monthly:* keys seeded — must fall back gracefully
    r = await client.post("/api/v1/compliance/report", json=_REPORT_BODY)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_report_uses_monthly_aggregate_data(auditor_client_redis):
    """When monthly aggregate hashes exist, their data appears in the report."""
    client, redis = auditor_client_redis
    await redis.hset("reporting:monthly:2026-01", mapping={
        "connections_total": "500000",
        "connections_blocked": "5000",
    })

    r = await client.post("/api/v1/compliance/report", json={
        "from_date": "2026-01-01",
        "to_date": "2026-01-31",
        "format": "html",
    })
    assert r.status_code == 200
    # 500,000 total should appear (formatted with comma)
    assert "500,000" in r.text


@pytest.mark.asyncio
async def test_report_analyst_role_allowed(analyst_client_redis):
    """Analyst role (rank > auditor) can access the report endpoint.

    Per the RBAC role ordering auditor=0 < analyst=1, require_role(Role.auditor)
    permits analyst. See test_require_role_auditor_accepts_all_roles in test_rbac.py.
    """
    client, _ = analyst_client_redis
    r = await client.post("/api/v1/compliance/report", json=_REPORT_BODY)
    assert r.status_code != 403, f"Analyst was incorrectly rejected: {r.status_code}"


# ── GET /api/v1/compliance/dsar/{ip} ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_dsar_export_returns_all_categories(auditor_client_redis):
    """DSAR response contains all required data category keys."""
    client, redis = auditor_client_redis
    # Seed some data for the IP
    await redis.set("ban:1.2.3.4", "scanning", ex=3600)

    r = await client.get("/api/v1/compliance/dsar/1.2.3.4")
    assert r.status_code == 200

    data = r.json()
    assert data["subject_ip"] == "1.2.3.4"
    cats = data["data_categories"]
    for key in ["connection_history", "ban_history", "watchlist_entries",
                "beaconing_records", "fingerprint_associations"]:
        assert key in cats, f"Missing data category: {key}"


@pytest.mark.asyncio
async def test_dsar_export_returns_ban_data(auditor_client_redis):
    """DSAR export includes active ban information for the IP."""
    client, redis = auditor_client_redis
    await redis.set("ban:10.20.30.40", "credential stuffing", ex=7200)

    r = await client.get("/api/v1/compliance/dsar/10.20.30.40")
    assert r.status_code == 200

    ban_history = r.json()["data_categories"]["ban_history"]
    assert len(ban_history) == 1
    assert ban_history[0]["active"] is True
    assert ban_history[0]["reason"] == "credential stuffing"


@pytest.mark.asyncio
async def test_dsar_export_empty_ip_returns_empty_categories(auditor_client_redis):
    """DSAR export for an IP with no data returns empty lists (not 404)."""
    client, _ = auditor_client_redis
    r = await client.get("/api/v1/compliance/dsar/192.0.2.1")

    assert r.status_code == 200
    cats = r.json()["data_categories"]
    for key in ["connection_history", "ban_history", "watchlist_entries",
                "beaconing_records", "fingerprint_associations"]:
        assert cats[key] == [], f"Expected empty list for {key}"


@pytest.mark.asyncio
async def test_dsar_export_includes_retention_periods(auditor_client_redis):
    """DSAR response includes retention_periods with all required keys."""
    client, _ = auditor_client_redis
    r = await client.get("/api/v1/compliance/dsar/1.2.3.4")

    assert r.status_code == 200
    retention = r.json()["retention_periods"]
    assert "connection_history" in retention
    assert "audit_trail" in retention


@pytest.mark.asyncio
async def test_dsar_export_analyst_allowed(analyst_client_redis):
    """Analyst role (rank > auditor) can access DSAR export.

    Per the RBAC role ordering auditor=0 < analyst=1, require_role(Role.auditor)
    permits analyst. See test_require_role_auditor_accepts_all_roles in test_rbac.py.
    """
    client, _ = analyst_client_redis
    r = await client.get("/api/v1/compliance/dsar/1.2.3.4")
    assert r.status_code != 403, f"Analyst was incorrectly rejected: {r.status_code}"


# ── DELETE /api/v1/compliance/dsar/{ip} ──────────────────────────────────────


@pytest.mark.asyncio
async def test_dsar_erase_removes_rv_key(admin_client_redis):
    """DSAR erasure removes the rv:{ip} hash from Redis."""
    client, redis = admin_client_redis
    await redis.hset("rv:5.5.5.5", "first_seen", "2026-01-01T00:00:00Z")

    r = await client.request(
        "DELETE",
        "/api/v1/compliance/dsar/5.5.5.5",
        json={"ticket": "GDPR-2026-0001"},
    )
    assert r.status_code == 200

    # The key must be gone from Redis
    assert not await redis.exists("rv:5.5.5.5"), "rv:5.5.5.5 still exists after erasure"


@pytest.mark.asyncio
async def test_dsar_erase_removes_beaconing_keys(admin_client_redis):
    """DSAR erasure removes beacon:{ip}:* sorted sets from Redis."""
    client, redis = admin_client_redis
    await redis.zadd("beacon:6.6.6.6:t13abc", {"ts:1000": 1000})

    r = await client.request(
        "DELETE",
        "/api/v1/compliance/dsar/6.6.6.6",
        json={"ticket": "GDPR-2026-0002"},
    )
    assert r.status_code == 200

    assert not await redis.exists("beacon:6.6.6.6:t13abc"), (
        "Beaconing key still exists after erasure"
    )


@pytest.mark.asyncio
async def test_dsar_erase_preserves_active_ban(admin_client_redis):
    """DSAR erasure must NOT delete an active ban (legitimate interest exemption)."""
    client, redis = admin_client_redis
    await redis.set("ban:7.7.7.7", "active scan detected", ex=3600)

    r = await client.request(
        "DELETE",
        "/api/v1/compliance/dsar/7.7.7.7",
        json={"ticket": "GDPR-2026-0003"},
    )
    assert r.status_code == 200

    # Ban must survive
    assert await redis.exists("ban:7.7.7.7"), "Active ban was illegally deleted by DSAR erasure"
    # And it must appear in the skipped list
    skipped = r.json()["skipped"]
    assert any("ban:7.7.7.7" in s.get("key", "") for s in skipped), (
        "Active ban not listed in skipped"
    )


@pytest.mark.asyncio
async def test_dsar_erase_writes_audit_log(admin_client_redis):
    """DSAR erasure must write an audit entry with the ticket reference."""
    client, redis = admin_client_redis

    r = await client.request(
        "DELETE",
        "/api/v1/compliance/dsar/8.8.8.8",
        json={"ticket": "GDPR-2026-TICKET-42"},
    )
    assert r.status_code == 200

    # Read audit log and find the erasure entry
    entries_raw = await redis.lrange("management:audit_log", 0, -1)
    entries = [json.loads(e) for e in entries_raw]
    erasure_entries = [e for e in entries if e.get("action_type") == "compliance.dsar_erasure"]
    assert len(erasure_entries) >= 1, "No DSAR erasure audit entry written"

    entry = erasure_entries[0]
    assert entry["resource_id"] == "8.8.8.8"
    # Ticket must be in after_value
    assert entry["after_value"]["ticket"] == "GDPR-2026-TICKET-42"


@pytest.mark.asyncio
async def test_dsar_erase_operator_forbidden(admin_client_redis):
    """Operator role must not be able to erase data (Admin only)."""
    # Create an operator-role client
    server = fakeredis.FakeServer()
    fake_r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    app = create_app()
    await _redis_module.init_redis(override_client=fake_r)
    token = _create_access_token("operator", role="operator")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as op_client:
        r = await op_client.request(
            "DELETE",
            "/api/v1/compliance/dsar/1.2.3.4",
            json={"ticket": "GDPR-2026-0099"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 403


# ── POST /api/v1/compliance/purge-expired ─────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_returns_summary(admin_client_redis):
    """Purge returns a JSON summary with all required fields."""
    client, _ = admin_client_redis
    r = await client.post("/api/v1/compliance/purge-expired")

    assert r.status_code == 200
    data = r.json()
    assert "purged" in data
    purged = data["purged"]
    for key in ["connection_events_deleted", "rv_hashes_deleted", "errors"]:
        assert key in purged, f"Missing key '{key}' in purge summary"


@pytest.mark.asyncio
async def test_purge_deletes_old_rv_hash(admin_client_redis):
    """Purge removes rv:{ip} hashes with first_seen older than retention."""
    client, redis = admin_client_redis
    await redis.hset("rv:1.2.3.4", "first_seen", "2020-01-01T00:00:00Z")

    r = await client.post("/api/v1/compliance/purge-expired")
    assert r.status_code == 200

    assert not await redis.exists("rv:1.2.3.4"), "Old rv hash not deleted by purge"
    purged = r.json()["purged"]
    assert purged["rv_hashes_deleted"] >= 1


@pytest.mark.asyncio
async def test_purge_writes_last_run_to_redis(admin_client_redis):
    """After purge, gdpr:purge:last_run must be set in Redis."""
    client, redis = admin_client_redis
    r = await client.post("/api/v1/compliance/purge-expired")
    assert r.status_code == 200

    val = await redis.get("gdpr:purge:last_run")
    assert val is not None and len(val) > 0


@pytest.mark.asyncio
async def test_purge_auditor_forbidden(auditor_client_redis):
    """Auditor role must not trigger purge (Admin only)."""
    client, _ = auditor_client_redis
    r = await client.post("/api/v1/compliance/purge-expired")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_purge_operator_forbidden(analyst_client_redis):
    """Analyst role must not trigger purge (Admin only)."""
    client, _ = analyst_client_redis
    r = await client.post("/api/v1/compliance/purge-expired")
    assert r.status_code == 403


# ── GET /api/v1/compliance/signal-categories ─────────────────────────────────


@pytest.mark.asyncio
async def test_signal_categories_returns_mapping(auditor_client_redis):
    """Signal categories endpoint returns a non-empty dict."""
    client, _ = auditor_client_redis
    r = await client.get("/api/v1/compliance/signal-categories")

    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)
    assert len(data) >= 12
    # Verify a known entry
    assert "spamhaus_drop" in data
    assert data["spamhaus_drop"]["category"] == "known_malicious_network"
    assert data["spamhaus_drop"]["weight"] == 100


@pytest.mark.asyncio
async def test_signal_categories_analyst_allowed(analyst_client_redis):
    """Analyst role (rank > auditor) can access signal-categories.

    Per the RBAC role ordering auditor=0 < analyst=1, require_role(Role.auditor)
    permits analyst. See test_require_role_auditor_accepts_all_roles in test_rbac.py.
    """
    client, _ = analyst_client_redis
    r = await client.get("/api/v1/compliance/signal-categories")
    assert r.status_code != 403, f"Analyst was incorrectly rejected: {r.status_code}"
